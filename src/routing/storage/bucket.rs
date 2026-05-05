use std::error::Error as StdError;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aws_config::retry::RetryConfig;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::Client;
use aws_sdk_s3::error::{DisplayErrorContext, SdkError};
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::operation::head_bucket::HeadBucketError;
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_sdk_s3::primitives::ByteStream;
use aws_smithy_http_client::{Builder as HttpClientBuilder, tls};
use aws_smithy_runtime_api::client::dns::{DnsFuture, ResolveDns, ResolveDnsError};
use bytes::Bytes;
use clap::ValueEnum;
use hickory_resolver::proto::rr::{RData, RecordType};
use ic_bn_lib::http::dns::Resolver as DnsResolver;
use ic_bn_lib::ic_bn_lib_common::traits::dns::Resolves;

/// Which S3-compatible backend the gateway is talking to.
///
/// The flavor encodes out-of-band knowledge about which features the backend
/// supports, so we don't have to discover capabilities at runtime. Add new
/// variants when you onboard a new backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum S3Flavor {
    /// Amazon S3 (production). Supports `INTELLIGENT_TIERING`.
    Aws,
    /// Pakistan deployment. Does not use `INTELLIGENT_TIERING`.
    Pakistan,
    /// MinIO (local/dev). Does not support `INTELLIGENT_TIERING`.
    Minio,
}

/// Configuration for the S3 backend.
#[derive(Debug, Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub bucket_name: String,
    pub region: String,
    pub session_token: Option<String>,
    /// Which S3 flavor we're talking to — drives feature selection
    /// (e.g. intelligent tiering) without a runtime capability probe.
    pub flavor: S3Flavor,
}

/// Errors from S3 storage operations.
#[derive(Debug)]
pub enum StorageError {
    AwsS3(String),
}

impl Display for StorageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwsS3(inner) => write!(f, "AWS S3 error: {inner}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl<E: StdError> From<DisplayErrorContext<E>> for StorageError {
    fn from(e: DisplayErrorContext<E>) -> Self {
        Self::AwsS3(e.to_string())
    }
}

/// Abstraction over S3 buckets to enable dependency injection in tests.
#[async_trait]
pub trait BucketLike: Send + Sync {
    /// Upload `content` under `path`. Takes ownership of `content` as
    /// `bytes::Bytes` so callers with either `Vec<u8>` or `Bytes` can hand off
    /// without a copy (`Vec<u8> -> Bytes` and `Bytes -> ByteStream` are both
    /// zero-copy).
    async fn put_object(&self, path: String, content: Bytes) -> Result<(), StorageError>;

    /// Returns `Ok(Some(data))` if the object exists, `Ok(None)` if not,
    /// and `Err` only for communication errors.
    async fn get_object(&self, path: String) -> Result<Option<Bytes>, StorageError>;

    async fn object_exists(&self, path: String) -> Result<bool, StorageError>;

    async fn delete_object(&self, path: String) -> Result<(), StorageError>;

    async fn list_page(
        &self,
        prefix: String,
        continuation_token: Option<String>,
        max_keys: Option<usize>,
    ) -> Result<ListPage, StorageError>;
}

/// A single page of object keys from a paginated list operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPage {
    pub keys: Vec<String>,
    pub next_continuation_token: Option<String>,
}

/// Adapter that exposes an `ic_bn_lib_common` [`Resolves`] implementation as
/// an AWS SDK [`ResolveDns`].
///
/// The AWS SDK only needs `hostname -> Vec<IpAddr>` resolution; we perform
/// parallel A and AAAA lookups and return the union.
#[derive(Clone, Debug)]
struct AwsDnsAdapter(Arc<DnsResolver>);

impl ResolveDns for AwsDnsAdapter {
    fn resolve_dns<'a>(&'a self, name: &'a str) -> DnsFuture<'a> {
        let resolver = self.0.clone();
        let name = name.to_string();
        DnsFuture::new(async move {
            let (v4, v6) = tokio::join!(
                resolver.resolve(RecordType::A, &name),
                resolver.resolve(RecordType::AAAA, &name),
            );

            let mut ips: Vec<IpAddr> = Vec::new();
            if let Ok(records) = &v4 {
                for r in records {
                    if let RData::A(a) = r.data() {
                        ips.push(IpAddr::V4(a.0));
                    }
                }
            }
            if let Ok(records) = &v6 {
                for r in records {
                    if let RData::AAAA(aaaa) = r.data() {
                        ips.push(IpAddr::V6(aaaa.0));
                    }
                }
            }

            if ips.is_empty() {
                // Surface the underlying error when we have one; otherwise
                // report an empty result explicitly.
                let err = v4.err().or(v6.err()).map_or_else(
                    || {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!("no addresses found for hostname: {name}"),
                        )
                    },
                    |e| std::io::Error::other(format!("DNS resolution failed for {name}: {e}")),
                );
                return Err(ResolveDnsError::new(err));
            }
            Ok(ips)
        })
    }
}

/// `BucketLike` implementation backed by the AWS SDK S3 client.
pub struct AWSBucket {
    client: Client,
    config: S3Config,
}

impl AWSBucket {
    fn normalize_endpoint(endpoint: &str) -> String {
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            endpoint.to_string()
        } else {
            format!("https://{endpoint}")
        }
    }

    /// Build a new `aws_sdk_s3::Client` from the given config.
    async fn build_client(config: &S3Config, dns_resolver: Arc<DnsResolver>) -> Client {
        let credentials = aws_sdk_s3::config::Credentials::new(
            &config.access_key,
            &config.secret_key,
            config.session_token.clone(),
            None,
            "ic-gateway-s3",
        );
        let normalized_endpoint = Self::normalize_endpoint(&config.endpoint);

        let http_client = HttpClientBuilder::new()
            .tls_provider(tls::Provider::Rustls(
                tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_with_resolver(AwsDnsAdapter(dns_resolver));

        let lib_config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .endpoint_url(&normalized_endpoint)
            .credentials_provider(credentials)
            .http_client(http_client)
            .retry_config(RetryConfig::standard().with_initial_backoff(Duration::from_millis(100)))
            .load()
            .await;

        let s3_config = aws_sdk_s3::config::Builder::from(&lib_config)
            .force_path_style(true)
            .build();
        Client::from_conf(s3_config)
    }

    /// Ensure the bucket exists, creating it if necessary. Probe intelligent tiering.
    async fn init_bucket(client: &Client, config: &S3Config) -> Result<bool, StorageError> {
        let exists = match client
            .head_bucket()
            .bucket(&config.bucket_name)
            .send()
            .await
        {
            Ok(_) => true,
            Err(SdkError::ServiceError(inner)) => match inner.into_err() {
                HeadBucketError::NotFound(_) => false,
                other => return Err(StorageError::AwsS3(other.to_string())),
            },
            Err(e) => return Err(DisplayErrorContext(e).into()),
        };

        if !exists {
            client
                .create_bucket()
                .bucket(&config.bucket_name)
                .send()
                .await
                .map_err(|e| -> StorageError { DisplayErrorContext(e).into() })?;
        }

        Ok(true)
    }

    pub async fn new(
        config: S3Config,
        dns_resolver: Arc<DnsResolver>,
    ) -> Result<Self, StorageError> {
        let client = Self::build_client(&config, dns_resolver).await;
        Self::init_bucket(&client, &config).await?;
        Ok(Self { client, config })
    }
}

#[async_trait]
impl BucketLike for AWSBucket {
    async fn put_object(&self, path: String, content: Bytes) -> Result<(), StorageError> {
        let mut req = self
            .client
            .put_object()
            .bucket(&self.config.bucket_name)
            .key(&path)
            .body(ByteStream::from(content));

        if let S3Flavor::Aws = self.config.flavor {
            req = req.storage_class(aws_sdk_s3::types::StorageClass::IntelligentTiering);
        }

        req.send()
            .await
            .map(|_| ())
            .map_err(|e| DisplayErrorContext(e).into())
    }

    async fn get_object(&self, path: String) -> Result<Option<Bytes>, StorageError> {
        match self
            .client
            .get_object()
            .bucket(&self.config.bucket_name)
            .key(path)
            .send()
            .await
        {
            Ok(output) => output
                .body
                .collect()
                .await
                .map(|b| Some(b.into_bytes()))
                .map_err(|e| StorageError::AwsS3(e.to_string())),
            Err(SdkError::ServiceError(inner)) => match inner.into_err() {
                GetObjectError::NoSuchKey(_) => Ok(None),
                other => Err(StorageError::AwsS3(other.to_string())),
            },
            Err(e) => Err(DisplayErrorContext(e).into()),
        }
    }

    async fn object_exists(&self, path: String) -> Result<bool, StorageError> {
        match self
            .client
            .head_object()
            .bucket(&self.config.bucket_name)
            .key(&path)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(SdkError::ServiceError(inner)) => match inner.into_err() {
                HeadObjectError::NotFound(_) => Ok(false),
                other => Err(StorageError::AwsS3(other.to_string())),
            },
            Err(e) => Err(DisplayErrorContext(e).into()),
        }
    }

    async fn delete_object(&self, path: String) -> Result<(), StorageError> {
        self.client
            .delete_object()
            .bucket(&self.config.bucket_name)
            .key(&path)
            .send()
            .await
            .map(|_| ())
            .map_err(|e| DisplayErrorContext(e).into())
    }

    async fn list_page(
        &self,
        prefix: String,
        continuation_token: Option<String>,
        max_keys: Option<usize>,
    ) -> Result<ListPage, StorageError> {
        let output = self
            .client
            .list_objects_v2()
            .bucket(&self.config.bucket_name)
            .prefix(prefix)
            .set_continuation_token(continuation_token)
            .set_max_keys(max_keys.map(|v| v as i32))
            .send()
            .await
            .map_err(|e| -> StorageError { DisplayErrorContext(e).into() })?;

        let keys = output
            .contents
            .unwrap_or_default()
            .into_iter()
            .map(|o| o.key.unwrap_or_default())
            .collect();

        Ok(ListPage {
            keys,
            next_continuation_token: output.next_continuation_token,
        })
    }
}
