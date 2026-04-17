use std::fmt::{Display, Formatter};
use std::net::IpAddr;
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

use super::bucket_config::S3Config;

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

/// Abstraction over S3 buckets to enable dependency injection in tests.
#[async_trait]
pub trait BucketLike: Send + Sync {
    async fn put_object(&self, path: String, content: &[u8]) -> Result<(), StorageError>;

    /// Returns `Ok(Some(data))` if the object exists, `Ok(None)` if not,
    /// and `Err` only for communication errors.
    async fn get_object(&self, path: String) -> Result<Option<Vec<u8>>, StorageError>;

    async fn object_exists(&self, path: String) -> Result<bool, StorageError>;

    async fn delete_object(&self, path: String) -> Result<(), StorageError>;

    async fn list_page(
        &self,
        prefix: String,
        delimiter: Option<String>,
        continuation_token: Option<String>,
        start_after: Option<String>,
        max_keys: Option<usize>,
    ) -> Result<(ListPage, u16), StorageError>;
}

/// A single page of object keys from a paginated list operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPage {
    pub keys: Vec<String>,
    pub next_continuation_token: Option<String>,
    pub sizes: Vec<u64>,
    pub last_modified_ts_secs: Option<Vec<u64>>,
}

/// DNS resolver using Tokio's async resolution (handles container hostnames, /etc/hosts).
#[derive(Clone, Debug)]
struct TokioDnsResolver;

impl ResolveDns for TokioDnsResolver {
    fn resolve_dns<'a>(&'a self, name: &'a str) -> DnsFuture<'a> {
        DnsFuture::new(async move {
            let addrs = tokio::net::lookup_host(format!("{name}:0")).await.map_err(|e| {
                ResolveDnsError::new(std::io::Error::other(format!(
                    "DNS resolution failed for {name}: {e}"
                )))
            })?;

            let ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();
            if ips.is_empty() {
                return Err(ResolveDnsError::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no addresses found for hostname: {name}"),
                )));
            }
            Ok(ips)
        })
    }
}

/// `BucketLike` implementation backed by the AWS SDK S3 client.
pub struct AWSBucket {
    client: Client,
    config: S3Config,
    use_intelligent_tiering: bool,
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
    async fn build_client(config: &S3Config) -> Client {
        let credentials = aws_sdk_s3::config::Credentials::new(
            &config.access_key,
            &config.secret_key,
            config.session_token.clone(),
            None,
            "ic-gateway-s3",
        );
        let normalized_endpoint = Self::normalize_endpoint(&config.endpoint);

        let http_client = HttpClientBuilder::new()
            .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::Ring))
            .build_with_resolver(TokioDnsResolver);

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
    async fn init_bucket(
        client: &Client,
        config: &S3Config,
    ) -> Result<bool, StorageError> {
        let exists = match client.head_bucket().bucket(&config.bucket_name).send().await {
            Ok(_) => true,
            Err(SdkError::ServiceError(inner)) => match inner.into_err() {
                HeadBucketError::NotFound(_) => false,
                other => return Err(StorageError::AwsS3(other.to_string())),
            },
            Err(e) => return Err(StorageError::AwsS3(format!("{}", DisplayErrorContext(e)))),
        };

        if !exists {
            client
                .create_bucket()
                .bucket(&config.bucket_name)
                .send()
                .await
                .map_err(|e| StorageError::AwsS3(format!("{}", DisplayErrorContext(e))))?;
        }

        Ok(true)
    }

    pub async fn new(config: S3Config) -> Result<Self, StorageError> {
        let client = Self::build_client(&config).await;
        Self::init_bucket(&client, &config).await?;

        let mut bucket = Self {
            client,
            config,
            use_intelligent_tiering: false,
        };
        bucket.use_intelligent_tiering = bucket.probe_intelligent_tiering().await;
        Ok(bucket)
    }

    pub fn supports_intelligent_tiering(&self) -> bool {
        self.use_intelligent_tiering
    }

    async fn probe_intelligent_tiering(&self) -> bool {
        let test_key = format!(
            "__capabilities__/intelligent-tiering-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );

        let result = self
            .client
            .put_object()
            .bucket(&self.config.bucket_name)
            .key(&test_key)
            .body(ByteStream::from(vec![]))
            .storage_class(aws_sdk_s3::types::StorageClass::IntelligentTiering)
            .send()
            .await;

        let ok = result.is_ok();
        if ok {
            let _ = self
                .client
                .delete_object()
                .bucket(&self.config.bucket_name)
                .key(&test_key)
                .send()
                .await;
        }
        ok
    }
}

#[async_trait]
impl BucketLike for AWSBucket {
    async fn put_object(&self, path: String, content: &[u8]) -> Result<(), StorageError> {
        let mut req = self
            .client
            .put_object()
            .bucket(&self.config.bucket_name)
            .key(&path)
            .body(ByteStream::from(content.to_vec()));

        if self.use_intelligent_tiering {
            req = req.storage_class(aws_sdk_s3::types::StorageClass::IntelligentTiering);
        }

        req.send()
            .await
            .map(|_| ())
            .map_err(|e| StorageError::AwsS3(format!("{}", DisplayErrorContext(e))))
    }

    async fn get_object(&self, path: String) -> Result<Option<Vec<u8>>, StorageError> {
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
                .map(|b| Some(b.to_vec()))
                .map_err(|e| StorageError::AwsS3(e.to_string())),
            Err(SdkError::ServiceError(inner)) => match inner.into_err() {
                GetObjectError::NoSuchKey(_) => Ok(None),
                other => Err(StorageError::AwsS3(other.to_string())),
            },
            Err(e) => Err(StorageError::AwsS3(format!("{}", DisplayErrorContext(e)))),
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
            Err(e) => Err(StorageError::AwsS3(format!("{}", DisplayErrorContext(e)))),
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
            .map_err(|e| StorageError::AwsS3(format!("{}", DisplayErrorContext(e))))
    }

    async fn list_page(
        &self,
        prefix: String,
        delimiter: Option<String>,
        continuation_token: Option<String>,
        start_after: Option<String>,
        max_keys: Option<usize>,
    ) -> Result<(ListPage, u16), StorageError> {
        match self
            .client
            .list_objects_v2()
            .bucket(&self.config.bucket_name)
            .prefix(prefix)
            .set_delimiter(delimiter)
            .set_continuation_token(continuation_token)
            .set_start_after(start_after)
            .set_max_keys(max_keys.map(|v| v as i32))
            .send()
            .await
        {
            Ok(output) => {
                if let Some(objects) = output.contents {
                    let keys: Vec<String> = objects
                        .iter()
                        .map(|o| o.key().unwrap_or_default().to_string())
                        .collect();
                    let sizes: Vec<u64> =
                        objects.iter().map(|o| o.size().map_or(0, |v| v as u64)).collect();
                    let last_modified: Vec<u64> = objects
                        .iter()
                        .map(|o| o.last_modified().map(|dt| dt.secs() as u64).unwrap_or(0))
                        .collect();

                    Ok((
                        ListPage {
                            keys,
                            next_continuation_token: output.next_continuation_token,
                            sizes,
                            last_modified_ts_secs: Some(last_modified),
                        },
                        200,
                    ))
                } else {
                    Ok((
                        ListPage {
                            keys: Vec::new(),
                            next_continuation_token: output.next_continuation_token,
                            sizes: Vec::new(),
                            last_modified_ts_secs: None,
                        },
                        200,
                    ))
                }
            }
            Err(e) => Err(StorageError::AwsS3(format!("{}", DisplayErrorContext(e)))),
        }
    }
}
