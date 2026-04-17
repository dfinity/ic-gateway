#[derive(Debug, Clone)]
pub struct S3Config {
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub bucket_name: String,
    pub region: String,
    pub session_token: Option<String>,
}

impl S3Config {
    pub fn new(
        endpoint: String,
        access_key: String,
        secret_key: String,
        bucket_name: String,
        region: String,
        session_token: Option<String>,
    ) -> Self {
        Self {
            endpoint,
            access_key,
            secret_key,
            bucket_name,
            region,
            session_token,
        }
    }
}
