use std::path::PathBuf;

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use tokio::fs::read_dir;

use super::{pem_convert_to_rustls, Cert, ProvidesCertificates};

pub struct Provider {
    path: PathBuf,
}

// It searches for .pem files in the given folder and tries to find the
// corresponding .key files with the same base name.
// After that it loads & parses each pair.
impl Provider {
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait]
impl ProvidesCertificates for Provider {
    async fn get_certificates(&self) -> Result<Vec<Cert>, Error> {
        let mut files = read_dir(&self.path).await?;

        let mut certs = vec![];
        while let Some(v) = files.next_entry().await? {
            if !v.file_type().await?.is_file() {
                continue;
            }

            if !v
                .path()
                .extension()
                .map_or(false, |x| x.eq_ignore_ascii_case("pem"))
            {
                continue;
            }

            let path = v.path();
            let base = path.file_stem().unwrap().to_string_lossy();
            let keyfile = self.path.join(format!("{base}.key"));

            let chain = tokio::fs::read(v.path()).await?;
            let key = tokio::fs::read(keyfile).await.context(format!(
                "Corresponding .key file for {} not found",
                v.path().to_string_lossy()
            ))?;

            let cert = pem_convert_to_rustls(&key, &chain)?;
            certs.push(cert);
        }

        Ok(certs)
    }
}

#[cfg(test)]
mod test {
    use super::super::test::{CERT, KEY};
    use super::*;

    #[tokio::test]
    async fn test() -> Result<(), Error> {
        let dir = tempfile::tempdir()?;

        let keyfile = dir.path().join("foobar.key");
        std::fs::write(keyfile, KEY)?;

        let certfile = dir.path().join("foobar.pem");
        std::fs::write(certfile, CERT)?;

        // Some junk to be ignored
        std::fs::write(dir.path().join("foobar.baz"), b"foobar")?;

        let prov = Provider::new(dir.path().to_path_buf());
        let certs = prov.get_certificates().await?;

        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].san, vec!["novg"]);

        Ok(())
    }
}
