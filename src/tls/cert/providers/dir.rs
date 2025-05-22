use std::path::PathBuf;

use anyhow::{Context, Error};
use async_trait::async_trait;
use tokio::fs::read_dir;
use tracing::debug;

use super::Pem;
use crate::tls::cert::providers::ProvidesCertificates;

// It searches for .pem files in the given directory and tries to find the
// corresponding .key files with the same base name.
// After that it loads & parses each pair.
#[derive(derive_new::new)]
pub struct Provider {
    path: PathBuf,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DirProvider({})", self.path.to_str().unwrap_or(""))
    }
}

#[async_trait]
impl ProvidesCertificates for Provider {
    async fn get_certificates(&self) -> Result<Vec<Pem>, Error> {
        let mut files = read_dir(&self.path).await?;

        let mut certs = vec![];
        while let Some(v) = files.next_entry().await? {
            // Skip non-file entries
            if !v.file_type().await?.is_file() {
                continue;
            }

            // Skip non-pem files
            if !v
                .path()
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("pem"))
            {
                continue;
            }

            // Guess key file name
            let path = v.path();
            // We already checked that file has .pem extension so unwrap is safe
            let base = path.file_stem().unwrap().to_string_lossy();
            let keyfile = self.path.join(format!("{base}.key"));

            // Load key & cert
            let cert = tokio::fs::read(v.path()).await?;
            let key = tokio::fs::read(&keyfile).await.context(format!(
                "Corresponding key file '{}' for '{}' could not be read",
                keyfile.to_string_lossy(),
                v.path().to_string_lossy()
            ))?;

            certs.push(Pem([cert, key].concat()));
        }

        debug!(
            "Dir provider ({}): {} certs loaded",
            self.path.to_string_lossy(),
            certs.len()
        );

        Ok(certs)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tls::cert::test::{CERT_1, CERT_2, KEY_1, KEY_2};

    #[tokio::test]
    async fn test() -> Result<(), Error> {
        let dir = tempfile::tempdir()?;

        let keyfile1 = dir.path().join("foobar1.key");
        std::fs::write(keyfile1, KEY_1)?;
        let certfile1 = dir.path().join("foobar1.pem");
        std::fs::write(certfile1, CERT_1)?;

        let keyfile2 = dir.path().join("foobar2.key");
        std::fs::write(keyfile2, KEY_2)?;
        let certfile2 = dir.path().join("foobar2.pem");
        std::fs::write(certfile2, CERT_2)?;

        // Some junk to be ignored
        std::fs::write(dir.path().join("foobar.baz"), b"foobar")?;

        let prov = Provider::new(dir.path().to_path_buf());
        let certs = prov.get_certificates().await?;

        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].0, [CERT_1, KEY_1].concat());
        assert_eq!(certs[1].0, [CERT_2, KEY_2].concat());

        Ok(())
    }
}
