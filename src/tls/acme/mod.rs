pub mod alpn;
pub mod dns;

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use derive_new::new;
use instant_acme::{
    Account, AccountCredentials, Authorization, AuthorizationStatus, ChallengeType, Identifier,
    LetsEncrypt, NewAccount, NewOrder, Order, OrderStatus,
};
use itertools::Itertools;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use strum_macros::{Display, EnumString};
use tokio::fs;
use tracing::info;

use crate::tls::cert::{extract_san_from_der, extract_validity_from_der};

#[derive(Clone, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum Challenge {
    Alpn,
    Dns,
}

pub struct Cert {
    cert: Vec<u8>,
    key: Vec<u8>,
}

#[derive(Clone, Display, EnumString)]
enum Validity {
    UnableToRead,
    NoCertsFound,
    Expires,
    SANMismatch,
    Valid,
}

#[async_trait]
pub trait TokenManager: Sync + Send {
    async fn set(&self, id: &str, token: &str) -> Result<(), Error>;
    async fn unset(&self, id: &str) -> Result<(), Error>;
    async fn verify(&self, id: &str, token: &str) -> Result<(), Error>;
}

#[derive(new)]
pub struct AcmeOptions {
    domains: Vec<String>,
    cache_path: PathBuf,
    renew_before: Duration,
    wildcard: bool,
    staging: bool,
    contact: String,
}

// Generic ACME client that is using TokenManager implementor to set a challenge token
pub struct Acme {
    domains: Vec<String>,
    challenge: ChallengeType,
    cache_path: PathBuf,
    renew_before: Duration,
    account: Account,
    wildcard: bool,
    token_manager: Arc<dyn TokenManager>,
}

impl Acme {
    pub async fn new(
        challenge: ChallengeType,
        token_manager: Arc<dyn TokenManager>,
        opts: AcmeOptions,
    ) -> Result<Self, Error> {
        let account = Self::load_or_create_account(
            opts.cache_path.join("acme_account.json"),
            opts.staging,
            &opts.contact,
        )
        .await?;

        if opts.wildcard && challenge != ChallengeType::Dns01 {
            return Err(anyhow!("wildcard is only available with DNS challenge"));
        }

        Ok(Self {
            domains: opts.domains,
            challenge,
            cache_path: opts.cache_path,
            renew_before: opts.renew_before,
            token_manager,
            wildcard: opts.wildcard,
            account,
        })
    }

    async fn load_or_create_account(
        path: PathBuf,
        staging: bool,
        contact: &str,
    ) -> Result<Account, Error> {
        if let Ok(v) = fs::read(&path).await {
            let creds: AccountCredentials = serde_json::from_slice(&v)
                .context("unable to json parse existing acme credentials")?;

            let account = Account::from_credentials(creds)
                .await
                .context("unable to load account from credentials")?;

            return Ok(account);
        }

        let url = if staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        let (account, creds) = Account::create(
            &NewAccount {
                contact: &[contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            url,
            None,
        )
        .await
        .context("unable to create account")?;

        let data =
            serde_json::to_vec_pretty(&creds).context("unable to serialize credentials to JSON")?;
        fs::write(path, data)
            .await
            .context("unable to store credentials")?;

        Ok(account)
    }

    // Generate a list of identifiers for certificate
    fn generate_names(&self) -> Vec<String> {
        self.domains
            .clone()
            .into_iter()
            .flat_map(|x| {
                let mut out = vec![x.clone()];
                if self.wildcard {
                    out.push(format!("*.{x}"))
                }
                out.into_iter()
            })
            .collect::<Vec<_>>()
    }

    async fn prepare_order(&self) -> Result<Order, Error> {
        let ids = self
            .generate_names()
            .into_iter()
            .map(Identifier::Dns)
            .collect::<Vec<_>>();

        info!("ACME: Order identifiers: {:?}", ids);

        let mut order = self
            .account
            .new_order(&NewOrder { identifiers: &ids })
            .await
            .context("unable to create ACME order")?;

        if !matches!(
            order.state().status,
            OrderStatus::Pending | OrderStatus::Ready
        ) {
            return Err(anyhow!(
                "Order status is not expected: {:?}",
                order.state().status
            ));
        }

        Ok(order)
    }

    async fn process_authorizations(&self, order: &mut Order) -> Result<Vec<Authorization>, Error> {
        let authorizations = order
            .authorizations()
            .await
            .context("unable to get ACME authorizations from order")?;

        let mut challenges = vec![];
        for authz in &authorizations {
            match authz.status {
                AuthorizationStatus::Valid => {
                    info!("ACME: Authorization is already valid");
                    continue;
                }
                AuthorizationStatus::Pending => {}
                _ => {
                    return Err(anyhow!(
                        "unexpected authorization status: {:?}",
                        authz.status
                    ))
                }
            }

            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == self.challenge)
                .ok_or_else(|| anyhow!("no challenge with type {:?} found", self.challenge))?;

            let token = order.key_authorization(challenge).dns_value();

            let Identifier::Dns(id) = &authz.identifier;
            self.token_manager
                .set(id, &token)
                .await
                .context("unable to set challenge token")?;

            challenges.push((id, token, &challenge.url));
        }

        // Give it a bit time to settle
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Verify that the tokens are set & mark challenges as ready
        for (id, token, url) in challenges {
            self.token_manager
                .verify(id, &token)
                .await
                .context("unable to verify that the token is set")?;

            order
                .set_challenge_ready(url)
                .await
                .context("unable to set challenge as ready")?;
        }

        Ok(authorizations)
    }

    async fn cleanup(&self, authorizations: Vec<Authorization>) -> Result<(), Error> {
        let ids = authorizations
            .into_iter()
            .map(|x| {
                let Identifier::Dns(v) = x.identifier;
                v
            })
            .unique()
            .collect::<Vec<_>>();

        for id in ids {
            self.token_manager.unset(&id).await?;
        }

        Ok(())
    }

    // Poll the order with increasing intervals until it reaches some final state
    // backoff crate does not work here nicely because of &mut
    async fn poll_order(&self, order: &mut Order, expect: OrderStatus) -> Result<(), Error> {
        let mut delay = Duration::from_millis(500);
        let mut retries = 8;

        while retries > 0 {
            if let Ok(state) = order.refresh().await {
                if state.status == expect {
                    break;
                }

                if state.status == OrderStatus::Invalid {
                    return Err(anyhow!("order is in invalid state"));
                }
            }

            tokio::time::sleep(delay).await;
            delay *= 2;
            retries -= 1;
        }

        Ok(())
    }

    pub async fn load(&self) -> Result<Cert, Error> {
        Ok(Cert {
            cert: tokio::fs::read(self.cache_path.join("cert.pem")).await?,
            key: tokio::fs::read(self.cache_path.join("cert.key")).await?,
        })
    }

    // Loads the existing certificate (if any) and checks if it is still valid for our domains
    async fn is_valid(&self) -> Result<Validity, Error> {
        if let Ok(v) = self.load().await {
            let certs =
                rustls_pemfile::certs(&mut v.cert.as_ref()).collect::<Result<Vec<_>, _>>()?;

            // Empty file?
            if certs.is_empty() {
                return Ok(Validity::NoCertsFound);
            }

            // Check if it's time to renew
            let validity = extract_validity_from_der(certs[0].as_ref())?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if now > validity.not_after.timestamp() as u64 - self.renew_before.as_secs() {
                return Ok(Validity::Expires);
            }

            // Check if cert's SANs match the domains that we have
            let mut sans = extract_san_from_der(certs[0].as_ref())?;
            let mut names = self.generate_names();
            sans.sort();
            names.sort();
            if sans != names {
                return Ok(Validity::SANMismatch);
            }

            return Ok(Validity::Valid);
        }

        Ok(Validity::UnableToRead)
    }

    pub async fn issue(&self) -> Result<(), Error> {
        let mut order = self.prepare_order().await?;
        info!("ACME: Order for {:?} created", self.domains);

        // Process authorizations and fulfill their challenges
        let authorizations = self
            .process_authorizations(&mut order)
            .await
            .context("unable to process authorizations")?;

        info!("ACME: Authorizations processed");

        // Poll until Ready or timeout if it's not already
        if order.state().status != OrderStatus::Ready {
            self.poll_order(&mut order, OrderStatus::Ready)
                .await
                .context("order unable to reach Ready state")?;
        }

        info!("ACME: Order is Ready");

        // Prepare the signing request
        let names = self.generate_names();
        info!("ACME: Creating CSR with SANs: {:?}", names);

        let mut params = CertificateParams::new(names)?;
        params.distinguished_name = DistinguishedName::new();
        let key_pair = KeyPair::generate()?;
        let csr = params.serialize_request(&key_pair)?;

        // Issue the certificate
        info!("ACME: Finalizing order");
        order.finalize(csr.der()).await?;

        // Poll until Valid or timeout
        self.poll_order(&mut order, OrderStatus::Valid)
            .await
            .context("order unable to reach Valid state")?;

        info!("ACME: Order is Valid");

        let cert = order
            .certificate()
            .await?
            .ok_or_else(|| anyhow!("certificate not found"))?;

        // Store the resulting cert & key
        tokio::fs::write(self.cache_path.join("cert.pem"), cert)
            .await
            .context("unable to store certificate")?;
        tokio::fs::write(self.cache_path.join("cert.key"), key_pair.serialize_pem())
            .await
            .context("unable to store private key")?;

        // Cleanup the tokens
        info!("ACME: Cleaning up");
        self.cleanup(authorizations)
            .await
            .context("unable to cleanup tokens")?;

        Ok(())
    }
}
