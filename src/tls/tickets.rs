use std::{
    fmt,
    sync::atomic::{AtomicU32, Ordering},
};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use prometheus::{register_int_counter_vec_with_registry, IntCounterVec, Registry};
use rustls::server::ProducesTickets;
use zeroize::ZeroizeOnDrop;

// We're using 192-bit nonce
const NONCE_LEN: usize = 192 / 8;

#[derive(Debug)]
pub struct Metrics {
    processed: IntCounterVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            processed: register_int_counter_vec_with_registry!(
                format!("tls_tickets"),
                format!("Number of TLS tickets that were processed"),
                &["action", "result"],
                registry
            )
            .unwrap(),
        }
    }
}

/// Encrypts & decrypts tickets for TLS 1.3 session resumption.
/// Must be used with `rustls::ticketer::TicketSwitcher` to facilitate key rotation.
/// We're using `XChaCha20Poly1305` authenicated encryption (AEAD).
/// `ZeroizeOnDrop` is derived below to make sure the encryption keys are wiped from
/// memory when the Ticketer is dropped.
/// See <https://docs.rs/zeroize/latest/zeroize/#what-guarantees-does-this-crate-provide>
#[derive(ZeroizeOnDrop)]
pub struct Ticketer {
    #[zeroize(skip)]
    counter: AtomicU32,
    cipher: XChaCha20Poly1305,
}

impl fmt::Debug for Ticketer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ticketer")
    }
}

impl Ticketer {
    pub fn new() -> Self {
        // Generate a random key that is valid for the lifetime of this ticketer
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);

        Self {
            cipher: XChaCha20Poly1305::new(&key),
            counter: AtomicU32::new(0),
        }
    }

    /// Generates a random nonce and then replaces first 4 bytes of it with a counter.
    /// Purely random nonces seem to be less secure, though 192-bit `XNonce` that we're using might be Ok.
    /// See <https://docs.rs/aead/latest/aead/trait.AeadCore.html#security-warning>
    fn nonce(&self) -> XNonce {
        let mut nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        nonce[0..4].copy_from_slice(&count.to_le_bytes());
        nonce
    }
}

impl ProducesTickets for Ticketer {
    fn enabled(&self) -> bool {
        true
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        // Check if the ciphertext is too short
        if cipher.len() <= NONCE_LEN {
            return None;
        }

        // Extract nonce
        let nonce = XNonce::from_slice(&cipher[0..NONCE_LEN]);

        // Try to decrypt
        self.cipher.decrypt(nonce, &cipher[NONCE_LEN..]).ok()
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        // Generate nonce & encrypt
        let nonce = self.nonce();
        let ciphertext = self.cipher.encrypt(&nonce, plain).ok()?;

        // Concatenate nonce & ciphertext
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(nonce.as_slice());
        result.extend_from_slice(&ciphertext);

        Some(result)
    }

    fn lifetime(&self) -> u32 {
        // Lifetime here isn't important since it's designed to be used under TicketSwitcher
        // which manages its own lifetimes
        3600
    }
}

#[derive(Debug)]
pub struct WithMetrics<T: ProducesTickets>(pub T, pub Metrics);

impl<T: ProducesTickets> WithMetrics<T> {
    fn record(&self, action: &str, res: &Option<Vec<u8>>) {
        self.1
            .processed
            .with_label_values(&[action, if res.is_some() { "ok" } else { "fail" }])
            .inc();
    }
}

impl<T: ProducesTickets> ProducesTickets for WithMetrics<T> {
    fn enabled(&self) -> bool {
        self.0.enabled()
    }

    fn lifetime(&self) -> u32 {
        self.0.lifetime()
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let res = self.0.encrypt(plain);
        self.record("encrypt", &res);
        res
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        let res = self.0.decrypt(cipher);
        self.record("decrypt", &res);
        res
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ticketer() {
        let t = Ticketer::new();

        // Make sure that nonce is using a counter
        for i in 0..10 {
            let counter = u32::from_le_bytes(t.nonce().as_slice()[0..4].try_into().unwrap());
            assert_eq!(counter, i);
        }

        // Check encryption & decryption
        let msg = b"The quick brown fox jumps over the lazy dog";
        let ciphertext = t.encrypt(msg).unwrap();
        let plaintext = t.decrypt(&ciphertext).unwrap();
        assert_eq!(&msg[..], plaintext);

        // Check that bad ciphertext fails to decrypt
        assert!(t.decrypt(msg).is_none());
    }
}
