use async_trait::async_trait;
use pingora_core::{
    listeners::{TlsAccept, TlsAcceptCallbacks},
    protocols::tls::TlsRef,
    tls::{
        ssl::NameType,
        x509::X509,
        pkey::PKey,
        ext::{ssl_use_certificate, ssl_use_private_key},
    },
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use log::{info, error, debug};
use crate::metrics;
use once_cell::sync::Lazy;

// Cache for loaded certificates to avoid disk I/O on every handshake
// Using owned types that can be cloned
static CERT_CACHE: Lazy<Mutex<HashMap<String, (Vec<u8>, Vec<u8>)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// SNI handler for managing multiple SSL certificates per port
pub struct SniHandler {
    /// Map of domain names to (cert_path, key_path)
    certificates: Arc<HashMap<String, (String, String)>>,
}

impl SniHandler {
    /// Create a new SNI handler
    pub fn new() -> Self {
        Self {
            certificates: Arc::new(HashMap::new()),
        }
    }

    /// Add a certificate for a specific domain
    pub fn add_certificate(&mut self, domain: &str, cert_path: String, key_path: String) {
        let mut certs = (*self.certificates).clone();
        certs.insert(domain.to_string(), (cert_path, key_path));
        self.certificates = Arc::new(certs);
        info!("Added certificate for domain: {}", domain);
    }

    /// Create TlsAcceptCallbacks from this SNI handler
    pub fn into_callbacks(self) -> TlsAcceptCallbacks {
        Box::new(self)
    }
}

#[async_trait]
impl TlsAccept for SniHandler {
    async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
        // Get the SNI (Server Name Indication) from the TLS connection
        let server_name = match ssl.servername(NameType::HOST_NAME) {
            Some(name) => name.to_string(),
            None => {
                return;
            }
        };

        // Look up the certificate for this domain
        let (cert_path, key_path) = match self.certificates.get(&server_name) {
            Some((cert, key)) => (cert.clone(), key.clone()),
            None => {
                // Try to find a wildcard certificate
                let wildcard_domain = format!("*.{}",
                    server_name.split('.').skip(1).collect::<Vec<_>>().join("."));

                match self.certificates.get(&wildcard_domain) {
                    Some((cert, key)) => (cert.clone(), key.clone()),
                    None => {
                        error!("No certificate found for domain: {}", server_name);
                        metrics::record_ssl_handshake(&server_name, false);
                        return;
                    }
                }
            }
        };

        // Create a cache key based on cert and key paths
        let cache_key = format!("{}:{}", cert_path, key_path);

        // Try to get certificate bytes from cache first
        let (cert_bytes, key_bytes) = {
            let cache = CERT_CACHE.lock().unwrap();
            if let Some((cached_cert, cached_key)) = cache.get(&cache_key) {
                debug!("Using cached certificate bytes for domain: {}", server_name);
                (cached_cert.clone(), cached_key.clone())
            } else {
                // Cache miss, need to load from disk
                drop(cache); // Release lock before I/O

                debug!("Loading certificate from disk for domain: {}", server_name);

                // Load certificate from file
                let cert_bytes = match std::fs::read(&cert_path) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!("Failed to read certificate file {}: {}", cert_path, e);
                        metrics::record_ssl_handshake(&server_name, false);
                        return;
                    }
                };

                // Load private key from file
                let key_bytes = match std::fs::read(&key_path) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!("Failed to read private key file {}: {}", key_path, e);
                        metrics::record_ssl_handshake(&server_name, false);
                        return;
                    }
                };

                // Store raw bytes in cache for future use
                let mut cache = CERT_CACHE.lock().unwrap();
                cache.insert(cache_key.clone(), (cert_bytes.clone(), key_bytes.clone()));
                info!("Cached certificate bytes for domain: {}", server_name);

                (cert_bytes, key_bytes)
            }
        };

        // Parse certificate from cached or loaded bytes
        let cert = match X509::from_pem(&cert_bytes) {
            Ok(cert) => cert,
            Err(e) => {
                error!("Failed to parse certificate {}: {}", cert_path, e);
                metrics::record_ssl_handshake(&server_name, false);
                return;
            }
        };

        // Parse private key from cached or loaded bytes
        let key = match PKey::private_key_from_pem(&key_bytes) {
            Ok(key) => key,
            Err(e) => {
                error!("Failed to parse private key {}: {}", key_path, e);
                metrics::record_ssl_handshake(&server_name, false);
                return;
            }
        };

        // Set the certificate and key
        if let Err(e) = ssl_use_certificate(ssl, &cert) {
            error!("Failed to set certificate for domain {}: {}", server_name, e);
            metrics::record_ssl_handshake(&server_name, false);
            return;
        }

        if let Err(e) = ssl_use_private_key(ssl, &key) {
            error!("Failed to set private key for domain {}: {}", server_name, e);
            metrics::record_ssl_handshake(&server_name, false);
            return;
        }

        debug!("SNI certificate successfully configured for domain: {}", server_name);
        metrics::record_ssl_handshake(&server_name, true);
    }
}