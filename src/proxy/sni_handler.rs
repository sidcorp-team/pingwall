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
use std::sync::Arc;
use log::{info, error};
use crate::metrics;

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

        // Load certificate from file
        let cert_bytes = match std::fs::read(&cert_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to read certificate file {}: {}", cert_path, e);
                metrics::record_ssl_handshake(&server_name, false);
                return;
            }
        };

        let cert = match X509::from_pem(&cert_bytes) {
            Ok(cert) => cert,
            Err(e) => {
                error!("Failed to parse certificate {}: {}", cert_path, e);
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

        info!("SNI certificate successfully configured for domain: {}", server_name);
        metrics::record_ssl_handshake(&server_name, true);
    }
}