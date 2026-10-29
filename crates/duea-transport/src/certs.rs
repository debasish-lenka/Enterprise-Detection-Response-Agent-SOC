use crate::error::{Result, TransportError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs;
use std::path::Path;

/// Loads a certificate chain from a PEM file
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let data = fs::read(path).map_err(|e| TransportError::Certificate(format!("Failed to read cert file: {}", e)))?;
    let mut reader = std::io::Cursor::new(data);
    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| TransportError::Certificate(format!("Failed to parse certificates: {}", e)))?;

    if certs.is_empty() {
        return Err(TransportError::Certificate("No certificates found in file".into()));
    }
    Ok(certs)
}

/// Loads a private key from a PEM file (PKCS#8 format)
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let data = fs::read(path).map_err(|e| TransportError::PrivateKey(format!("Failed to read key file: {}", e)))?;
    let mut reader = std::io::Cursor::new(data);
    let keys: Vec<PrivatePkcs8KeyDer<'static>> = pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| TransportError::PrivateKey(format!("Failed to parse private key: {}", e)))?;

    let key = keys.into_iter().next()
        .ok_or_else(|| TransportError::PrivateKey("No private key found in file".into()))?;

    Ok(PrivateKeyDer::from(key))
}

/// Creates a client TLS config for mTLS
pub fn make_client_config(
    ca_path: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> Result<rustls::ClientConfig> {
    let ca_certs = load_certs(ca_path)?;
    let client_certs = load_certs(cert_path)?;
    let client_key = load_private_key(key_path)?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert).map_err(|e| TransportError::Certificate(format!("Failed to add CA cert: {}", e)))?;
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|e| TransportError::Config(format!("Failed to build client config: {}", e)))?;

    Ok(config)
}

/// Creates a server TLS config for mTLS (for the management server)
pub fn make_server_config(
    ca_path: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> Result<rustls::ServerConfig> {
    let ca_certs = load_certs(ca_path)?;
    let server_certs = load_certs(cert_path)?;
    let server_key = load_private_key(key_path)?;

    let mut client_auth_roots = rustls::RootCertStore::empty();
    for cert in ca_certs {
        client_auth_roots.add(cert).map_err(|e| TransportError::Certificate(format!("Failed to add client CA cert: {}", e)))?;
    }

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder(client_auth_roots.into())
                .build()
                .map_err(|e| TransportError::Config(format!("Failed to build client verifier: {}", e)))?
        )
        .with_single_cert(server_certs, server_key)
        .map_err(|e| TransportError::Config(format!("Failed to build server config: {}", e)))?;

    Ok(config)
}

/// Generates a self-signed CA certificate for testing
pub fn generate_test_ca() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params = rcgen::CertificateParams::new(vec!["DUEA Test CA".into()]);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];

    let cert = rcgen::Certificate::from_params(params)?;
    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.get_key_pair().serialize_pem();

    Ok((cert_pem.into_bytes(), key_pem.into_bytes()))
}

/// Generates a client certificate signed by the CA (for testing, creates self-signed)
pub fn generate_client_cert(
    _ca_cert: &[u8],
    _ca_key: &[u8],
    common_name: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params = rcgen::CertificateParams::new(vec![common_name.into()]);
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];

    let cert = rcgen::Certificate::from_params(params)?;
    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.get_key_pair().serialize_pem();

    Ok((cert_pem.into_bytes(), key_pem.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn generates_test_ca() {
        let (cert, key) = generate_test_ca().unwrap();
        assert!(!cert.is_empty());
        assert!(!key.is_empty());
        assert!(String::from_utf8_lossy(&cert).contains("BEGIN CERTIFICATE"));
        assert!(String::from_utf8_lossy(&key).contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn generates_client_cert() {
        let (ca_cert, ca_key) = generate_test_ca().unwrap();
        let (client_cert, client_key) = generate_client_cert(&ca_cert, &ca_key, "agent-01").unwrap();
        assert!(!client_cert.is_empty());
        assert!(!client_key.is_empty());
    }

    #[test]
    fn loads_certs_and_keys() {
        let (cert_pem, key_pem) = generate_test_ca().unwrap();

        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(&cert_pem).unwrap();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(&key_pem).unwrap();

        let certs = load_certs(cert_file.path()).unwrap();
        assert_eq!(certs.len(), 1);

        let key = load_private_key(key_file.path()).unwrap();
        assert!(!key.secret_der().is_empty());
    }
}