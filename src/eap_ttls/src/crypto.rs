//! crypto.rs - Certificate verification and EAP-TTLS key derivation.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ClientConfig;
use rustls::{ClientConnection, DigitallySignedStruct, Error, ProtocolVersion, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use rustls_rustcrypto::provider;
use webpki::EndEntityCert;

use crate::der::extract_cert_validity_secs;

/// Custom verifier enforcing CA chain verification with time bypass for pre-2026 clocks.
#[derive(Debug)]
pub struct CaCertVerifier {
    roots: Arc<RootCertStore>,
    force_1970: bool,
}

impl CaCertVerifier {
    pub fn new(roots: Arc<RootCertStore>, force_1970: bool) -> Self {
        Self { roots, force_1970 }
    }
}

impl ServerCertVerifier for CaCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        mut now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if self.force_1970 {
            now = UnixTime::since_unix_epoch(Duration::from_secs(100)); // Year 1970
            eprintln!("[verifier] Simulating 1970 clock (timestamp=100)");
        }

        let cert = EndEntityCert::try_from(end_entity)
            .map_err(|e| Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(Arc::new(e)))))?;

        let check_time = if now.as_secs() < 1767225600 {
            // Clock is stuck before year 2026 (e.g. 1970 on F680 without RTC).
            // Skip notBefore/notAfter by picking a timestamp within the cert validity.
            if let Some((valid_from, _valid_to)) = extract_cert_validity_secs(end_entity.as_ref()) {
                let adjusted = valid_from.saturating_add(1);
                eprintln!("[verifier] Clock < 2026 (now={}): bypassed notBefore/notAfter check using cert valid_from+1 ({})", now.as_secs(), adjusted);
                UnixTime::since_unix_epoch(Duration::from_secs(adjusted))
            } else {
                eprintln!("[verifier] Clock < 2026: using fallback timestamp 1727740800");
                UnixTime::since_unix_epoch(Duration::from_secs(1727740800))
            }
        } else {
            // Modern clock >= 2026: enforce real time
            now
        };

        let p = provider();
        let sig_algs = p.signature_verification_algorithms.all;
        let anchors: Vec<TrustAnchor<'_>> = self.roots.roots.iter().map(|ta| ta.to_owned()).collect();

        cert.verify_for_usage(
            sig_algs,
            &anchors,
            intermediates,
            check_time,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        ).map_err(|e| Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(Arc::new(e)))))?;

        eprintln!("[verifier] CA signature chain verified successfully!");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}

/// Fallback verifier when no --ca is passed.
#[derive(Debug)]
pub struct InsecureCertVerifier;

impl ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        eprintln!("[verifier] Warning: No --ca passed, skipping certificate verification");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}

pub fn load_ca_roots(path: &str) -> Result<RootCertStore, String> {
    let file = File::open(path).map_err(|e| format!("Cannot open CA file '{}': {}", path, e))?;
    let mut reader = BufReader::new(file);
    let mut roots = RootCertStore::empty();
    let certs = rustls_pemfile::certs(&mut reader);
    let mut count = 0;
    for cert in certs {
        let cert = cert.map_err(|e| format!("PEM parsing error in CA file '{}': {}", path, e))?;
        roots.add(cert).map_err(|e| format!("Failed to add CA cert: {}", e))?;
        count += 1;
    }
    if count == 0 {
        return Err(format!("No certificates found in CA file '{}'", path));
    }
    Ok(roots)
}

pub fn build_client_config(
    ca_path: Option<&str>,
    force_1970: bool,
    tls12_only: bool,
) -> Result<Arc<ClientConfig>, String> {
    let p = Arc::new(provider());
    let builder = if tls12_only {
        ClientConfig::builder_with_provider(p)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .map_err(|e| format!("TLS 1.2 protocol version error: {}", e))?
    } else {
        ClientConfig::builder_with_provider(p)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS protocol versions error: {}", e))?
    };

    let verifier: Arc<dyn ServerCertVerifier> = if let Some(ca) = ca_path {
        let roots = load_ca_roots(ca)?;
        Arc::new(CaCertVerifier::new(Arc::new(roots), force_1970))
    } else {
        Arc::new(InsecureCertVerifier)
    };

    let config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

pub fn derive_pmk(conn: &ClientConnection) -> Result<[u8; 32], String> {
    let mut buf = [0u8; 128];
    let is_tls13 = conn.protocol_version() == Some(ProtocolVersion::TLSv1_3);
    if is_tls13 {
        conn.export_keying_material(&mut buf, b"EXPORTER_EAP_TLS_Key_Material", Some(&[0x15]))
            .map_err(|e| format!("Key export error (TLS 1.3): {}", e))?;
    } else {
        conn.export_keying_material(&mut buf, b"ttls keying material", None)
            .map_err(|e| format!("Key export error (TLS 1.2): {}", e))?;
    }
    let mut pmk = [0u8; 32];
    pmk.copy_from_slice(&buf[0..32]);
    Ok(pmk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suites() {
        let p = provider();
        for cs in &p.cipher_suites {
            println!("Suite: {:?}, version: {:?}", cs.suite(), cs.version());
        }
    }

    #[test]
    fn test_tls12_only_builder() {
        let p = Arc::new(provider());
        let builder = ClientConfig::builder_with_provider(p)
            .with_protocol_versions(&[&rustls::version::TLS12]);
        assert!(builder.is_ok());
    }
}

