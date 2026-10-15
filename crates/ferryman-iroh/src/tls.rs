//! Trusting exactly one relay certificate.
//!
//! iroh verifies a relay's TLS certificate with whatever [`iroh::tls::CaTlsConfig`] it is
//! given: public CA roots by default, or a `ServerCertVerifier` of our own through
//! `CaTlsConfig::custom_server_cert_verifier`. Our relay's certificate is self-signed for
//! a bare IP, so no CA will ever vouch for it, and the alternative iroh ships for that
//! case (skip verification) exists only under its `test-utils` feature and would trust
//! anyone. This is the verifier in between: the certificate's SHA-256 must be the pinned
//! one, and the handshake signatures are still checked against it with the crypto
//! provider's own algorithms, so possession of the certificate's private key is proven
//! as it would be for any other TLS server.
//!
//! The server name is not checked, deliberately: there is no name, and the pin is
//! stronger than one. Rotating the relay's certificate means changing the pin on every
//! machine, which is the point.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::Digest as _;

/// A verifier that accepts one certificate, by its SHA-256.
#[derive(Debug)]
pub struct Pinned {
    sha256: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl Pinned {
    #[must_use]
    pub fn new(sha256: [u8; 32], provider: Arc<CryptoProvider>) -> Self {
        Self { sha256, provider }
    }
}

/// The SHA-256 of a DER certificate, as a pin is written.
#[must_use]
pub fn fingerprint(der: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(der).into()
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if fingerprint(end_entity.as_ref()) == self.sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The relay TLS trust for a config: the pin when there is one, public CAs when not.
#[must_use]
pub fn ca_config(pin: Option<[u8; 32]>) -> iroh::tls::CaTlsConfig {
    match pin {
        Some(sha256) => {
            iroh::tls::CaTlsConfig::custom_server_cert_verifier(Arc::new(move |provider| {
                Ok(Arc::new(Pinned::new(sha256, provider)) as Arc<_>)
            }))
        }
        None => iroh::tls::CaTlsConfig::embedded(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier(pin: [u8; 32]) -> Pinned {
        Pinned::new(pin, Arc::new(rustls::crypto::ring::default_provider()))
    }

    #[test]
    fn only_the_pinned_certificate_is_accepted() {
        let cert = CertificateDer::from(b"pretend this is DER".to_vec());
        let name = ServerName::try_from("162.35.10.46").unwrap();
        let pinned = verifier(fingerprint(cert.as_ref()));
        assert!(
            pinned
                .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
                .is_ok()
        );
        let other = CertificateDer::from(b"some other certificate".to_vec());
        assert!(
            pinned
                .verify_server_cert(&other, &[], &name, &[], UnixTime::now())
                .is_err()
        );
    }
}
