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
//!
//! # With public relays as a fallback
//!
//! When the lane may also use iroh's public relays, one verifier serves both: a relay whose
//! host is one of ours must present the pinned certificate (and nothing a public CA signed
//! is accepted for it), and any other relay is checked against the public CA roots in the
//! ordinary way. The pin never loosens, and a public relay never needs one.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::Digest as _;

/// A verifier that accepts one certificate, by its SHA-256.
#[derive(Debug)]
pub struct Pinned {
    /// The pin for our own relays (those in `public`'s host list, or all of them when
    /// there is no `public`). `None`: no such default.
    sha256: Option<[u8; 32]>,
    /// Relays the master's list vouches for with a certificate of their own: host, pin.
    /// Checked first.
    host_pins: Vec<(String, [u8; 32])>,
    provider: Arc<CryptoProvider>,
    /// For a relay that is not one of ours: the ordinary public-CA check, and the hosts that
    /// ARE ours (and so need the pin). `None`: every relay needs the pin.
    public: Option<(Arc<dyn ServerCertVerifier>, Vec<String>)>,
}

impl Pinned {
    #[must_use]
    pub fn new(sha256: [u8; 32], provider: Arc<CryptoProvider>) -> Self {
        Self {
            sha256: Some(sha256),
            host_pins: Vec::new(),
            provider,
            public: None,
        }
    }

    /// No default pin: a relay needs the pin the master gave its host, or (with
    /// [`Self::with_public_fallback`]) a public CA.
    #[must_use]
    pub fn without_default(provider: Arc<CryptoProvider>) -> Self {
        Self {
            sha256: None,
            host_pins: Vec::new(),
            provider,
            public: None,
        }
    }

    /// These hosts need exactly these certificates, whatever else is trusted.
    #[must_use]
    pub fn with_host_pins(mut self, pins: Vec<(String, [u8; 32])>) -> Self {
        self.host_pins = pins
            .into_iter()
            .map(|(host, pin)| (host.trim_matches(['[', ']']).to_ascii_lowercase(), pin))
            .collect();
        self
    }

    /// Also accept a relay that is not at one of `pinned_hosts` when a public CA vouches for
    /// it (`public`); the hosts in `pinned_hosts` still need the pin.
    #[must_use]
    pub fn with_public_fallback(
        mut self,
        public: Arc<dyn ServerCertVerifier>,
        pinned_hosts: Vec<String>,
    ) -> Self {
        self.public = Some((public, pinned_hosts));
        self
    }
}

/// The host a `ServerName` names, lowercase, without brackets.
fn host_of(name: &ServerName<'_>) -> String {
    name.to_str().trim_matches(['[', ']']).to_ascii_lowercase()
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
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let host = host_of(server_name);
        let pin = if let Some((_, pin)) = self.host_pins.iter().find(|(h, _)| *h == host) {
            Some(*pin)
        } else {
            if let Some((public, ours)) = &self.public
                && !ours.contains(&host)
            {
                return public.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                );
            }
            self.sha256
        };
        if pin.is_some_and(|pin| fingerprint(end_entity.as_ref()) == pin) {
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
///
/// With a pin and `public_fallback`, relays whose host is not in `pinned_hosts` are checked
/// against the public CA roots instead (see the module notes).
#[must_use]
pub fn ca_config(
    pin: Option<[u8; 32]>,
    pinned_hosts: &[String],
    public_fallback: bool,
) -> iroh::tls::CaTlsConfig {
    ca_config_with(pin, pinned_hosts, &[], public_fallback)
}

/// [`ca_config`], and relays the master's list gave a certificate of their own
/// (`host_pins`: host, pin). Those hosts need exactly that certificate. With `host_pins`
/// and no `pin`, every other relay is checked against the public CAs, as it is without
/// any of this.
#[must_use]
pub fn ca_config_with(
    pin: Option<[u8; 32]>,
    pinned_hosts: &[String],
    host_pins: &[(String, [u8; 32])],
    public_fallback: bool,
) -> iroh::tls::CaTlsConfig {
    if pin.is_none() && host_pins.is_empty() {
        return iroh::tls::CaTlsConfig::embedded();
    }
    let hosts: Vec<String> = pinned_hosts
        .iter()
        .map(|host| host.trim_matches(['[', ']']).to_ascii_lowercase())
        .collect();
    let host_pins = host_pins.to_vec();
    iroh::tls::CaTlsConfig::custom_server_cert_verifier(Arc::new(move |provider| {
        let base = match pin {
            Some(sha256) => Pinned::new(sha256, provider.clone()),
            None => Pinned::without_default(provider.clone()),
        };
        let mut pinned = base.with_host_pins(host_pins.clone());
        if public_fallback || pin.is_none() {
            pinned = pinned.with_public_fallback(
                public_verifier(provider).map_err(std::io::Error::other)?,
                hosts.clone(),
            );
        }
        Ok(Arc::new(pinned) as Arc<_>)
    }))
}

/// The ordinary check: certificates a public CA signed, for the name asked for.
fn public_verifier(
    provider: Arc<CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, rustls::Error> {
    let roots = Arc::new(rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    });
    rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider)
        .build()
        .map(|verifier| verifier as Arc<dyn ServerCertVerifier>)
        .map_err(|error| rustls::Error::General(error.to_string()))
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

    #[test]
    fn a_host_the_master_gave_its_own_pin_needs_that_one() {
        let a = CertificateDer::from(b"certificate a".to_vec());
        let b = CertificateDer::from(b"certificate b".to_vec());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let pinned = Pinned::new(fingerprint(a.as_ref()), provider)
            .with_host_pins(vec![("Relay.Example".into(), fingerprint(b.as_ref()))]);
        let theirs = ServerName::try_from("relay.example").unwrap();
        let ours = ServerName::try_from("162.35.10.46").unwrap();
        let ok = |cert: &CertificateDer<'_>, name: &ServerName<'_>| {
            pinned
                .verify_server_cert(cert, &[], name, &[], UnixTime::now())
                .is_ok()
        };
        assert!(ok(&b, &theirs));
        assert!(!ok(&a, &theirs), "its host does not take the default pin");
        assert!(ok(&a, &ours));
        assert!(!ok(&b, &ours), "another host does not take its pin");
    }

    #[test]
    fn with_no_default_pin_a_host_without_one_is_refused() {
        let a = CertificateDer::from(b"certificate a".to_vec());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let pinned = Pinned::without_default(provider);
        let name = ServerName::try_from("anywhere.example").unwrap();
        assert!(
            pinned
                .verify_server_cert(&a, &[], &name, &[], UnixTime::now())
                .is_err()
        );
    }

    #[test]
    fn our_host_needs_the_pin_even_with_the_public_fallback_on() {
        struct Anything;
        impl std::fmt::Debug for Anything {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("Anything")
            }
        }
        impl ServerCertVerifier for Anything {
            fn verify_server_cert(
                &self,
                _: &CertificateDer<'_>,
                _: &[CertificateDer<'_>],
                _: &ServerName<'_>,
                _: &[u8],
                _: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![SignatureScheme::ED25519]
            }
        }
        let pinned_cert = CertificateDer::from(b"our relay".to_vec());
        let other = CertificateDer::from(b"somebody else".to_vec());
        let ours = ServerName::try_from("162.35.10.46").unwrap();
        let public_name = ServerName::try_from("use1-1.relay.n0.iroh.link").unwrap();
        let verifier = verifier(fingerprint(pinned_cert.as_ref()))
            .with_public_fallback(Arc::new(Anything), vec!["162.35.10.46".into()]);
        let check = |cert: &CertificateDer<'_>, name: &ServerName<'_>| {
            verifier
                .verify_server_cert(cert, &[], name, &[], UnixTime::now())
                .is_ok()
        };
        // Ours: the pin, and a certificate a CA would accept does not stand in for it.
        assert!(check(&pinned_cert, &ours));
        assert!(!check(&other, &ours));
        // Not ours: the public check decides (here, a stand-in that accepts).
        assert!(check(&other, &public_name));
    }

    #[test]
    fn the_public_verifier_builds_and_rejects_garbage() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let public = public_verifier(provider).unwrap();
        let name = ServerName::try_from("use1-1.relay.n0.iroh.link").unwrap();
        let junk = CertificateDer::from(b"not a certificate".to_vec());
        assert!(
            public
                .verify_server_cert(&junk, &[], &name, &[], UnixTime::now())
                .is_err()
        );
    }
}
