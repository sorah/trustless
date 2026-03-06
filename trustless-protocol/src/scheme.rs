/// Parse a signature scheme name string (e.g., `"ECDSA_NISTP256_SHA256"`) into a rustls `SignatureScheme`.
///
/// Returns `None` for unrecognized names.
pub fn parse_scheme(name: &str) -> Option<rustls::SignatureScheme> {
    match name {
        "RSA_PKCS1_SHA256" => Some(rustls::SignatureScheme::RSA_PKCS1_SHA256),
        "RSA_PKCS1_SHA384" => Some(rustls::SignatureScheme::RSA_PKCS1_SHA384),
        "RSA_PKCS1_SHA512" => Some(rustls::SignatureScheme::RSA_PKCS1_SHA512),
        "RSA_PSS_SHA256" => Some(rustls::SignatureScheme::RSA_PSS_SHA256),
        "RSA_PSS_SHA384" => Some(rustls::SignatureScheme::RSA_PSS_SHA384),
        "RSA_PSS_SHA512" => Some(rustls::SignatureScheme::RSA_PSS_SHA512),
        "ECDSA_NISTP256_SHA256" => Some(rustls::SignatureScheme::ECDSA_NISTP256_SHA256),
        "ECDSA_NISTP384_SHA384" => Some(rustls::SignatureScheme::ECDSA_NISTP384_SHA384),
        "ECDSA_NISTP521_SHA512" => Some(rustls::SignatureScheme::ECDSA_NISTP521_SHA512),
        "ED25519" => Some(rustls::SignatureScheme::ED25519),
        "ED448" => Some(rustls::SignatureScheme::ED448),
        _ => None,
    }
}

/// Convert a rustls `SignatureScheme` to its canonical string name.
///
/// Returns `"UNKNOWN"` for unrecognized schemes.
pub fn scheme_to_string(scheme: rustls::SignatureScheme) -> &'static str {
    match scheme {
        rustls::SignatureScheme::RSA_PKCS1_SHA256 => "RSA_PKCS1_SHA256",
        rustls::SignatureScheme::RSA_PKCS1_SHA384 => "RSA_PKCS1_SHA384",
        rustls::SignatureScheme::RSA_PKCS1_SHA512 => "RSA_PKCS1_SHA512",
        rustls::SignatureScheme::RSA_PSS_SHA256 => "RSA_PSS_SHA256",
        rustls::SignatureScheme::RSA_PSS_SHA384 => "RSA_PSS_SHA384",
        rustls::SignatureScheme::RSA_PSS_SHA512 => "RSA_PSS_SHA512",
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256 => "ECDSA_NISTP256_SHA256",
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384 => "ECDSA_NISTP384_SHA384",
        rustls::SignatureScheme::ECDSA_NISTP521_SHA512 => "ECDSA_NISTP521_SHA512",
        rustls::SignatureScheme::ED25519 => "ED25519",
        rustls::SignatureScheme::ED448 => "ED448",
        _ => "UNKNOWN",
    }
}

fn algorithm_for_scheme(scheme: rustls::SignatureScheme) -> rustls::SignatureAlgorithm {
    match scheme {
        rustls::SignatureScheme::RSA_PKCS1_SHA256
        | rustls::SignatureScheme::RSA_PKCS1_SHA384
        | rustls::SignatureScheme::RSA_PKCS1_SHA512
        | rustls::SignatureScheme::RSA_PSS_SHA256
        | rustls::SignatureScheme::RSA_PSS_SHA384
        | rustls::SignatureScheme::RSA_PSS_SHA512 => rustls::SignatureAlgorithm::RSA,
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256
        | rustls::SignatureScheme::ECDSA_NISTP384_SHA384
        | rustls::SignatureScheme::ECDSA_NISTP521_SHA512 => rustls::SignatureAlgorithm::ECDSA,
        rustls::SignatureScheme::ED25519 => rustls::SignatureAlgorithm::ED25519,
        rustls::SignatureScheme::ED448 => rustls::SignatureAlgorithm::ED448,
        _ => rustls::SignatureAlgorithm::Unknown(0),
    }
}

/// Determine the common `SignatureAlgorithm` for a list of schemes.
///
/// Returns `None` if the list is empty or contains schemes from mixed algorithm families
/// (e.g., both RSA and ECDSA).
pub fn algorithm_for_schemes(
    schemes: &[rustls::SignatureScheme],
) -> Option<rustls::SignatureAlgorithm> {
    let first = schemes.first()?;
    let algo = algorithm_for_scheme(*first);
    // Verify all schemes map to the same algorithm
    if schemes
        .iter()
        .skip(1)
        .any(|s| algorithm_for_scheme(*s) != algo)
    {
        return None;
    }
    Some(algo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scheme_round_trip() {
        let names = [
            "RSA_PKCS1_SHA256",
            "RSA_PKCS1_SHA384",
            "RSA_PKCS1_SHA512",
            "RSA_PSS_SHA256",
            "RSA_PSS_SHA384",
            "RSA_PSS_SHA512",
            "ECDSA_NISTP256_SHA256",
            "ECDSA_NISTP384_SHA384",
            "ECDSA_NISTP521_SHA512",
            "ED25519",
            "ED448",
        ];
        for name in names {
            let scheme = parse_scheme(name).unwrap_or_else(|| panic!("failed to parse {name}"));
            assert_eq!(scheme_to_string(scheme), name);
        }
    }

    #[test]
    fn parse_scheme_unknown() {
        assert!(parse_scheme("UNKNOWN_SCHEME").is_none());
    }

    #[test]
    fn algorithm_for_rsa_schemes() {
        let schemes = vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
        ];
        assert_eq!(
            algorithm_for_schemes(&schemes),
            Some(rustls::SignatureAlgorithm::RSA),
        );
    }

    #[test]
    fn algorithm_for_ecdsa_schemes() {
        let schemes = vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256];
        assert_eq!(
            algorithm_for_schemes(&schemes),
            Some(rustls::SignatureAlgorithm::ECDSA),
        );
    }

    #[test]
    fn algorithm_for_ed25519() {
        let schemes = vec![rustls::SignatureScheme::ED25519];
        assert_eq!(
            algorithm_for_schemes(&schemes),
            Some(rustls::SignatureAlgorithm::ED25519),
        );
    }

    #[test]
    fn algorithm_for_empty() {
        assert_eq!(algorithm_for_schemes(&[]), None);
    }

    #[test]
    fn algorithm_for_mixed_algorithms() {
        let schemes = vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ];
        assert_eq!(algorithm_for_schemes(&schemes), None);
    }
}
