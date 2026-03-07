use crate::route::RouteError;

/// How a hostname was specified by the user.
#[derive(Debug, Clone)]
pub(crate) enum HostnameSpec {
    /// Subdomain label — will be combined with a wildcard domain via resolve_hostname
    Label(String),
    /// Full FQDN — used directly, bypasses resolve_hostname
    Full(String),
}

/// Result of resolving a hostname spec into a concrete hostname.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedHostname {
    pub hostname: String,
    pub domain_suffix: Option<String>,
}

impl HostnameSpec {
    /// Resolve this spec into a concrete hostname.
    ///
    /// For `Label`, looks up provider info and combines the label with a wildcard domain suffix.
    /// For `Full`, validates the hostname and returns it directly.
    pub fn resolve(
        &self,
        status: &crate::control::StatusResponse,
        profile: Option<&str>,
        domain: Option<&str>,
    ) -> anyhow::Result<ResolvedHostname> {
        match self {
            HostnameSpec::Label(s) => {
                let (hostname, suffix) = resolve_hostname(status, s, profile, domain)?;
                Ok(ResolvedHostname {
                    hostname,
                    domain_suffix: Some(suffix),
                })
            }
            HostnameSpec::Full(h) => {
                validate_hostname(h)?;
                Ok(ResolvedHostname {
                    hostname: h.clone(),
                    domain_suffix: None,
                })
            }
        }
    }
}

pub fn validate_hostname(host: &str) -> Result<(), RouteError> {
    if host.eq_ignore_ascii_case("trustless") {
        return Err(RouteError::ReservedHostname(host.to_string()));
    }
    if host.is_empty() {
        return Err(RouteError::InvalidHostname(
            host.to_string(),
            "hostname must not be empty".to_string(),
        ));
    }
    if host.len() > 253 {
        return Err(RouteError::InvalidHostname(
            host.to_string(),
            "hostname too long".to_string(),
        ));
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err(RouteError::InvalidHostname(
                host.to_string(),
                "empty label".to_string(),
            ));
        }
        if label.len() > 63 {
            return Err(RouteError::InvalidHostname(
                host.to_string(),
                "label too long".to_string(),
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(RouteError::InvalidHostname(
                host.to_string(),
                "invalid characters in label".to_string(),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(RouteError::InvalidHostname(
                host.to_string(),
                "label must not start or end with a hyphen".to_string(),
            ));
        }
    }
    Ok(())
}

/// Sanitize an arbitrary string into a valid DNS label.
/// Lowercases, replaces invalid characters with hyphens, collapses consecutive
/// hyphens, and trims leading/trailing hyphens. Returns `None` if the result is empty.
pub fn sanitize_label(input: &str) -> Option<String> {
    let s: String = input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = s.trim_matches('-');
    let mut result = String::with_capacity(trimmed.len());
    let mut prev_hyphen = false;
    for c in trimmed.chars() {
        if c == '-' {
            if !prev_hyphen {
                result.push('-');
            }
            prev_hyphen = true;
        } else {
            result.push(c);
            prev_hyphen = false;
        }
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Given a subdomain label and a list of wildcard domain suffixes (without `*.` prefix),
/// find the best matching suffix using longest prefix matching.
///
/// A suffix is valid if, after removing overlapping trailing labels from the subdomain
/// that match leading labels of the suffix, exactly 1 label remains (wildcard covers
/// a single label only). Among valid suffixes, the one with the longest overlap wins.
/// Returns `None` if zero or multiple suffixes tie.
fn find_best_wildcard_suffix<'a>(subdomain: &str, suffixes: &[&'a str]) -> Option<&'a str> {
    let sub_labels: Vec<&str> = subdomain.split('.').collect();

    let mut best: Option<&str> = None;
    let mut best_overlap: usize = 0;
    let mut ambiguous = false;

    for &suffix in suffixes {
        let suffix_labels: Vec<&str> = suffix.split('.').collect();

        // Find the overlap: how many trailing labels of subdomain match leading labels of suffix
        let max_overlap = sub_labels.len().min(suffix_labels.len());
        let mut overlap = 0;
        for k in 1..=max_overlap {
            // Check if last k labels of subdomain == first k labels of suffix
            if sub_labels[sub_labels.len() - k..] == suffix_labels[..k] {
                overlap = k;
            }
        }

        // After removing overlapping labels, remaining subdomain labels count
        let remaining = sub_labels.len() - overlap;
        if remaining != 1 {
            continue; // wildcard covers exactly one label
        }

        if overlap > best_overlap {
            best = Some(suffix);
            best_overlap = overlap;
            ambiguous = false;
        } else if overlap == best_overlap {
            ambiguous = true;
        }
    }

    if ambiguous { None } else { best }
}

/// Resolves subdomain + provider info into `(full_hostname, domain_suffix)`.
pub(crate) fn resolve_hostname(
    status: &crate::control::StatusResponse,
    subdomain: &str,
    profile: Option<&str>,
    domain: Option<&str>,
) -> anyhow::Result<(String, String)> {
    let provider = match profile {
        Some(name) => status
            .providers
            .iter()
            .find(|p| p.name == *name)
            .ok_or_else(|| anyhow::anyhow!("provider profile '{}' not found", name))?,
        None => {
            if status.providers.len() == 1 {
                &status.providers[0]
            } else if status.providers.is_empty() {
                anyhow::bail!("no providers configured; run 'trustless setup' first");
            } else {
                let names: Vec<&str> = status.providers.iter().map(|p| p.name.as_str()).collect();
                anyhow::bail!(
                    "multiple providers configured ({}); use --profile to select one",
                    names.join(", ")
                );
            }
        }
    };

    let wildcard_domains: Vec<&str> = provider
        .certificates
        .iter()
        .flat_map(|cert| cert.domains.iter())
        .filter_map(|d| d.strip_prefix("*."))
        .collect();

    let suffix = match domain {
        Some(domain) => {
            if wildcard_domains.contains(&domain) {
                domain
            } else {
                anyhow::bail!(
                    "domain '{}' not found in provider '{}' certificates; available: {}",
                    domain,
                    provider.name,
                    wildcard_domains.join(", ")
                );
            }
        }
        None => {
            if wildcard_domains.len() == 1 {
                wildcard_domains[0]
            } else if wildcard_domains.is_empty() {
                anyhow::bail!(
                    "no wildcard domains in provider '{}' certificates",
                    provider.name
                );
            } else if let Some(best) = find_best_wildcard_suffix(subdomain, &wildcard_domains) {
                best
            } else {
                anyhow::bail!(
                    "multiple wildcard domains in provider '{}'; use --domain to select one: {}",
                    provider.name,
                    wildcard_domains.join(", ")
                );
            }
        }
    };

    let hostname = format!("{}.{}", subdomain, suffix);
    validate_hostname(&hostname)?;
    Ok((hostname, suffix.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_hostname() {
        // Empty hostname
        assert!(validate_hostname("").is_err());
        // Spaces
        assert!(validate_hostname("host name").is_err());
        // Leading hyphen
        assert!(validate_hostname("-host.example").is_err());
        // Valid hostname
        assert!(validate_hostname("api.lo.dev.invalid").is_ok());
        // Reserved
        assert!(validate_hostname("trustless").is_err());
        assert!(validate_hostname("Trustless").is_err());
        assert!(validate_hostname("TRUSTLESS").is_err());
    }

    #[test]
    fn test_sanitize_label() {
        assert_eq!(sanitize_label("MyApp"), Some("myapp".to_string()));
        assert_eq!(sanitize_label("my_app"), Some("my-app".to_string()));
        assert_eq!(sanitize_label("my app"), Some("my-app".to_string()));
        assert_eq!(sanitize_label("my--app"), Some("my-app".to_string()));
        assert_eq!(sanitize_label("a___b"), Some("a-b".to_string()));
        assert_eq!(sanitize_label("--myapp--"), Some("myapp".to_string()));
        assert_eq!(sanitize_label("@myapp!"), Some("myapp".to_string()));
        assert_eq!(sanitize_label("@@@"), None);
        assert_eq!(sanitize_label("---"), None);
        assert_eq!(sanitize_label(""), None);
        assert_eq!(sanitize_label("my-app-123"), Some("my-app-123".to_string()));
        assert_eq!(
            sanitize_label("My_Feature_Branch"),
            Some("my-feature-branch".to_string())
        );
    }

    fn make_status(
        providers: Vec<crate::provider::ProviderStatusInfo>,
    ) -> crate::control::StatusResponse {
        crate::control::StatusResponse {
            pid: 1,
            port: 1443,
            providers,
            routes: std::collections::HashMap::new(),
        }
    }

    fn make_provider(name: &str, domains: Vec<&str>) -> crate::provider::ProviderStatusInfo {
        crate::provider::ProviderStatusInfo {
            name: name.to_string(),
            state: crate::provider::ProviderState::Running,
            certificates: vec![crate::provider::CertificateStatusInfo {
                id: "test".to_string(),
                domains: domains.into_iter().map(|s| s.to_string()).collect(),
                issuer: "test".to_string(),
                serial: "00".to_string(),
                not_after: "2099-01-01".to_string(),
            }],
            errors: vec![],
        }
    }

    #[test]
    fn test_resolve_hostname_single_provider_single_wildcard() {
        let status = make_status(vec![make_provider("default", vec!["*.dev.invalid"])]);
        let (hostname, suffix) = resolve_hostname(&status, "api", None, None).unwrap();
        assert_eq!(hostname, "api.dev.invalid");
        assert_eq!(suffix, "dev.invalid");
    }

    #[test]
    fn test_resolve_hostname_with_profile() {
        let status = make_status(vec![
            make_provider("alpha", vec!["*.alpha.invalid"]),
            make_provider("beta", vec!["*.beta.invalid"]),
        ]);
        let (hostname, suffix) = resolve_hostname(&status, "app", Some("beta"), None).unwrap();
        assert_eq!(hostname, "app.beta.invalid");
        assert_eq!(suffix, "beta.invalid");
    }

    #[test]
    fn test_resolve_hostname_with_domain() {
        let status = make_status(vec![make_provider(
            "default",
            vec!["*.a.invalid", "*.b.invalid"],
        )]);
        let (hostname, suffix) = resolve_hostname(&status, "app", None, Some("b.invalid")).unwrap();
        assert_eq!(hostname, "app.b.invalid");
        assert_eq!(suffix, "b.invalid");
    }

    #[test]
    fn test_resolve_hostname_no_providers() {
        let status = make_status(vec![]);
        let err = resolve_hostname(&status, "app", None, None).unwrap_err();
        assert!(err.to_string().contains("no providers configured"));
    }

    #[test]
    fn test_resolve_hostname_ambiguous_providers() {
        let status = make_status(vec![
            make_provider("a", vec!["*.a.invalid"]),
            make_provider("b", vec!["*.b.invalid"]),
        ]);
        let err = resolve_hostname(&status, "app", None, None).unwrap_err();
        assert!(err.to_string().contains("--profile"));
    }

    #[test]
    fn test_resolve_hostname_ambiguous_domains() {
        let status = make_status(vec![make_provider(
            "default",
            vec!["*.a.invalid", "*.b.invalid"],
        )]);
        let err = resolve_hostname(&status, "app", None, None).unwrap_err();
        assert!(err.to_string().contains("--domain"));
    }

    #[test]
    fn test_find_best_wildcard_suffix_basic() {
        // foo.bar with *.bar.dev.invalid and *.dev.invalid:
        // bar.dev.invalid: overlap=1 (bar), remaining=1 (foo) → valid
        // dev.invalid: overlap=0, remaining=2 (foo.bar) → invalid
        let result = find_best_wildcard_suffix("foo.bar", &["bar.dev.invalid", "dev.invalid"]);
        assert_eq!(result, Some("bar.dev.invalid"));
    }

    #[test]
    fn test_find_best_wildcard_suffix_three_levels() {
        // foo.baz.bar with three wildcard levels
        let result = find_best_wildcard_suffix(
            "foo.baz.bar",
            &["baz.bar.dev.invalid", "bar.dev.invalid", "dev.invalid"],
        );
        assert_eq!(result, Some("baz.bar.dev.invalid"));
    }

    #[test]
    fn test_find_best_wildcard_suffix_ambiguous() {
        // foo with *.bar.dev.invalid and *.dev.invalid:
        // bar.dev.invalid: overlap=0, remaining=1 (foo) → valid
        // dev.invalid: overlap=0, remaining=1 (foo) → valid
        // Both valid with overlap=0 → ambiguous
        let result = find_best_wildcard_suffix("foo", &["bar.dev.invalid", "dev.invalid"]);
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_hostname_auto_selects_by_prefix_match() {
        let status = make_status(vec![make_provider(
            "default",
            vec!["*.bar.dev.invalid", "*.dev.invalid"],
        )]);
        let (hostname, suffix) = resolve_hostname(&status, "foo.bar", None, None).unwrap();
        assert_eq!(hostname, "foo.bar.bar.dev.invalid");
        assert_eq!(suffix, "bar.dev.invalid");
    }

    #[test]
    fn test_resolve_hostname_explicit_domain_overrides_auto() {
        let status = make_status(vec![make_provider(
            "default",
            vec!["*.bar.dev.invalid", "*.dev.invalid"],
        )]);
        let (hostname, suffix) =
            resolve_hostname(&status, "foo.bar", None, Some("dev.invalid")).unwrap();
        assert_eq!(hostname, "foo.bar.dev.invalid");
        assert_eq!(suffix, "dev.invalid");
    }

    #[test]
    fn test_resolve_hostname_profile_not_found() {
        let status = make_status(vec![make_provider("default", vec!["*.dev.invalid"])]);
        let err = resolve_hostname(&status, "app", Some("nonexistent"), None).unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn test_resolve_hostname_domain_not_found() {
        let status = make_status(vec![make_provider("default", vec!["*.dev.invalid"])]);
        let err = resolve_hostname(&status, "app", None, Some("other.invalid")).unwrap_err();
        assert!(err.to_string().contains("other.invalid"));
    }

    #[test]
    fn test_hostname_spec_resolve_label() {
        let status = make_status(vec![make_provider("default", vec!["*.dev.invalid"])]);
        let spec = HostnameSpec::Label("api".to_string());
        let resolved = spec.resolve(&status, None, None).unwrap();
        assert_eq!(resolved.hostname, "api.dev.invalid");
        assert_eq!(resolved.domain_suffix, Some("dev.invalid".to_string()));
    }

    #[test]
    fn test_hostname_spec_resolve_full() {
        let status = make_status(vec![make_provider("default", vec!["*.dev.invalid"])]);
        let spec = HostnameSpec::Full("custom.example.com".to_string());
        let resolved = spec.resolve(&status, None, None).unwrap();
        assert_eq!(resolved.hostname, "custom.example.com");
        assert_eq!(resolved.domain_suffix, None);
    }
}
