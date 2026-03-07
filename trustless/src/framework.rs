use std::ffi::OsString;

#[enum_dispatch::enum_dispatch]
pub trait FrameworkBehavior {
    /// Build the full command args (replacing the original command entirely).
    /// Receives the original command and port; returns the complete args
    /// with framework-specific flags injected as needed.
    fn build_command(&self, command: &[OsString], port: u16) -> Vec<OsString>;

    /// Extra environment variables to set.
    /// `domain_suffix` is the domain suffix from the wildcard cert (e.g. "dev.example.com").
    fn extra_env(&self, domain_suffix: Option<&str>) -> Vec<(OsString, OsString)>;
}

pub struct Vite;
pub struct ReactRouter;
pub struct Astro;
pub struct Angular;
pub struct ReactNative;
pub struct Expo;

#[enum_dispatch::enum_dispatch(FrameworkBehavior)]
pub enum Framework {
    Vite,
    ReactRouter,
    Astro,
    Angular,
    ReactNative,
    Expo,
}

/// Detect framework from command args. Extracts basename of command[0],
/// looks up in known frameworks. Returns None for unknown commands.
pub fn detect(command: &[OsString]) -> Option<Framework> {
    let arg0 = command.first()?;
    let arg0_str = arg0.to_str()?;
    let basename = std::path::Path::new(arg0_str).file_name()?.to_str()?;

    match basename {
        "vite" => Some(Framework::Vite(Vite)),
        "react-router" => Some(Framework::ReactRouter(ReactRouter)),
        "astro" => Some(Framework::Astro(Astro)),
        "ng" | "angular" => Some(Framework::Angular(Angular)),
        "react-native" => Some(Framework::ReactNative(ReactNative)),
        "expo" => Some(Framework::Expo(Expo)),
        _ => None,
    }
}

fn has_flag(args: &[OsString], flag: &str) -> bool {
    args.iter().any(|a| a.to_str().is_some_and(|s| s == flag))
}

fn append_port_flags(args: &mut Vec<OsString>, port: u16, strict: bool) {
    if !has_flag(args, "--port") {
        args.push("--port".into());
        args.push(port.to_string().into());
        if strict {
            args.push("--strictPort".into());
        }
    }
}

fn append_host_flag(args: &mut Vec<OsString>, host: &str) {
    if !has_flag(args, "--host") {
        args.push("--host".into());
        args.push(host.into());
    }
}

fn build_command_common(
    command: &[OsString],
    port: u16,
    strict_port: bool,
    host: &str,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = command.to_vec();
    append_port_flags(&mut args, port, strict_port);
    append_host_flag(&mut args, host);
    args
}

fn vite_extra_env(domain_suffix: Option<&str>) -> Vec<(OsString, OsString)> {
    let mut env = Vec::new();
    if let Some(wd) = domain_suffix {
        env.push((
            "__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS".into(),
            format!(".{}", wd).into(),
        ));
    }
    env
}

impl FrameworkBehavior for Vite {
    fn build_command(&self, command: &[OsString], port: u16) -> Vec<OsString> {
        build_command_common(command, port, true, "127.0.0.1")
    }

    fn extra_env(&self, domain_suffix: Option<&str>) -> Vec<(OsString, OsString)> {
        vite_extra_env(domain_suffix)
    }
}

impl FrameworkBehavior for ReactRouter {
    fn build_command(&self, command: &[OsString], port: u16) -> Vec<OsString> {
        build_command_common(command, port, true, "127.0.0.1")
    }

    fn extra_env(&self, domain_suffix: Option<&str>) -> Vec<(OsString, OsString)> {
        vite_extra_env(domain_suffix)
    }
}

impl FrameworkBehavior for Astro {
    fn build_command(&self, command: &[OsString], port: u16) -> Vec<OsString> {
        build_command_common(command, port, false, "127.0.0.1")
    }

    fn extra_env(&self, _domain_suffix: Option<&str>) -> Vec<(OsString, OsString)> {
        Vec::new()
    }
}

impl FrameworkBehavior for Angular {
    fn build_command(&self, command: &[OsString], port: u16) -> Vec<OsString> {
        build_command_common(command, port, false, "127.0.0.1")
    }

    fn extra_env(&self, _domain_suffix: Option<&str>) -> Vec<(OsString, OsString)> {
        Vec::new()
    }
}

impl FrameworkBehavior for ReactNative {
    fn build_command(&self, command: &[OsString], port: u16) -> Vec<OsString> {
        build_command_common(command, port, false, "127.0.0.1")
    }

    fn extra_env(&self, _domain_suffix: Option<&str>) -> Vec<(OsString, OsString)> {
        Vec::new()
    }
}

impl FrameworkBehavior for Expo {
    fn build_command(&self, command: &[OsString], port: u16) -> Vec<OsString> {
        build_command_common(command, port, false, "localhost")
    }

    fn extra_env(&self, _domain_suffix: Option<&str>) -> Vec<(OsString, OsString)> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> OsString {
        s.into()
    }

    fn cmd(args: &[&str]) -> Vec<OsString> {
        args.iter().map(|s| os(s)).collect()
    }

    // --- detect tests ---

    #[test]
    fn test_detect_vite() {
        assert!(matches!(
            detect(&cmd(&["vite", "dev"])),
            Some(Framework::Vite(_))
        ));
    }

    #[test]
    fn test_detect_vite_with_path() {
        assert!(matches!(
            detect(&cmd(&["./node_modules/.bin/vite", "dev"])),
            Some(Framework::Vite(_))
        ));
    }

    #[test]
    fn test_detect_react_router() {
        assert!(matches!(
            detect(&cmd(&["react-router", "dev"])),
            Some(Framework::ReactRouter(_))
        ));
    }

    #[test]
    fn test_detect_astro() {
        assert!(matches!(
            detect(&cmd(&["astro", "dev"])),
            Some(Framework::Astro(_))
        ));
    }

    #[test]
    fn test_detect_angular_ng() {
        assert!(matches!(
            detect(&cmd(&["ng", "serve"])),
            Some(Framework::Angular(_))
        ));
    }

    #[test]
    fn test_detect_angular() {
        assert!(matches!(
            detect(&cmd(&["angular", "serve"])),
            Some(Framework::Angular(_))
        ));
    }

    #[test]
    fn test_detect_react_native() {
        assert!(matches!(
            detect(&cmd(&["react-native", "start"])),
            Some(Framework::ReactNative(_))
        ));
    }

    #[test]
    fn test_detect_expo() {
        assert!(matches!(
            detect(&cmd(&["expo", "start"])),
            Some(Framework::Expo(_))
        ));
    }

    #[test]
    fn test_detect_unknown() {
        assert!(detect(&cmd(&["node", "server.js"])).is_none());
    }

    #[test]
    fn test_detect_empty() {
        assert!(detect(&[]).is_none());
    }

    #[test]
    fn test_detect_path_variants() {
        assert!(matches!(
            detect(&cmd(&["/usr/local/bin/vite"])),
            Some(Framework::Vite(_))
        ));
        assert!(matches!(
            detect(&cmd(&["../node_modules/.bin/astro", "dev"])),
            Some(Framework::Astro(_))
        ));
    }

    // --- build_command tests ---

    #[test]
    fn test_vite_build_command() {
        let result = Vite.build_command(&cmd(&["vite", "dev"]), 3000);
        assert_eq!(
            result,
            cmd(&[
                "vite",
                "dev",
                "--port",
                "3000",
                "--strictPort",
                "--host",
                "127.0.0.1"
            ])
        );
    }

    #[test]
    fn test_react_router_build_command() {
        let result = ReactRouter.build_command(&cmd(&["react-router", "dev"]), 5000);
        assert_eq!(
            result,
            cmd(&[
                "react-router",
                "dev",
                "--port",
                "5000",
                "--strictPort",
                "--host",
                "127.0.0.1"
            ])
        );
    }

    #[test]
    fn test_astro_build_command() {
        let result = Astro.build_command(&cmd(&["astro", "dev"]), 4321);
        assert_eq!(
            result,
            cmd(&["astro", "dev", "--port", "4321", "--host", "127.0.0.1"])
        );
    }

    #[test]
    fn test_angular_build_command() {
        let result = Angular.build_command(&cmd(&["ng", "serve"]), 4200);
        assert_eq!(
            result,
            cmd(&["ng", "serve", "--port", "4200", "--host", "127.0.0.1"])
        );
    }

    #[test]
    fn test_expo_build_command_uses_localhost() {
        let result = Expo.build_command(&cmd(&["expo", "start"]), 8081);
        assert_eq!(
            result,
            cmd(&["expo", "start", "--port", "8081", "--host", "localhost"])
        );
    }

    #[test]
    fn test_preserves_existing_port_flag() {
        let result = Vite.build_command(&cmd(&["vite", "dev", "--port", "9999"]), 3000);
        // Should not append --port or --strictPort
        assert_eq!(
            result,
            cmd(&["vite", "dev", "--port", "9999", "--host", "127.0.0.1"])
        );
    }

    #[test]
    fn test_preserves_existing_host_flag() {
        let result = Vite.build_command(&cmd(&["vite", "dev", "--host", "0.0.0.0"]), 3000);
        assert_eq!(
            result,
            cmd(&[
                "vite",
                "dev",
                "--host",
                "0.0.0.0",
                "--port",
                "3000",
                "--strictPort"
            ])
        );
    }

    #[test]
    fn test_preserves_both_existing_flags() {
        let result = Vite.build_command(
            &cmd(&["vite", "dev", "--port", "9999", "--host", "0.0.0.0"]),
            3000,
        );
        assert_eq!(
            result,
            cmd(&["vite", "dev", "--port", "9999", "--host", "0.0.0.0"])
        );
    }

    // --- extra_env tests ---

    #[test]
    fn test_vite_extra_env_with_wildcard() {
        let env = Vite.extra_env(Some("dev.example.com"));
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].0, os("__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS"));
        assert_eq!(env[0].1, os(".dev.example.com"));
    }

    #[test]
    fn test_vite_extra_env_without_wildcard() {
        let env = Vite.extra_env(None);
        assert!(env.is_empty());
    }

    #[test]
    fn test_react_router_extra_env_with_wildcard() {
        let env = ReactRouter.extra_env(Some("dev.example.com"));
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].0, os("__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS"));
        assert_eq!(env[0].1, os(".dev.example.com"));
    }

    #[test]
    fn test_astro_extra_env_empty() {
        assert!(Astro.extra_env(Some("dev.example.com")).is_empty());
    }

    #[test]
    fn test_angular_extra_env_empty() {
        assert!(Angular.extra_env(Some("dev.example.com")).is_empty());
    }

    #[test]
    fn test_react_native_extra_env_empty() {
        assert!(ReactNative.extra_env(Some("dev.example.com")).is_empty());
    }

    #[test]
    fn test_expo_extra_env_empty() {
        assert!(Expo.extra_env(Some("dev.example.com")).is_empty());
    }
}
