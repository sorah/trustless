fn default_port() -> u16 {
    1443
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Config {
    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default)]
    pub tls12: bool,

    #[serde(skip)]
    config_dir: std::path::PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 0,
            tls12: false,
            config_dir: std::path::PathBuf::new(),
        }
    }
}

pub fn default_sign_timeout_seconds() -> u64 {
    15
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub struct Profile {
    pub command: Vec<String>,
    #[serde(default = "default_sign_timeout_seconds")]
    pub sign_timeout_seconds: u64,
}

pub fn config_dir() -> std::path::PathBuf {
    if let Ok(v) = std::env::var("TRUSTLESS_CONFIG_DIR") {
        return v.into();
    }
    std::env::var("XDG_CONFIG_HOME")
        .map(|x| x.into())
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(
                std::env::var("HOME").expect("No $HOME environment variable present"),
            )
            .join(".config")
        })
        .join("trustless")
}

pub fn state_dir() -> std::path::PathBuf {
    if let Ok(v) = std::env::var("TRUSTLESS_STATE_DIR") {
        return v.into();
    }
    match std::env::var("XDG_RUNTIME_DIR") {
        Ok(d) => std::path::PathBuf::from(d).join("trustless"),
        Err(_) => std::path::PathBuf::from(
            std::env::var("HOME").expect("No $HOME environment variable present"),
        )
        .join(".local")
        .join("state")
        .join("trustless")
        .join("run"),
    }
}

const STATE_DIR_MODE: nix::sys::stat::Mode = nix::sys::stat::Mode::S_IRWXU;

pub fn state_dir_mkpath() -> std::io::Result<std::path::PathBuf> {
    let dir = state_dir();
    if dir.exists() {
        use std::os::unix::fs::PermissionsExt;
        #[allow(clippy::useless_conversion)]
        std::fs::set_permissions(
            &dir,
            std::fs::Permissions::from_mode(STATE_DIR_MODE.bits().into()),
        )?;
    } else {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        nix::unistd::mkdir(&dir, STATE_DIR_MODE)?;
    }
    Ok(dir)
}

pub fn log_dir_mkpath() -> std::io::Result<std::path::PathBuf> {
    let dir = state_dir().join("log");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[derive(Debug)]
pub struct ProfileDiff {
    pub added: Vec<(String, Profile)>,
    pub removed: Vec<String>,
    pub changed: Vec<(String, Profile)>,
    pub unchanged: Vec<String>,
}

impl Config {
    pub fn load() -> Result<Self, crate::Error> {
        Self::load_from(config_dir())
    }

    pub fn load_from(base: std::path::PathBuf) -> Result<Self, crate::Error> {
        let path = base.join("config.json");
        let mut config = match std::fs::read(&path) {
            Ok(data) => serde_json::from_slice::<Self>(&data)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(e.into()),
        };
        config.config_dir = base;
        Ok(config)
    }

    pub fn config_dir(&self) -> &std::path::Path {
        &self.config_dir
    }

    pub fn list_profiles(&self) -> Result<Vec<String>, crate::Error> {
        let dir = self.config_dir.join("profiles.d");
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                names.push(stem.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn load_profile(&self, name: &str) -> Result<Profile, crate::Error> {
        let path = self
            .config_dir
            .join("profiles.d")
            .join(format!("{name}.json"));
        let data = std::fs::read(&path)?;
        Ok(serde_json::from_slice(&data)?)
    }

    /// Compute the diff between the currently configured profiles on disk and
    /// a set of running provider profiles (keyed by name).
    pub fn diff_profiles(
        &self,
        current: &std::collections::HashMap<String, Profile>,
    ) -> Result<ProfileDiff, crate::Error> {
        let configured_names: std::collections::HashSet<String> =
            self.list_profiles()?.into_iter().collect();
        let current_names: std::collections::HashSet<String> = current.keys().cloned().collect();

        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();
        let mut unchanged = Vec::new();

        for name in configured_names.difference(&current_names) {
            let profile = self.load_profile(name)?;
            added.push((name.clone(), profile));
        }

        for name in current_names.difference(&configured_names) {
            removed.push(name.clone());
        }

        for name in configured_names.intersection(&current_names) {
            let new_profile = self.load_profile(name)?;
            if current.get(name) == Some(&new_profile) {
                unchanged.push(name.clone());
            } else {
                changed.push((name.clone(), new_profile));
            }
        }

        Ok(ProfileDiff {
            added,
            removed,
            changed,
            unchanged,
        })
    }

    pub fn save_profile(&self, name: &str, profile: &Profile) -> Result<(), crate::Error> {
        let dir = self.config_dir.join("profiles.d");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{name}.json"));
        let data = serde_json::to_string_pretty(profile)?;
        std::fs::write(&path, format!("{data}\n"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load_from(dir.path().to_path_buf()).unwrap();
        let profile = Profile {
            command: vec![
                "cargo".into(),
                "run".into(),
                "--".into(),
                "--cert-dir".into(),
                "/tmp/certs".into(),
            ],
            sign_timeout_seconds: default_sign_timeout_seconds(),
        };
        config.save_profile("test", &profile).unwrap();
        let loaded = config.load_profile("test").unwrap();
        assert_eq!(loaded.command, profile.command);
    }

    #[test]
    fn test_list_profiles_empty() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load_from(dir.path().to_path_buf()).unwrap();
        let profiles = config.list_profiles().unwrap();
        assert!(profiles.is_empty());
    }

    #[test]
    fn test_list_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load_from(dir.path().to_path_buf()).unwrap();
        let profile = Profile {
            command: vec!["cmd".into()],
            sign_timeout_seconds: default_sign_timeout_seconds(),
        };
        config.save_profile("beta", &profile).unwrap();
        config.save_profile("alpha", &profile).unwrap();
        let profiles = config.list_profiles().unwrap();
        assert_eq!(profiles, vec!["alpha", "beta"]);
    }

    #[test]
    fn test_config_load_default_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load_from(dir.path().to_path_buf()).unwrap();
        assert_eq!(config.port, 0); // Default::default() gives 0 for u16
    }

    #[test]
    fn test_config_load_with_default_port() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();
        let config = Config::load_from(dir.path().to_path_buf()).unwrap();
        assert_eq!(config.port, 1443);
    }

    #[test]
    fn test_config_load_with_custom_port() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), r#"{"port": 8443}"#).unwrap();
        let config = Config::load_from(dir.path().to_path_buf()).unwrap();
        assert_eq!(config.port, 8443);
    }

    #[test]
    fn test_config_tls12_default_false() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();
        let config = Config::load_from(dir.path().to_path_buf()).unwrap();
        assert!(!config.tls12);
    }

    #[test]
    fn test_config_tls12_enabled() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), r#"{"tls12": true}"#).unwrap();
        let config = Config::load_from(dir.path().to_path_buf()).unwrap();
        assert!(config.tls12);
    }

    fn make_profile(cmd: &str) -> Profile {
        Profile {
            command: vec![cmd.into()],
            sign_timeout_seconds: default_sign_timeout_seconds(),
        }
    }

    #[test]
    fn test_diff_profiles_added() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load_from(dir.path().to_path_buf()).unwrap();
        config.save_profile("new", &make_profile("cmd1")).unwrap();

        let current = std::collections::HashMap::new();
        let diff = config.diff_profiles(&current).unwrap();

        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].0, "new");
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
        assert!(diff.unchanged.is_empty());
    }

    #[test]
    fn test_diff_profiles_removed() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load_from(dir.path().to_path_buf()).unwrap();

        let current = std::collections::HashMap::from([("old".to_owned(), make_profile("cmd1"))]);
        let diff = config.diff_profiles(&current).unwrap();

        assert!(diff.added.is_empty());
        assert_eq!(diff.removed, vec!["old"]);
        assert!(diff.changed.is_empty());
        assert!(diff.unchanged.is_empty());
    }

    #[test]
    fn test_diff_profiles_changed() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load_from(dir.path().to_path_buf()).unwrap();
        config.save_profile("p", &make_profile("new_cmd")).unwrap();

        let current = std::collections::HashMap::from([("p".to_owned(), make_profile("old_cmd"))]);
        let diff = config.diff_profiles(&current).unwrap();

        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].0, "p");
        assert_eq!(diff.changed[0].1.command, vec!["new_cmd".to_owned()]);
        assert!(diff.unchanged.is_empty());
    }

    #[test]
    fn test_diff_profiles_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load_from(dir.path().to_path_buf()).unwrap();
        let profile = make_profile("cmd1");
        config.save_profile("p", &profile).unwrap();

        let current = std::collections::HashMap::from([("p".to_owned(), profile)]);
        let diff = config.diff_profiles(&current).unwrap();

        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
        assert_eq!(diff.unchanged, vec!["p"]);
    }

    #[test]
    fn test_diff_profiles_mixed() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load_from(dir.path().to_path_buf()).unwrap();
        config
            .save_profile("added", &make_profile("cmd_a"))
            .unwrap();
        config.save_profile("same", &make_profile("cmd_s")).unwrap();
        config
            .save_profile("changed", &make_profile("cmd_new"))
            .unwrap();

        let current = std::collections::HashMap::from([
            ("same".to_owned(), make_profile("cmd_s")),
            ("changed".to_owned(), make_profile("cmd_old")),
            ("removed".to_owned(), make_profile("cmd_r")),
        ]);
        let diff = config.diff_profiles(&current).unwrap();

        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].0, "added");
        assert_eq!(diff.removed, vec!["removed"]);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].0, "changed");
        assert_eq!(diff.unchanged, vec!["same"]);
    }
}
