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

#[derive(serde::Serialize, serde::Deserialize, Debug)]
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

pub fn state_dir_mkpath() -> std::io::Result<std::path::PathBuf> {
    let dir = state_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn log_dir_mkpath() -> std::io::Result<std::path::PathBuf> {
    let dir = state_dir().join("log");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

impl Config {
    pub fn load() -> Result<Self, crate::Error> {
        Self::load_from(config_dir())
    }

    fn load_from(base: std::path::PathBuf) -> Result<Self, crate::Error> {
        let path = base.join("config.json");
        let mut config = match std::fs::read(&path) {
            Ok(data) => serde_json::from_slice::<Self>(&data)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(e.into()),
        };
        config.config_dir = base;
        Ok(config)
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
}
