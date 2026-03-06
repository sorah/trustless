#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ProxyState {
    pub pid: u32,
    pub port: u16,
    pub control_cert_pem: String,
}

impl ProxyState {
    pub fn path() -> std::path::PathBuf {
        crate::config::state_dir().join("proxy.json")
    }

    pub fn load() -> Result<Self, crate::Error> {
        let data = std::fs::read(Self::path())?;
        Ok(serde_json::from_slice(&data)?)
    }

    pub fn write_atomic(&self) -> Result<(), crate::Error> {
        let path = Self::path();
        let tmp_path = path.with_extension("json.tmp");
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp_path, format!("{data}\n"))?;
        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    pub fn remove() {
        let _ = std::fs::remove_file(Self::path());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_state_roundtrip() {
        let state = ProxyState {
            pid: 12345,
            port: 1443,
            control_cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
                .to_owned(),
        };
        let json = serde_json::to_string(&state).unwrap();
        let loaded: ProxyState = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.pid, 12345);
        assert_eq!(loaded.port, 1443);
        assert_eq!(loaded.control_cert_pem, state.control_cert_pem);
    }
}
