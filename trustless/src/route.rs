#[derive(thiserror::Error, Debug)]
pub enum RouteError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("route already exists for host '{0}' (use --force to overwrite)")]
    RouteExists(String),
    #[error("no route exists for host '{0}'")]
    RouteNotFound(String),
    #[error("hostname '{0}' is reserved")]
    ReservedHostname(String),
    #[error("invalid hostname '{0}': {1}")]
    InvalidHostname(String, String),
    #[error("backend {0} is not a loopback address (use --allow-non-localhost to allow)")]
    NonLoopbackBackend(std::net::SocketAddr),
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct RouteEntry {
    pub backend: std::net::SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
struct RoutesFile {
    routes: std::collections::HashMap<String, RouteEntry>,
}

struct Inner {
    state_dir: std::path::PathBuf,
    cached_routes: std::collections::HashMap<String, RouteEntry>,
    cached_mtime: Option<std::time::SystemTime>,
}

#[derive(Clone)]
pub struct RouteTable {
    inner: std::sync::Arc<parking_lot::Mutex<Inner>>,
}

pub fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        // Bracketed IPv6: [::1]:8080 or [::1]
        match rest.find(']') {
            Some(i) => &host[..i + 2], // include the brackets
            None => host,
        }
    } else {
        match host.rsplit_once(':') {
            Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
            _ => host,
        }
    }
}

impl RouteTable {
    pub fn new(state_dir: std::path::PathBuf) -> Self {
        Self {
            inner: std::sync::Arc::new(parking_lot::Mutex::new(Inner {
                state_dir,
                cached_routes: std::collections::HashMap::new(),
                cached_mtime: None,
            })),
        }
    }

    fn routes_path(state_dir: &std::path::Path) -> std::path::PathBuf {
        state_dir.join("routes.json")
    }

    pub fn list_routes(&self) -> Result<std::collections::HashMap<String, RouteEntry>, RouteError> {
        let mut inner = self.inner.lock();
        let path = Self::routes_path(&inner.state_dir);

        let current_mtime = match std::fs::metadata(&path) {
            Ok(meta) => Some(meta.modified()?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                inner.cached_routes.clear();
                inner.cached_mtime = None;
                return Ok(std::collections::HashMap::new());
            }
            Err(e) => return Err(e.into()),
        };

        if inner.cached_mtime != current_mtime {
            let data = std::fs::read(&path)?;
            let file: RoutesFile = serde_json::from_slice(&data)?;
            inner.cached_routes = file.routes;
            inner.cached_mtime = current_mtime;
        }

        Ok(inner.cached_routes.clone())
    }

    pub fn resolve(&self, host: &str) -> Result<Option<std::net::SocketAddr>, RouteError> {
        let host = strip_port(host);
        let mut inner = self.inner.lock();
        let path = Self::routes_path(&inner.state_dir);

        let current_mtime = match std::fs::metadata(&path) {
            Ok(meta) => Some(meta.modified()?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                inner.cached_routes.clear();
                inner.cached_mtime = None;
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        if inner.cached_mtime != current_mtime {
            let data = std::fs::read(&path)?;
            let file: RoutesFile = serde_json::from_slice(&data)?;
            inner.cached_routes = file.routes;
            inner.cached_mtime = current_mtime;
            tracing::debug!("route table reloaded from disk");
        }

        Ok(inner.cached_routes.get(host).map(|e| e.backend))
    }

    /// Open the routes file with an exclusive advisory lock and return the parsed contents
    /// along with the locked file handle. The caller must keep the file handle alive until
    /// after `save_routes` completes, so the flock is held throughout the read-modify-write.
    fn lock_and_load(
        &self,
        host: &str,
        create: bool,
    ) -> Result<(RoutesFile, std::fs::File), RouteError> {
        let path = {
            let inner = self.inner.lock();
            if create {
                std::fs::create_dir_all(&inner.state_dir)?;
            }
            Self::routes_path(&inner.state_dir)
        };

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .truncate(false)
            .open(&path)
            .map_err(|e| {
                if !create && e.kind() == std::io::ErrorKind::NotFound {
                    RouteError::RouteNotFound(host.to_string())
                } else {
                    RouteError::Io(e)
                }
            })?;
        flock_exclusive(&file)?;

        use std::io::Read as _;
        let mut data = Vec::new();
        (&file).read_to_end(&mut data)?;
        let routes_file = if data.is_empty() {
            RoutesFile::default()
        } else {
            serde_json::from_slice(&data)?
        };

        Ok((routes_file, file))
    }

    fn save_routes(file: &std::fs::File, routes_file: &RoutesFile) -> Result<(), RouteError> {
        use std::io::{Seek as _, Write as _};
        let data = serde_json::to_string_pretty(routes_file)?;
        let mut file = file;
        file.seek(std::io::SeekFrom::Start(0))?;
        file.set_len(0)?;
        file.write_all(format!("{data}\n").as_bytes())?;
        Ok(())
    }

    pub fn add_route(
        &self,
        host: &str,
        backend: std::net::SocketAddr,
        name: Option<&str>,
        force: bool,
        allow_non_localhost: bool,
    ) -> Result<(), RouteError> {
        crate::domain::validate_hostname(host)?;
        if !allow_non_localhost && !backend.ip().is_loopback() {
            return Err(RouteError::NonLoopbackBackend(backend));
        }
        let (mut routes_file, file) = self.lock_and_load(host, true)?;

        if !force && routes_file.routes.contains_key(host) {
            return Err(RouteError::RouteExists(host.to_string()));
        }

        routes_file.routes.insert(
            host.to_string(),
            RouteEntry {
                backend,
                name: name.map(|s| s.to_string()),
            },
        );
        Self::save_routes(&file, &routes_file)
    }

    pub fn find_by_name(&self, name: &str) -> Result<Option<(String, RouteEntry)>, RouteError> {
        let routes = self.list_routes()?;

        // First try matching by name field
        let mut matches: Vec<_> = routes
            .iter()
            .filter(|(_, entry)| entry.name.as_deref() == Some(name))
            .collect();

        if matches.len() == 1 {
            let (host, entry) = matches.remove(0);
            return Ok(Some((host.clone(), entry.clone())));
        }
        if matches.len() > 1 {
            return Ok(None); // ambiguous
        }

        // Fall back to exact hostname match
        if let Some(entry) = routes.get(name) {
            return Ok(Some((name.to_string(), entry.clone())));
        }

        Ok(None)
    }

    pub fn remove_route(&self, host: &str) -> Result<(), RouteError> {
        let (mut routes_file, file) = self.lock_and_load(host, false)?;

        if routes_file.routes.remove(host).is_none() {
            return Err(RouteError::RouteNotFound(host.to_string()));
        }

        Self::save_routes(&file, &routes_file)
    }
}

fn flock_exclusive(file: &std::fs::File) -> Result<(), std::io::Error> {
    file.lock()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());

        let addr: std::net::SocketAddr = "127.0.0.1:3000".parse().unwrap();
        table
            .add_route("api.lo.dev.invalid", addr, Some("api"), false, false)
            .unwrap();

        let resolved = table.resolve("api.lo.dev.invalid").unwrap();
        assert_eq!(resolved, Some(addr));

        // Verify file content
        let data = std::fs::read_to_string(dir.path().join("routes.json")).unwrap();
        let file: RoutesFile = serde_json::from_str(&data).unwrap();
        let entry = file.routes.get("api.lo.dev.invalid").unwrap();
        assert_eq!(entry.backend, addr);
        assert_eq!(entry.name.as_deref(), Some("api"));
    }

    #[test]
    fn test_duplicate_host_detection() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());

        let addr: std::net::SocketAddr = "127.0.0.1:3000".parse().unwrap();
        table
            .add_route("api.lo.dev.invalid", addr, None, false, false)
            .unwrap();

        let err = table
            .add_route("api.lo.dev.invalid", addr, None, false, false)
            .unwrap_err();
        assert!(matches!(err, RouteError::RouteExists(_)));
    }

    #[test]
    fn test_force_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());

        let addr1: std::net::SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let addr2: std::net::SocketAddr = "127.0.0.1:4000".parse().unwrap();
        table
            .add_route("api.lo.dev.invalid", addr1, None, false, false)
            .unwrap();
        table
            .add_route("api.lo.dev.invalid", addr2, None, true, false)
            .unwrap();

        let resolved = table.resolve("api.lo.dev.invalid").unwrap();
        assert_eq!(resolved, Some(addr2));
    }

    #[test]
    fn test_remove_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());

        let err = table.remove_route("nonexistent.host").unwrap_err();
        assert!(matches!(err, RouteError::RouteNotFound(_)));
    }

    #[test]
    fn test_host_port_stripping() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());

        let addr: std::net::SocketAddr = "127.0.0.1:3000".parse().unwrap();
        table
            .add_route("api.lo.dev.invalid", addr, None, false, false)
            .unwrap();

        let resolved = table.resolve("api.lo.dev.invalid:8080").unwrap();
        assert_eq!(resolved, Some(addr));
    }

    #[test]
    fn test_strip_port() {
        assert_eq!(strip_port("example.com:8080"), "example.com");
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("[::1]:8080"), "[::1]");
        assert_eq!(strip_port("[::1]"), "[::1]");
        assert_eq!(strip_port("[2001:db8::1]:443"), "[2001:db8::1]");
    }

    #[test]
    fn test_reserved_host_rejection() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());

        let addr: std::net::SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let err = table
            .add_route("trustless", addr, None, false, false)
            .unwrap_err();
        assert!(matches!(err, RouteError::ReservedHostname(_)));
    }

    #[test]
    fn test_reserved_host_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());

        let addr: std::net::SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let err = table
            .add_route("Trustless", addr, None, false, false)
            .unwrap_err();
        assert!(matches!(err, RouteError::ReservedHostname(_)));

        let err = table
            .add_route("TRUSTLESS", addr, None, false, false)
            .unwrap_err();
        assert!(matches!(err, RouteError::ReservedHostname(_)));
    }

    #[test]
    fn test_non_loopback_backend_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());

        let addr: std::net::SocketAddr = "192.168.1.1:3000".parse().unwrap();
        let err = table
            .add_route("app.lo.dev.invalid", addr, None, false, false)
            .unwrap_err();
        assert!(matches!(err, RouteError::NonLoopbackBackend(_)));

        // With --allow-non-localhost it should succeed
        table
            .add_route("app.lo.dev.invalid", addr, None, false, true)
            .unwrap();
    }

    #[test]
    fn test_invalid_hostname() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());
        let addr: std::net::SocketAddr = "127.0.0.1:3000".parse().unwrap();

        // Empty hostname
        assert!(table.add_route("", addr, None, false, false).is_err());
        // Spaces
        assert!(
            table
                .add_route("host name", addr, None, false, false)
                .is_err()
        );
        // Leading hyphen
        assert!(
            table
                .add_route("-host.example", addr, None, false, false)
                .is_err()
        );
    }

    #[test]
    fn test_mtime_caching() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());

        let addr1: std::net::SocketAddr = "127.0.0.1:3000".parse().unwrap();
        table
            .add_route("api.lo.dev.invalid", addr1, None, false, false)
            .unwrap();

        // First resolve caches the file
        let resolved = table.resolve("api.lo.dev.invalid").unwrap();
        assert_eq!(resolved, Some(addr1));

        // Externally modify the file
        let addr2: std::net::SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let routes_file = RoutesFile {
            routes: std::collections::HashMap::from([(
                "api.lo.dev.invalid".to_string(),
                RouteEntry {
                    backend: addr2,
                    name: None,
                },
            )]),
        };
        // Ensure mtime changes (some filesystems have 1-second granularity)
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let data = serde_json::to_string_pretty(&routes_file).unwrap();
        std::fs::write(dir.path().join("routes.json"), format!("{data}\n")).unwrap();

        // Re-resolve should pick up the change
        let resolved = table.resolve("api.lo.dev.invalid").unwrap();
        assert_eq!(resolved, Some(addr2));
    }

    #[test]
    fn test_missing_routes_file() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());

        let resolved = table.resolve("nonexistent.host").unwrap();
        assert_eq!(resolved, None);
    }

    #[test]
    fn test_concurrent_add_remove() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());

        // Add initial routes
        for i in 0..10 {
            let addr: std::net::SocketAddr = format!("127.0.0.1:{}", 3000 + i).parse().unwrap();
            table
                .add_route(&format!("host{i}.example.com"), addr, None, false, false)
                .unwrap();
        }

        // Verify all routes exist
        for i in 0..10 {
            let expected: std::net::SocketAddr = format!("127.0.0.1:{}", 3000 + i).parse().unwrap();
            let resolved = table.resolve(&format!("host{i}.example.com")).unwrap();
            assert_eq!(resolved, Some(expected));
        }

        // Remove some routes
        for i in 0..5 {
            table.remove_route(&format!("host{i}.example.com")).unwrap();
        }

        // Verify remaining routes
        for i in 0..5 {
            let resolved = table.resolve(&format!("host{i}.example.com")).unwrap();
            assert_eq!(resolved, None);
        }
        for i in 5..10 {
            let expected: std::net::SocketAddr = format!("127.0.0.1:{}", 3000 + i).parse().unwrap();
            let resolved = table.resolve(&format!("host{i}.example.com")).unwrap();
            assert_eq!(resolved, Some(expected));
        }
    }

    #[test]
    fn test_find_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());

        let addr: std::net::SocketAddr = "127.0.0.1:3000".parse().unwrap();
        table
            .add_route("api.lo.dev.invalid", addr, Some("api"), false, false)
            .unwrap();

        // Find by name
        let (host, entry) = table.find_by_name("api").unwrap().unwrap();
        assert_eq!(host, "api.lo.dev.invalid");
        assert_eq!(entry.backend, addr);
        assert_eq!(entry.name.as_deref(), Some("api"));

        // Not found
        assert!(table.find_by_name("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_find_by_name_falls_back_to_hostname() {
        let dir = tempfile::tempdir().unwrap();
        let table = RouteTable::new(dir.path().to_path_buf());

        let addr: std::net::SocketAddr = "127.0.0.1:3000".parse().unwrap();
        table
            .add_route("api.lo.dev.invalid", addr, None, false, false)
            .unwrap();

        // No name field set, but exact hostname match works
        let (host, entry) = table.find_by_name("api.lo.dev.invalid").unwrap().unwrap();
        assert_eq!(host, "api.lo.dev.invalid");
        assert_eq!(entry.backend, addr);
    }
}
