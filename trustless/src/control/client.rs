use std::net::SocketAddr;

use super::state::ProxyState;

pub struct Client {
    inner: reqwest::Client,
    #[allow(dead_code)]
    port: u16,
}

impl Client {
    /// Build a client from a given ProxyState with certificate pinning.
    pub fn from_proxy_state(state: &ProxyState) -> Result<Self, crate::Error> {
        let mut root_store = rustls::RootCertStore::empty();
        let pem_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pki_types::pem::PemObject::pem_slice_iter(state.control_cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()?;
        for cert_der in &pem_certs {
            root_store.add(cert_der.clone())?;
        }

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let addr: SocketAddr = ([127, 0, 0, 1], state.port).into();
        let inner = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config)
            .resolve("trustless", addr)
            .no_proxy()
            .build()?;

        Ok(Self {
            inner,
            port: state.port,
        })
    }

    /// Load proxy state from disk and build a client with pinned certificate.
    pub fn from_state() -> Result<Self, crate::Error> {
        let state = ProxyState::load()?;
        Self::from_proxy_state(&state)
    }

    /// Ping the proxy. Returns Ok(()) if alive.
    pub async fn ping(&self) -> Result<(), crate::Error> {
        let resp = self.inner.get("https://trustless/ping").send().await?;
        if !resp.status().is_success() {
            return Err(crate::Error::Control(format!(
                "ping failed: HTTP {}",
                resp.status()
            )));
        }
        Ok(())
    }

    /// Request graceful shutdown. Fire-and-forget.
    pub async fn stop(&self) -> Result<(), crate::Error> {
        let resp = self.inner.post("https://trustless/stop").send().await?;
        if !resp.status().is_success() {
            return Err(crate::Error::Control(format!(
                "stop failed: HTTP {}",
                resp.status()
            )));
        }
        Ok(())
    }
}

/// Connect to existing proxy or auto-start one.
/// Respects TRUSTLESS_NO_AUTO_PROXY env var.
pub async fn connect_or_start() -> Result<Client, crate::Error> {
    if let Ok(client) = Client::from_state()
        && client.ping().await.is_ok()
    {
        return Ok(client);
    }

    if std::env::var_os("TRUSTLESS_NO_AUTO_PROXY").is_some() {
        return Err(crate::Error::Control(
            "no running proxy and TRUSTLESS_NO_AUTO_PROXY is set".to_owned(),
        ));
    }

    tracing::info!("Starting the proxy");
    spawn_proxy().await?;

    let fut = async {
        loop {
            if let Ok(client) = Client::from_state()
                && client.ping().await.is_ok()
            {
                return Ok(client);
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    };

    match tokio::time::timeout(std::time::Duration::from_secs(20), fut).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(crate::Error::Control(
            "timed out waiting for proxy to start".to_owned(),
        )),
    }
}

/// Spawn proxy as a daemon process.
async fn spawn_proxy() -> Result<(), crate::Error> {
    let arg0 = process_path::get_executable_path().expect("can't get executable path");

    // Pass TRUSTLESS_PROXY_LOG as TRUSTLESS_LOG to the spawned proxy
    let mut cmd = tokio::process::Command::new(arg0);
    cmd.args(["proxy", "start", "--log-to-file", "--daemonize"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(false);

    if let Ok(v) = std::env::var("TRUSTLESS_PROXY_LOG") {
        cmd.env("TRUSTLESS_LOG", v);
    }

    cmd.status().await?;
    Ok(())
}
