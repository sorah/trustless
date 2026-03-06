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

        let addr: std::net::SocketAddr = ([127, 0, 0, 1], state.port).into();
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

    pub async fn status(&self) -> Result<super::StatusResponse, crate::Error> {
        let resp = self.inner.get("https://trustless/status").send().await?;
        if !resp.status().is_success() {
            return Err(crate::Error::Control(format!(
                "status failed: HTTP {}",
                resp.status()
            )));
        }
        Ok(resp.json::<super::StatusResponse>().await?)
    }

    pub async fn reload(&self) -> Result<super::ReloadResponse, crate::Error> {
        let resp = self.inner.post("https://trustless/reload").send().await?;
        if !resp.status().is_success() {
            return Err(crate::Error::Control(format!(
                "reload failed: HTTP {}",
                resp.status()
            )));
        }
        Ok(resp.json::<super::ReloadResponse>().await?)
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
