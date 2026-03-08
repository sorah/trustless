const ARROW_SVG: &str = r#"<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M6.5 3.5L11 8l-4.5 4.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>"#;

fn engine() -> minijinja::Environment<'static> {
    let mut env = minijinja::Environment::new();
    minijinja_embed::load_templates!(&mut env);
    env
}

#[derive(serde::Serialize)]
struct ErrorPageRouteEntry {
    hostname: String,
    addr: String,
}

fn sorted_routes(
    routes: &std::collections::HashMap<String, crate::route::RouteEntry>,
) -> Vec<ErrorPageRouteEntry> {
    let mut sorted: Vec<_> = routes.iter().collect();
    sorted.sort_by_key(|(h, _)| h.as_str());
    sorted
        .into_iter()
        .map(|(hostname, entry)| ErrorPageRouteEntry {
            hostname: hostname.clone(),
            addr: entry.backend.to_string(),
        })
        .collect()
}

pub fn render_404_page(
    host: &str,
    routes: &std::collections::HashMap<String, crate::route::RouteEntry>,
) -> String {
    let env = engine();
    let tmpl = env.get_template("404.html").unwrap();
    tmpl.render(minijinja::context! {
        status => 404,
        status_text => "Not Found",
        host => host,
        routes => sorted_routes(routes),
        arrow_svg => minijinja::Value::from_safe_string(ARROW_SVG.to_string()),
    })
    .expect("render 404.html")
}

pub fn render_404_text(
    host: &str,
    routes: &std::collections::HashMap<String, crate::route::RouteEntry>,
) -> String {
    let env = engine();
    let tmpl = env.get_template("404.txt").unwrap();
    tmpl.render(minijinja::context! {
        host => host,
        routes => sorted_routes(routes),
    })
    .expect("render 404.txt")
}

pub fn render_502_page(backend: std::net::SocketAddr, error_detail: &str) -> String {
    let env = engine();
    let tmpl = env.get_template("502.html").unwrap();
    tmpl.render(minijinja::context! {
        status => 502,
        status_text => "Bad Gateway",
        backend => backend.to_string(),
        error_detail => error_detail,
    })
    .expect("render 502.html")
}

/// Provider error with a pre-computed relative timestamp for templates.
#[derive(serde::Serialize)]
struct ErrorPageError {
    kind: String,
    message: String,
    timestamp_relative: String,
}

/// Provider info with enriched errors for template rendering.
#[derive(serde::Serialize)]
struct ErrorPageProvider {
    name: String,
    state: String,
    certificates: Vec<crate::provider::CertificateStatusInfo>,
    errors: Vec<ErrorPageError>,
}

fn enrich_providers(providers: &[crate::provider::ProviderStatusInfo]) -> Vec<ErrorPageProvider> {
    providers
        .iter()
        .map(|p| ErrorPageProvider {
            name: p.name.clone(),
            state: p.state.to_string(),
            certificates: p.certificates.clone(),
            errors: p
                .errors
                .iter()
                .map(|e| ErrorPageError {
                    kind: e.error.kind.to_string(),
                    message: e.error.message.clone(),
                    timestamp_relative: crate::provider::format_relative_time(e.timestamp),
                })
                .collect(),
        })
        .collect()
}

pub fn render_status_page(status: &crate::control::StatusResponse) -> String {
    let routes: Vec<ErrorPageRouteEntry> = {
        let mut sorted: Vec<_> = status.routes.iter().collect();
        sorted.sort_by_key(|(h, _)| h.as_str());
        sorted
            .into_iter()
            .map(|(hostname, addr)| ErrorPageRouteEntry {
                hostname: hostname.clone(),
                addr: addr.clone(),
            })
            .collect()
    };

    let providers = enrich_providers(&status.providers);

    let env = engine();
    let tmpl = env.get_template("status.html").unwrap();
    tmpl.render(minijinja::context! {
        page_title => "trustless",
        status => "",
        status_text => "trustless",
        pid => status.pid,
        port => status.port,
        providers => providers,
        routes => routes,
        arrow_svg => minijinja::Value::from_safe_string(ARROW_SVG.to_string()),
    })
    .expect("render status.html")
}

pub fn render_508_page(host: &str, hops: u32) -> String {
    let env = engine();
    let tmpl = env.get_template("508.html").unwrap();
    tmpl.render(minijinja::context! {
        status => 508,
        status_text => "Loop Detected",
        host => host,
        hops => hops,
    })
    .expect("render 508.html")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_status_page_empty() {
        let status = crate::control::StatusResponse {
            pid: 12345,
            port: 1443,
            providers: vec![],
            routes: std::collections::HashMap::new(),
        };
        let html = render_status_page(&status);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<title>trustless</title>"));
        assert!(html.contains("1443"));
        assert!(html.contains("12345"));
        assert!(html.contains("No apps running."));
    }

    #[test]
    fn test_render_status_page_with_routes() {
        let mut routes = std::collections::HashMap::new();
        routes.insert("app.lo.dev".to_string(), "127.0.0.1:3000".to_string());
        let status = crate::control::StatusResponse {
            pid: 1,
            port: 1443,
            providers: vec![],
            routes,
        };
        let html = render_status_page(&status);
        assert!(html.contains("app.lo.dev"));
        assert!(html.contains("127.0.0.1:3000"));
        assert!(html.contains("Active apps"));
    }

    #[test]
    fn test_render_status_page_with_providers() {
        let status = crate::control::StatusResponse {
            pid: 1,
            port: 1443,
            providers: vec![crate::provider::ProviderStatusInfo {
                name: "test-provider".to_string(),
                state: crate::provider::ProviderState::Running,
                command: vec![],
                certificates: vec![crate::provider::CertificateStatusInfo {
                    id: "v1".to_string(),
                    domains: vec!["*.lo.dev".to_string()],
                    issuer: "Test CA".to_string(),
                    serial: "1234".to_string(),
                    not_after: "2027-01-01".to_string(),
                }],
                errors: vec![],
            }],
            routes: std::collections::HashMap::new(),
        };
        let html = render_status_page(&status);
        assert!(html.contains("test-provider"));
        assert!(html.contains("dot-running"));
        assert!(html.contains("*.lo.dev"));
        assert!(html.contains("2027-01-01"));
    }

    #[test]
    fn test_render_404_page_no_routes() {
        let routes = std::collections::HashMap::new();
        let html = render_404_page("unknown.host", &routes);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("404"));
        assert!(html.contains("Not Found"));
        assert!(html.contains("unknown.host"));
        assert!(html.contains("No apps running."));
        assert!(html.contains("prefers-color-scheme: dark"));
        assert!(html.contains("trustless run your-command"));
    }

    #[test]
    fn test_render_404_page_with_routes() {
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "app.lo.dev".to_string(),
            crate::route::RouteEntry {
                backend: "127.0.0.1:3000".parse().unwrap(),
                name: None,
            },
        );
        let html = render_404_page("unknown.host", &routes);
        assert!(html.contains("Active apps"));
        assert!(html.contains("app.lo.dev"));
        assert!(html.contains("127.0.0.1:3000"));
        assert!(
            html.contains(r#"data-hostname="app.lo.dev""#),
            "card links should use data-hostname"
        );
        assert!(
            html.contains("location.port"),
            "should have JS to set href from location"
        );
    }

    #[test]
    fn test_render_404_page_escapes_host() {
        let routes = std::collections::HashMap::new();
        let html = render_404_page("<img src=x onerror=steal()>", &routes);
        assert!(
            !html.contains("<img"),
            "user-supplied HTML tags must be escaped"
        );
        assert!(html.contains("&lt;img src=x onerror=steal()&gt;"));
    }

    #[test]
    fn test_render_404_text_no_routes() {
        let routes = std::collections::HashMap::new();
        let text = render_404_text("unknown.host", &routes);
        assert!(text.contains("no route for host: unknown.host"));
        assert!(text.contains("trustless run your-command"));
        assert!(!text.contains("Active apps"));
    }

    #[test]
    fn test_render_404_text_with_routes() {
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "app.lo.dev".to_string(),
            crate::route::RouteEntry {
                backend: "127.0.0.1:3000".parse().unwrap(),
                name: None,
            },
        );
        let text = render_404_text("unknown.host", &routes);
        assert!(text.contains("Active apps:"));
        assert!(text.contains("app.lo.dev -> 127.0.0.1:3000"));
        assert!(text.contains("trustless run your-command"));
    }

    #[test]
    fn test_render_502_page() {
        let backend = "127.0.0.1:3000".parse().unwrap();
        let html = render_502_page(backend, "is not responding");
        assert!(html.contains("502"));
        assert!(html.contains("Bad Gateway"));
        assert!(html.contains("127.0.0.1:3000"));
        assert!(html.contains("is not responding"));
    }

    #[test]
    fn test_render_508_page() {
        let html = render_508_page("loop.example.com", 5);
        assert!(html.contains("508"));
        assert!(html.contains("Loop Detected"));
        assert!(html.contains("loop.example.com"));
        assert!(html.contains(">5<"));
        assert!(html.contains("changeOrigin"));
    }

    #[test]
    fn test_dark_mode_css_present() {
        let routes = std::collections::HashMap::new();
        let html = render_404_page("x", &routes);
        assert!(html.contains("prefers-color-scheme: dark"));
        assert!(html.contains("--bg: #000"));
    }

    #[test]
    fn test_heading_layout() {
        let routes = std::collections::HashMap::new();
        let html = render_404_page("x", &routes);
        assert!(html.contains(r#"<span class="status">404</span><h1>Not Found</h1>"#));
    }

    #[test]
    fn test_footer_link() {
        let routes = std::collections::HashMap::new();
        let html = render_404_page("x", &routes);
        assert!(html.contains("Powered by"));
        assert!(html.contains("sorah/trustless"));
    }
}
