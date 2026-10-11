use crate::config::{Config, Endpoint};
use crate::policy::{self, Action};
use crate::{log_info, log_warn};
use reqwest::{Client, Url};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::Deserialize;
use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

pub struct Share(String);

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Share(<redacted>)")
    }
}

impl Share {
    pub fn from_credentials(dir: Option<OsString>, name: &str) -> Result<Self, String> {
        let dir = dir
            .filter(|d| !d.is_empty())
            .ok_or("CREDENTIALS_DIRECTORY is not set")?;
        let path = Path::new(&dir).join(name);
        let raw = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let text =
            String::from_utf8(raw).map_err(|_| format!("{}: not valid UTF-8", path.display()))?;
        let share = text.trim();
        if share.is_empty() {
            return Err(format!("{}: empty", path.display()));
        }
        Ok(Share(share.to_owned()))
    }
}

#[derive(Debug, Deserialize)]
struct SealStatus {
    #[serde(default = "yes")]
    initialized: bool,
    sealed: bool,
    #[serde(default)]
    progress: u32,
    #[serde(default)]
    t: u32,
}

fn yes() -> bool {
    true
}

impl SealStatus {
    fn describe(&self) -> String {
        match (self.initialized, self.sealed) {
            (false, _) => "not initialized".into(),
            (true, true) => format!("sealed progress={}/{}", self.progress, self.t),
            (true, false) => "unsealed".into(),
        }
    }
}

enum Outcome {
    Status(SealStatus),
    Failed(String),
}

pub fn tls_config(extra_ca_file: Option<&Path>) -> Result<rustls::ClientConfig, String> {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    if let Some(path) = extra_ca_file {
        let certs = CertificateDer::pem_file_iter(path)
            .and_then(|it| it.collect::<Result<Vec<_>, _>>())
            .map_err(|e| format!("extra_ca_file {}: {e}", path.display()))?;
        if certs.is_empty() {
            return Err(format!("extra_ca_file {}: no certificates", path.display()));
        }
        for cert in certs {
            roots
                .add(cert)
                .map_err(|e| format!("extra_ca_file {}: {e}", path.display()))?;
        }
    }
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())
        .map(|b| b.with_root_certificates(roots).with_no_client_auth())
}

pub fn client_for(
    endpoint: &Endpoint,
    tls: &rustls::ClientConfig,
) -> Result<(Client, Url), String> {
    let base = Url::parse(&format!(
        "https://{}:{}/",
        endpoint.name,
        endpoint.addr.port()
    ))
    .map_err(|e| format!("endpoint {}: {e}", endpoint.name))?;
    let client = Client::builder()
        .tls_backend_preconfigured(tls.clone())
        .resolve(&endpoint.name, endpoint.addr)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("endpoint {}: {}", endpoint.name, chain(&e)))?;
    Ok((client, base))
}

pub async fn run(config: Config, share: Share) -> Result<(), String> {
    let tls = tls_config(config.extra_ca_file.as_deref())?;
    let share = Arc::new(share);
    let interval = config.interval();
    let mut tasks = JoinSet::new();
    for endpoint in &config.endpoints {
        let (client, base) = client_for(endpoint, &tls)?;
        tasks.spawn(watch(
            endpoint.name.clone(),
            client,
            base,
            share.clone(),
            interval,
        ));
    }
    log_info!(
        "vault-share-unsealer {} watching {} endpoint(s) every {}s",
        crate::VERSION,
        config.endpoints.len(),
        config.interval_secs
    );
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| format!("signal handler: {e}"))?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
        res = tasks.join_next() => {
            return Err(format!("endpoint task stopped: {res:?}"));
        }
    }
    log_info!("stopping");
    Ok(())
}

async fn watch(name: String, client: Client, base: Url, share: Arc<Share>, interval: Duration) {
    let mut failures = 0u32;
    let mut last = String::new();
    loop {
        let (line, failed) = match check(&client, &base, &share).await {
            Outcome::Status(status) => (status.describe(), false),
            Outcome::Failed(reason) => (reason, true),
        };
        if line != last {
            if failed {
                log_warn!("endpoint={name} {line}");
            } else {
                log_info!("endpoint={name} {line}");
            }
            last = line;
        }
        failures = if failed {
            failures.saturating_add(1)
        } else {
            0
        };
        tokio::time::sleep(policy::next_delay(
            interval,
            failures,
            policy::random_unit(),
        ))
        .await;
    }
}

async fn check(client: &Client, base: &Url, share: &Share) -> Outcome {
    let status = match get_seal_status(client, base).await {
        Ok(status) => status,
        Err(e) => return Outcome::Failed(e),
    };
    match policy::decide(status.initialized, status.sealed) {
        Action::Idle => Outcome::Status(status),
        Action::Unseal => submit(client, base, share).await,
    }
}

async fn get_seal_status(client: &Client, base: &Url) -> Result<SealStatus, String> {
    let url = base.join("v1/sys/seal-status").map_err(|e| e.to_string())?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("seal-status failed: {}", chain(&e)))?;
    let code = resp.status();
    if !code.is_success() {
        return Err(format!("seal-status failed: HTTP {}", code.as_u16()));
    }
    resp.json::<SealStatus>()
        .await
        .map_err(|e| format!("seal-status failed: {}", chain(&e)))
}

async fn submit(client: &Client, base: &Url, share: &Share) -> Outcome {
    let url = match base.join("v1/sys/unseal") {
        Ok(url) => url,
        Err(e) => return Outcome::Failed(e.to_string()),
    };
    let body = serde_json::json!({ "key": share.0 });
    let resp = match client.put(url).json(&body).send().await {
        Ok(resp) => resp,
        Err(e) => return Outcome::Failed(format!("unseal failed: {}", chain(&e))),
    };
    drop(body);
    let code = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !code.is_success() {
        return Outcome::Failed(format!(
            "unseal rejected: {} (HTTP {})",
            policy::classify_unseal_error(&text),
            code.as_u16()
        ));
    }
    match serde_json::from_str::<SealStatus>(&text) {
        Ok(status) => Outcome::Status(status),
        Err(_) => Outcome::Failed("unseal failed: unexpected response".into()),
    }
}

fn chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(inner) = source {
        let msg = inner.to_string();
        if !out.contains(&msg) {
            out.push_str(": ");
            out.push_str(&msg);
        }
        source = inner.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_with(content: Option<&[u8]>) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("vsu-test-{}", policy::random_unit().to_bits()));
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(content) = content {
            std::fs::write(dir.join("vault-unseal-share"), content).unwrap();
        }
        dir
    }

    #[test]
    fn reads_and_trims_share() {
        let dir = dir_with(Some(b"  abc123==\n"));
        let share =
            Share::from_credentials(Some(dir.clone().into()), "vault-unseal-share").unwrap();
        assert_eq!(share.0, "abc123==");
        assert_eq!(format!("{share:?}"), "Share(<redacted>)");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_missing_or_empty_share() {
        assert!(Share::from_credentials(None, "vault-unseal-share").is_err());
        assert!(Share::from_credentials(Some(OsString::new()), "vault-unseal-share").is_err());
        let missing = dir_with(None);
        assert!(
            Share::from_credentials(Some(missing.clone().into()), "vault-unseal-share").is_err()
        );
        let empty = dir_with(Some(b" \n\t"));
        let err =
            Share::from_credentials(Some(empty.clone().into()), "vault-unseal-share").unwrap_err();
        assert!(err.ends_with("empty"));
        std::fs::remove_dir_all(missing).unwrap();
        std::fs::remove_dir_all(empty).unwrap();
    }

    #[test]
    fn describes_states() {
        let parse = |s: &str| serde_json::from_str::<SealStatus>(s).unwrap().describe();
        assert_eq!(
            parse(r#"{"initialized":true,"sealed":true,"progress":1,"t":3}"#),
            "sealed progress=1/3"
        );
        assert_eq!(
            parse(r#"{"initialized":true,"sealed":false,"t":3}"#),
            "unsealed"
        );
        assert_eq!(
            parse(r#"{"initialized":false,"sealed":true}"#),
            "not initialized"
        );
        assert_eq!(
            parse(r#"{"sealed":true,"progress":2,"t":3,"n":8}"#),
            "sealed progress=2/3"
        );
    }

    #[test]
    fn builds_client_with_sni_name() {
        let tls = tls_config(None).unwrap();
        let endpoint = Endpoint {
            name: "vault-0.xqx.uk".into(),
            addr: "10.1.10.206:8200".parse().unwrap(),
        };
        let (_, base) = client_for(&endpoint, &tls).unwrap();
        assert_eq!(base.as_str(), "https://vault-0.xqx.uk:8200/");
    }

    #[test]
    fn rejects_bad_extra_ca_file() {
        let dir = dir_with(Some(b"not a pem"));
        assert!(tls_config(Some(&dir.join("vault-unseal-share"))).is_err());
        assert!(tls_config(Some(&dir.join("absent"))).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
