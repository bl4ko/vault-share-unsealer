use serde::Deserialize;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    pub extra_ca_file: Option<PathBuf>,
    #[serde(rename = "endpoint", default)]
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub name: String,
    pub addr: SocketAddr,
}

const MAX_INTERVAL_SECS: u64 = 3600;

fn default_interval() -> u64 {
    10
}

fn is_dns_name(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    name.len() <= 253
        && labels.len() >= 2
        && !labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit())
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let config: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        if !(1..=MAX_INTERVAL_SECS).contains(&config.interval_secs) {
            return Err(format!("interval_secs must be 1..={MAX_INTERVAL_SECS}"));
        }
        if config.endpoints.is_empty() {
            return Err("at least one [[endpoint]] is required".into());
        }
        let mut names = HashSet::new();
        for endpoint in &config.endpoints {
            if !is_dns_name(&endpoint.name) {
                return Err(format!(
                    "endpoint name {:?} must be a lowercase DNS name",
                    endpoint.name
                ));
            }
            if !names.insert(endpoint.name.as_str()) {
                return Err(format!("duplicate endpoint name {}", endpoint.name));
            }
        }
        Ok(config)
    }

    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spec_example() {
        let config = Config::parse(
            r#"
interval_secs = 10
[[endpoint]]
name = "vault-0.xqx.uk"
addr = "10.1.10.205:8200"
[[endpoint]]
name = "vault-1.xqx.uk"
addr = "10.1.10.206:8200"
"#,
        )
        .unwrap();
        assert_eq!(config.interval(), Duration::from_secs(10));
        assert_eq!(config.endpoints.len(), 2);
        assert_eq!(
            config.endpoints[1].addr,
            "10.1.10.206:8200".parse().unwrap()
        );
        assert!(config.extra_ca_file.is_none());
    }

    #[test]
    fn interval_defaults_to_ten() {
        let config =
            Config::parse("[[endpoint]]\nname = \"a.example\"\naddr = \"127.0.0.1:8200\"\n")
                .unwrap();
        assert_eq!(config.interval_secs, 10);
    }

    #[test]
    fn rejects_invalid_configs() {
        for text in [
            "interval_secs = 10\n",
            "interval_secs = 0\n[[endpoint]]\nname = \"a.example\"\naddr = \"127.0.0.1:8200\"\n",
            "[[endpoint]]\nname = \"a.example\"\naddr = \"127.0.0.1\"\n",
            "[[endpoint]]\nname = \"10.0.0.1\"\naddr = \"10.0.0.1:8200\"\n",
            "[[endpoint]]\nname = \"a.example\"\naddr = \"127.0.0.1:8200\"\n[[endpoint]]\nname = \"A.example\"\naddr = \"127.0.0.2:8200\"\n",
            "unknown = 1\n[[endpoint]]\nname = \"a.example\"\naddr = \"127.0.0.1:8200\"\n",
            "interval_secs = 18446744073709551615\n[[endpoint]]\nname = \"a.example\"\naddr = \"127.0.0.1:8200\"\n",
        ] {
            assert!(Config::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn rejects_names_that_change_in_a_url() {
        for name in [
            "",
            "Vault-0.xqx.uk",
            "evil.example/x",
            "user@vault-0.xqx.uk",
            "vault-0.xqx.uk:443",
            "vault-0.xqx.uk.",
            "localhost",
            "1.2.3",
            "0x7f.1",
            "-a.example",
            "a_b.example",
            "xn--bcher-kva.example\u{e9}",
        ] {
            let text = format!("[[endpoint]]\nname = {name:?}\naddr = \"127.0.0.1:8200\"\n");
            assert!(Config::parse(&text).is_err(), "{name}");
        }
    }
}
