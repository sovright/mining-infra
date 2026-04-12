use serde::Deserialize;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    pub timeouts: TimeoutsConfig,
    pub metrics: MetricsConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone)]
pub struct TimeoutsConfig {
    pub upstream_connect: Duration,
    pub upstream_reconnect_max: Duration,
    pub miner_idle: Duration,
}

#[derive(Debug, Clone)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug)]
pub struct ConfigError(String);

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    #[serde(default)]
    proxy: FileProxyConfig,
    #[serde(default)]
    metrics: FileMetricsConfig,
    #[serde(default)]
    logging: FileLoggingConfig,
}

#[derive(Debug, Default, Deserialize)]
struct FileProxyConfig {
    listen: Option<String>,
    upstream: Option<String>,
    #[serde(default)]
    timeouts: FileTimeoutsConfig,
}

#[derive(Debug, Default, Deserialize)]
struct FileTimeoutsConfig {
    upstream_connect: Option<u64>,
    upstream_reconnect_max: Option<u64>,
    miner_idle: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct FileMetricsConfig {
    enabled: Option<bool>,
    listen: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct FileLoggingConfig {
    level: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:3334".parse().expect("default listen address is valid"),
            upstream: "127.0.0.1:3333"
                .parse()
                .expect("default upstream address is valid"),
            timeouts: TimeoutsConfig {
                upstream_connect: Duration::from_secs(10),
                upstream_reconnect_max: Duration::from_secs(60),
                miner_idle: Duration::from_secs(600),
            },
            metrics: MetricsConfig {
                enabled: false,
                listen: "0.0.0.0:9334"
                    .parse()
                    .expect("default metrics address is valid"),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
            },
        }
    }
}

impl ProxyConfig {
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|error| {
            ConfigError::new(format!(
                "failed to read config file {}: {}",
                path.display(),
                error
            ))
        })?;
        let file: FileConfig = toml::from_str(&contents).map_err(|error| {
            ConfigError::new(format!(
                "failed to parse config file {}: {}",
                path.display(),
                error
            ))
        })?;

        let mut config = Self::default();
        config.apply_file(file)?;
        Ok(config)
    }

    pub fn apply_overrides(
        &mut self,
        listen: Option<SocketAddr>,
        upstream: Option<SocketAddr>,
        upstream_connect_secs: Option<u64>,
        upstream_reconnect_max_secs: Option<u64>,
        miner_idle_secs: Option<u64>,
        metrics_enabled: Option<bool>,
        metrics_listen: Option<SocketAddr>,
        log_level: Option<String>,
    ) {
        if let Some(listen) = listen {
            self.listen = listen;
        }
        if let Some(upstream) = upstream {
            self.upstream = upstream;
        }
        if let Some(secs) = upstream_connect_secs {
            self.timeouts.upstream_connect = Duration::from_secs(secs);
        }
        if let Some(secs) = upstream_reconnect_max_secs {
            self.timeouts.upstream_reconnect_max = Duration::from_secs(secs);
        }
        if let Some(secs) = miner_idle_secs {
            self.timeouts.miner_idle = Duration::from_secs(secs);
        }
        if let Some(enabled) = metrics_enabled {
            self.metrics.enabled = enabled;
        }
        if let Some(metrics_listen) = metrics_listen {
            self.metrics.listen = metrics_listen;
        }
        if let Some(level) = log_level {
            self.logging.level = level;
        }
    }

    fn apply_file(&mut self, file: FileConfig) -> Result<(), ConfigError> {
        if let Some(listen) = file.proxy.listen {
            self.listen = parse_socket_addr("proxy.listen", &listen)?;
        }
        if let Some(upstream) = file.proxy.upstream {
            self.upstream = parse_socket_addr("proxy.upstream", &upstream)?;
        }
        if let Some(seconds) = file.proxy.timeouts.upstream_connect {
            self.timeouts.upstream_connect = Duration::from_secs(seconds);
        }
        if let Some(seconds) = file.proxy.timeouts.upstream_reconnect_max {
            self.timeouts.upstream_reconnect_max = Duration::from_secs(seconds);
        }
        if let Some(seconds) = file.proxy.timeouts.miner_idle {
            self.timeouts.miner_idle = Duration::from_secs(seconds);
        }
        if let Some(enabled) = file.metrics.enabled {
            self.metrics.enabled = enabled;
        }
        if let Some(listen) = file.metrics.listen {
            self.metrics.listen = parse_socket_addr("metrics.listen", &listen)?;
        }
        if let Some(level) = file.logging.level {
            self.logging.level = level;
        }

        Ok(())
    }
}

fn parse_socket_addr(field_name: &str, value: &str) -> Result<SocketAddr, ConfigError> {
    value
        .parse()
        .map_err(|error| ConfigError::new(format!("invalid {} value '{}': {}", field_name, value, error)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_spec() {
        let config = ProxyConfig::default();
        assert_eq!(config.listen, "0.0.0.0:3334".parse().unwrap());
        assert_eq!(config.upstream, "127.0.0.1:3333".parse().unwrap());
        assert_eq!(config.timeouts.upstream_connect, Duration::from_secs(10));
        assert_eq!(config.timeouts.upstream_reconnect_max, Duration::from_secs(60));
        assert_eq!(config.timeouts.miner_idle, Duration::from_secs(600));
        assert!(!config.metrics.enabled);
    }

    #[test]
    fn parse_toml_config() {
        let config: FileConfig = toml::from_str(
            r#"
                [proxy]
                listen = "127.0.0.1:4444"
                upstream = "127.0.0.1:5555"

                [proxy.timeouts]
                upstream_connect = 5
                upstream_reconnect_max = 30
                miner_idle = 120

                [metrics]
                enabled = true
                listen = "127.0.0.1:9000"

                [logging]
                level = "debug"
            "#,
        )
        .unwrap();

        let mut merged = ProxyConfig::default();
        merged.apply_file(config).unwrap();

        assert_eq!(merged.listen, "127.0.0.1:4444".parse().unwrap());
        assert_eq!(merged.upstream, "127.0.0.1:5555".parse().unwrap());
        assert_eq!(merged.timeouts.upstream_connect, Duration::from_secs(5));
        assert_eq!(merged.timeouts.upstream_reconnect_max, Duration::from_secs(30));
        assert_eq!(merged.timeouts.miner_idle, Duration::from_secs(120));
        assert!(merged.metrics.enabled);
        assert_eq!(merged.metrics.listen, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(merged.logging.level, "debug");
    }
}
