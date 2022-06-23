pub mod dynamic;
mod peer;

pub use peer::*;

use clap::Parser;
use ntp_proto::SystemConfig;
use serde::{de, Deserialize, Deserializer};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};
use thiserror::Error;
use tokio::{fs::read_to_string, io};
use tracing::info;
use tracing_subscriber::filter::{self, EnvFilter};

fn parse_env_filter(input: &str) -> Result<EnvFilter, filter::ParseError> {
    EnvFilter::builder().with_regex(false).parse(input)
}

fn deserialize_option_env_filter<'de, D>(deserializer: D) -> Result<Option<EnvFilter>, D::Error>
where
    D: Deserializer<'de>,
{
    let data: Option<&str> = Deserialize::deserialize(deserializer)?;
    if let Some(dirs) = data {
        // allow us to recognise configs with an empty log filter directive
        if dirs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(EnvFilter::try_new(dirs).map_err(de::Error::custom)?))
        }
    } else {
        Ok(None)
    }
}

#[derive(Parser, Debug)]
pub struct CmdArgs {
    #[clap(
        short,
        long = "peer",
        global = true,
        value_name = "SERVER",
        parse(try_from_str = TryFrom::try_from)
    )]
    pub peers: Vec<PeerConfig>,

    #[clap(short, long, parse(from_os_str), global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[clap(long, short, global = true, parse(try_from_str = parse_env_filter), env = "NTP_LOG")]
    pub log_filter: Option<EnvFilter>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub system: SystemConfig,
    #[serde(deserialize_with = "deserialize_option_env_filter", default)]
    pub log_filter: Option<EnvFilter>,
    #[cfg(feature = "sentry")]
    #[serde(default)]
    pub sentry: SentryConfig,
    #[serde(default)]
    pub observe: ObserveConfig,
    #[serde(default)]
    pub configure: ConfigureConfig,
}

fn default_observe_path() -> PathBuf {
    PathBuf::from("/run/ntpd-rs/observe")
}

const fn default_observe_permissions() -> u32 {
    0o777
}

#[derive(Clone, Deserialize, Debug)]
pub struct ObserveConfig {
    #[serde(default = "default_observe_path")]
    pub path: PathBuf,
    #[serde(default = "default_observe_permissions")]
    pub mode: u32,
}

fn default_configure_path() -> PathBuf {
    PathBuf::from("/run/ntpd-rs/configure")
}

const fn default_configure_permissions() -> u32 {
    0o770
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self {
            path: default_observe_path(),
            mode: default_observe_permissions(),
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct ConfigureConfig {
    #[serde(default = "default_configure_path")]
    pub path: std::path::PathBuf,
    #[serde(default = "default_configure_permissions")]
    pub mode: u32,
}

impl Default for ConfigureConfig {
    fn default() -> Self {
        Self {
            path: default_configure_path(),
            mode: default_configure_permissions(),
        }
    }
}

#[cfg(feature = "sentry")]
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct SentryConfig {
    pub dsn: Option<String>,
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f32,
}

#[cfg(feature = "sentry")]
fn default_sample_rate() -> f32 {
    0.0
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("io error while reading config: {0}")]
    Io(#[from] io::Error),
    #[error("config toml parsing error: {0}")]
    Toml(#[from] toml::de::Error),
}

impl Config {
    async fn from_file(file: impl AsRef<Path>) -> Result<Config, ConfigError> {
        let contents = read_to_string(file).await?;
        Ok(toml::de::from_str(&contents)?)
    }

    async fn from_first_file(file: Option<impl AsRef<Path>>) -> Result<Config, ConfigError> {
        // if an explicit file is given, always use that one
        if let Some(f) = file {
            return Config::from_file(f).await;
        }

        // try ntp.toml in working directory or skip if file doesn't exist
        match Config::from_file("./ntp.toml").await {
            Err(ConfigError::Io(e)) if e.kind() == ErrorKind::NotFound => {}
            other => return other,
        }

        // for the global file we also ignore it when there are permission errors
        match Config::from_file("/etc/ntp.toml").await {
            Err(ConfigError::Io(e))
                if e.kind() == ErrorKind::NotFound || e.kind() == ErrorKind::PermissionDenied => {}
            other => return other,
        }

        Ok(Config::default())
    }

    pub async fn from_args(
        file: Option<impl AsRef<Path>>,
        peers: Vec<PeerConfig>,
    ) -> Result<Config, ConfigError> {
        let mut config = Config::from_first_file(file).await?;

        if !peers.is_empty() {
            if !config.peers.is_empty() {
                info!("overriding peers from configuration");
            }
            config.peers = peers;
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use std::{env, ffi::OsString};

    use super::*;

    #[test]
    fn test_config() {
        let config: Config = toml::from_str("[[peers]]\naddr = \"example.com\"").unwrap();
        assert_eq!(
            config.peers,
            vec![PeerConfig {
                addr: "example.com:123".into(),
                mode: PeerHostMode::Server
            }]
        );

        let config: Config =
            toml::from_str("log-filter = \"\"\n[[peers]]\naddr = \"example.com\"").unwrap();
        assert!(config.log_filter.is_none());
        assert_eq!(
            config.peers,
            vec![PeerConfig {
                addr: "example.com:123".into(),
                mode: PeerHostMode::Server
            }]
        );

        let config: Config =
            toml::from_str("log-filter = \"info\"\n[[peers]]\naddr = \"example.com\"").unwrap();
        assert!(config.log_filter.is_some());
        assert_eq!(
            config.peers,
            vec![PeerConfig {
                addr: "example.com:123".into(),
                mode: PeerHostMode::Server
            }]
        );

        let config: Config =
            toml::from_str("[[peers]]\naddr = \"example.com\"\n[system]\npanic-threshold = 0")
                .unwrap();
        assert_eq!(
            config.peers,
            vec![PeerConfig {
                addr: "example.com:123".into(),
                mode: PeerHostMode::Server
            }]
        );
        assert!(config.system.panic_threshold.is_none());

        let config: Config = toml::from_str(
            r#"
            log-filter = "info"
            [[peers]]
            addr = "example.com"
            [observe]
            path = "/foo/bar/observe"
            mode = 0o567
            [configure]
            path = "/foo/bar/configure"
            mode = 0o123
            "#,
        )
        .unwrap();
        assert!(config.log_filter.is_some());

        assert_eq!(config.observe.path, PathBuf::from("/foo/bar/observe"));
        assert_eq!(config.observe.mode, 0o567);

        assert_eq!(config.configure.path, PathBuf::from("/foo/bar/configure"));
        assert_eq!(config.configure.mode, 0o123);

        assert_eq!(
            config.peers,
            vec![PeerConfig {
                addr: "example.com:123".into(),
                mode: PeerHostMode::Server
            }]
        );
    }

    #[cfg(feature = "sentry")]
    #[test]
    fn test_sentry_config() {
        let config: Config = toml::from_str("[[peers]]\naddr = \"example.com\"").unwrap();
        assert!(config.sentry.dsn.is_none());

        let config: Config =
            toml::from_str("[[peers]]\naddr = \"example.com\"\n[sentry]\ndsn = \"abc\"").unwrap();
        assert_eq!(config.sentry.dsn, Some("abc".into()));

        let config: Config = toml::from_str(
            "[[peers]]\naddr = \"example.com\"\n[sentry]\ndsn = \"abc\"\nsample-rate = 0.5",
        )
        .unwrap();
        assert_eq!(config.sentry.dsn, Some("abc".into()));
        assert!((config.sentry.sample_rate - 0.5).abs() < 1e-9);
    }

    #[tokio::test]
    async fn test_file_config() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("testdata/config");
        env::set_current_dir(d).unwrap();

        let config = Config::from_args(None as Option<&'static str>, vec![])
            .await
            .unwrap();
        assert_eq!(config.system.min_intersection_survivors, 2);
        assert_eq!(config.peers.len(), 1);

        let config = Config::from_args(Some("other.toml"), vec![]).await.unwrap();
        assert_eq!(config.system.min_intersection_survivors, 3);
        assert_eq!(config.peers.len(), 1);

        let config = Config::from_args(
            None as Option<&'static str>,
            vec![
                PeerConfig::try_from("example1.com").unwrap(),
                PeerConfig::try_from("example2.com").unwrap(),
            ],
        )
        .await
        .unwrap();
        assert_eq!(config.system.min_intersection_survivors, 2);
        assert_eq!(config.peers.len(), 2);

        let config = Config::from_args(
            Some("other.toml"),
            vec![
                PeerConfig::try_from("example1.com").unwrap(),
                PeerConfig::try_from("example2.com").unwrap(),
            ],
        )
        .await
        .unwrap();
        assert_eq!(config.system.min_intersection_survivors, 3);
        assert_eq!(config.peers.len(), 2);
    }

    #[test]
    fn clap_no_arguments() {
        use clap::Parser;

        let arguments: [OsString; 0] = [];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.peers.is_empty());
        assert!(parsed_empty.config.is_none());
        assert!(parsed_empty.log_filter.is_none());
    }

    #[test]
    fn clap_external_config() {
        use clap::Parser;

        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("testdata/config");
        env::set_current_dir(d).unwrap();

        let arguments = &["--", "--config", "other.toml"];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.peers.is_empty());
        assert_eq!(parsed_empty.config, Some("other.toml".into()));
        assert!(parsed_empty.log_filter.is_none());

        let arguments = &["--", "-c", "other.toml"];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.peers.is_empty());
        assert_eq!(parsed_empty.config, Some("other.toml".into()));
        assert!(parsed_empty.log_filter.is_none());
    }

    #[test]
    fn clap_log_filter() {
        use clap::Parser;

        let arguments = &["--", "--log-filter", "debug"];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.peers.is_empty());
        assert!(parsed_empty.config.is_none());
        assert_eq!(parsed_empty.log_filter.unwrap().to_string(), "debug");

        let arguments = &["--", "-l", "debug"];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert!(parsed_empty.peers.is_empty());
        assert!(parsed_empty.config.is_none());
        assert_eq!(parsed_empty.log_filter.unwrap().to_string(), "debug");
    }

    #[test]
    fn clap_peers() {
        use clap::Parser;

        let arguments = &["--", "--peer", "foo.nl"];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert_eq!(
            parsed_empty.peers,
            vec![PeerConfig {
                addr: "foo.nl:123".to_string(),
                mode: PeerHostMode::Server
            }]
        );
        assert!(parsed_empty.config.is_none());
        assert!(parsed_empty.log_filter.is_none());

        let arguments = &["--", "--peer", "foo.rs", "-p", "spam.nl:123"];
        let parsed_empty = CmdArgs::try_parse_from(arguments).unwrap();

        assert_eq!(
            parsed_empty.peers,
            vec![
                PeerConfig {
                    addr: "foo.rs:123".to_string(),
                    mode: PeerHostMode::Server
                },
                PeerConfig {
                    addr: "spam.nl:123".to_string(),
                    mode: PeerHostMode::Server
                },
            ]
        );
        assert!(parsed_empty.config.is_none());
        assert!(parsed_empty.log_filter.is_none());
    }

    #[test]
    fn clap_peers_invalid() {
        let arguments = &["--", "--peer", "foo.bar:123"];
        let parsed = CmdArgs::try_parse_from(arguments).unwrap_err();

        eprintln!("{:#?}", &parsed);

        let error = r#"error: Invalid value "foo.bar:123" for '--peer <SERVER>': failed to lookup address information: Name or service not known"#;

        assert!(parsed.to_string().starts_with(error));
    }

    #[test]
    fn toml_peers_invalid() {
        let config: Result<Config, _> = toml::from_str(
            r#"
            [[peers]]
            addr = "foo.bar:123"
            "#,
        );

        let e = config.unwrap_err();
        let error = r#"failed to lookup address information: Name or service not known"#;

        assert!(e.to_string().starts_with(error));
    }
}
