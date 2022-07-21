use std::{fmt, net::SocketAddr};

use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};

#[derive(Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum PeerHostMode {
    Server,
}

impl Default for PeerHostMode {
    fn default() -> Self {
        PeerHostMode::Server
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PeerConfig {
    // We ensure that this is an address with a host and port part
    // however the host may or may not be valid.
    pub addr: String,
    pub mode: PeerHostMode,
}

fn normalize_addr(mut addr: String) -> std::io::Result<String> {
    if addr.split(':').count() > 2 {
        // IPv6, try to parse it as such
        match addr.parse::<SocketAddr>() {
            Ok(_) => Ok(addr),
            Err(e) => {
                // Could be because of no port, add one and see
                addr = format!("[{addr}]:123");
                if addr.parse::<SocketAddr>().is_ok() {
                    Ok(addr)
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, e))
                }
            }
        }
    } else if let Some((_, port)) = addr.split_once(':') {
        // Not ipv6, and we seem to have a port. We cant reasonably
        // check whether the host is valid, but at least check that
        // the port is.
        match port.parse::<u16>() {
            Ok(_) => Ok(addr),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    } else {
        // Not ipv6 and no port. As we cant reasonably check host
        // so just append a port
        addr.push_str(":123");
        Ok(addr)
    }
}

impl TryFrom<&str> for PeerConfig {
    type Error = std::io::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(PeerConfig {
            addr: normalize_addr(value.into())?,
            mode: PeerHostMode::Server,
        })
    }
}

// We have a custom deserializer for peerconfig because we
// want to deserialize it from either a string or a map
impl<'de> Deserialize<'de> for PeerConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PeerConfigVisitor;

        impl<'de> Visitor<'de> for PeerConfigVisitor {
            type Value = PeerConfig;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("string or map")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<PeerConfig, E> {
                TryFrom::try_from(value).map_err(de::Error::custom)
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<PeerConfig, M::Error> {
                let mut addr = None;
                let mut mode = None;
                while let Some(key) = map.next_key::<&str>()? {
                    match key {
                        "addr" => {
                            if addr.is_some() {
                                return Err(de::Error::duplicate_field("addr"));
                            }
                            let raw: String = map.next_value()?;

                            // validate: this will add the `:123` port if no port is specified
                            let parsed_addr =
                                normalize_addr(raw.as_str().into()).map_err(de::Error::custom)?;

                            addr = Some(parsed_addr);
                        }
                        "mode" => {
                            if mode.is_some() {
                                return Err(de::Error::duplicate_field("mode"));
                            }
                            mode = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(key, &["addr", "mode"]));
                        }
                    }
                }

                let addr = addr.ok_or_else(|| de::Error::missing_field("addr"))?;
                let mode = mode.unwrap_or_default();
                Ok(PeerConfig { addr, mode })
            }
        }

        deserializer.deserialize_any(PeerConfigVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_peer() {
        #[derive(Deserialize, Debug)]
        struct TestConfig {
            peer: PeerConfig,
        }

        let test: TestConfig = toml::from_str("peer = \"example.com\"").unwrap();
        assert_eq!(test.peer.addr, "example.com:123");
        assert_eq!(test.peer.mode, PeerHostMode::Server);

        let test: TestConfig = toml::from_str("peer = \"example.com:5678\"").unwrap();
        assert_eq!(test.peer.addr, "example.com:5678");
        assert_eq!(test.peer.mode, PeerHostMode::Server);

        let test: TestConfig = toml::from_str("[peer]\naddr = \"example.com\"").unwrap();
        assert_eq!(test.peer.addr, "example.com:123");
        assert_eq!(test.peer.mode, PeerHostMode::Server);

        let test: TestConfig = toml::from_str("[peer]\naddr = \"example.com:5678\"").unwrap();
        assert_eq!(test.peer.addr, "example.com:5678");
        assert_eq!(test.peer.mode, PeerHostMode::Server);

        let test: TestConfig =
            toml::from_str("[peer]\naddr = \"example.com\"\nmode = \"Server\"").unwrap();
        assert_eq!(test.peer.addr, "example.com:123");
        assert_eq!(test.peer.mode, PeerHostMode::Server);
    }

    #[test]
    fn test_peer_from_string() {
        let peer = PeerConfig::try_from("example.com").unwrap();
        assert_eq!(peer.addr, "example.com:123");
        assert_eq!(peer.mode, PeerHostMode::Server);

        let peer = PeerConfig::try_from("example.com:5678").unwrap();
        assert_eq!(peer.addr, "example.com:5678");
        assert_eq!(peer.mode, PeerHostMode::Server);
    }

    #[test]
    fn test_normalize_addr() {
        let addr = normalize_addr("[::1]:456".into()).unwrap();
        assert_eq!(addr, "[::1]:456");
        let addr = normalize_addr("::1".into()).unwrap();
        assert_eq!(addr, "[::1]:123");
        assert!(normalize_addr(":some:invalid:1".into()).is_err());
        let addr = normalize_addr("127.0.0.1:456".into()).unwrap();
        assert_eq!(addr, "127.0.0.1:456");
        let addr = normalize_addr("127.0.0.1".into()).unwrap();
        assert_eq!(addr, "127.0.0.1:123");
        let addr = normalize_addr("1234567890.example.com".into()).unwrap();
        assert_eq!(addr, "1234567890.example.com:123");
    }
}
