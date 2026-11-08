use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use hickory_proto::rr::{Name, RecordType};
use serde::Deserialize;

use crate::store::{RecordData, RecordTarget, ResolvedRecord};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proto(pub Option<u8>);

impl Proto {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.eq_ignore_ascii_case("any") {
            return Ok(Self(None));
        }
        let known = match value.to_ascii_lowercase().as_str() {
            "unspec" => Some(0),
            "redirect" => Some(1),
            "kernel" => Some(2),
            "boot" => Some(3),
            "static" => Some(4),
            "gated" => Some(8),
            "ra" => Some(9),
            "mrt" => Some(10),
            "zebra" => Some(11),
            "bird" => Some(12),
            "dnrouted" => Some(13),
            "xorp" => Some(14),
            "ntk" => Some(15),
            "dhcp" => Some(16),
            "mrouted" => Some(17),
            "keepalived" => Some(18),
            "babel" => Some(42),
            "bgp" => Some(186),
            "isis" => Some(187),
            "ospf" => Some(188),
            "rip" => Some(189),
            "eigrp" => Some(192),
            _ => None,
        };
        if let Some(proto) = known {
            return Ok(Self(Some(proto)));
        }
        let proto = value.parse::<u8>().context("invalid proto")?;
        Ok(Self(Some(proto)))
    }
}

impl<'de> Deserialize<'de> for Proto {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Proto;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a protocol name like bird or a number 0..=255")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Proto, E> {
                Proto::parse(value).map_err(E::custom)
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Proto, E> {
                if value > u8::MAX as u64 {
                    return Err(E::custom("proto must fit in u8"));
                }
                Ok(Proto(Some(value as u8)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn de_duration<'de, D>(deserializer: D) -> std::result::Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    humantime::parse_duration(&value).map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub id: Option<u64>,
    pub zone: String,
    #[serde(default = "default_dns_listen")]
    pub dns_listen: Vec<SocketAddr>,
    #[serde(default = "default_port")]
    pub port: u16,
    pub secret: Option<String>,
    pub secret_file: Option<PathBuf>,
    #[serde(default)]
    pub seeds: Vec<SocketAddr>,
    #[serde(default = "default_proto")]
    pub proto: Proto,
    #[serde(default = "default_ttl")]
    pub default_ttl: u32,
    #[serde(default = "default_negative_ttl")]
    pub negative_ttl: u32,
    #[serde(default = "default_announce", deserialize_with = "de_duration")]
    pub announce_interval: Duration,
    #[serde(default = "default_origin_timeout", deserialize_with = "de_duration")]
    pub origin_timeout: Duration,
    #[serde(default = "default_tombstone_ttl", deserialize_with = "de_duration")]
    pub tombstone_ttl: Duration,
    #[serde(default)]
    pub records: Vec<RecordSpec>,
}

fn default_dns_listen() -> Vec<SocketAddr> {
    vec!["127.0.0.1:15353".parse().unwrap()]
}
fn default_port() -> u16 {
    7654
}
fn default_proto() -> Proto {
    Proto(Some(12))
}
fn default_ttl() -> u32 {
    60
}
fn default_negative_ttl() -> u32 {
    30
}
fn default_announce() -> Duration {
    Duration::from_secs(30)
}
fn default_origin_timeout() -> Duration {
    Duration::from_secs(90)
}
fn default_tombstone_ttl() -> Duration {
    Duration::from_secs(3600)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub value: Option<String>,
    pub from_interface: Option<String>,
    pub ttl: Option<u32>,
    #[serde(default = "default_priority")]
    pub priority: u16,
    #[serde(default = "default_publish")]
    pub publish: bool,
}

fn default_priority() -> u16 {
    100
}
fn default_publish() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dropin {
    #[serde(default)]
    records: Vec<RecordSpec>,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub raw: Config,
    pub zone: Name,
    pub secret: Vec<u8>,
    pub records: Vec<ResolvedRecord>,
    pub node_id: u64,
}

impl LoadedConfig {
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    pub fn load(config_path: &Path, config_dir: &Path) -> Result<Self> {
        let text = fs::read_to_string(config_path)
            .with_context(|| format!("reading {}", config_path.display()))?;
        let mut raw: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", config_path.display()))?;

        let mut specs = std::mem::take(&mut raw.records);
        if config_dir.exists() {
            let mut paths = fs::read_dir(config_dir)
                .with_context(|| format!("reading {}", config_dir.display()))?
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension().is_some_and(|ext| ext == "toml")
                        && path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| !name.starts_with('.'))
                })
                .collect::<Vec<_>>();
            paths.sort();
            for path in paths {
                let text = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                let dropin: Dropin =
                    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
                specs.extend(dropin.records);
            }
        }

        let zone = normalize_zone(&raw.zone)?;
        let secret = resolve_secret(&raw)?;
        let records = resolve_records(&zone, &specs)?;
        validate_records(&records)?;
        Ok(Self {
            node_id: raw.id.unwrap_or_else(rand::random),
            raw,
            zone,
            secret,
            records,
        })
    }

    pub fn dns_listen(&self) -> &[SocketAddr] {
        &self.raw.dns_listen
    }
}

fn resolve_secret(raw: &Config) -> Result<Vec<u8>> {
    let secret = match (&raw.secret, &raw.secret_file) {
        (Some(secret), None) => secret.as_bytes().to_vec(),
        (None, Some(path)) => fs::read(path)
            .with_context(|| format!("reading secret file {}", path.display()))?
            .into_iter()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect(),
        (Some(_), Some(_)) => bail!("secret and secret_file are mutually exclusive"),
        (None, None) => bail!("secret or secret_file is required"),
    };
    if secret.is_empty() {
        bail!("secret must not be empty");
    }
    Ok(secret)
}

pub fn normalize_zone(input: &str) -> Result<Name> {
    let input = input.trim();
    if input.is_empty() {
        bail!("zone is required");
    }
    let value = if input.ends_with('.') {
        input.to_owned()
    } else {
        format!("{input}.")
    };
    let name = Name::from_str(&value).with_context(|| format!("invalid zone {input:?}"))?;
    if !name.is_fqdn() {
        bail!("zone must be fully qualified");
    }
    Ok(name.to_lowercase())
}

pub fn normalize_name(input: &str, zone: &Name) -> Result<Name> {
    let input = input.trim();
    if input.is_empty() {
        bail!("record name is required");
    }
    let value = if input.ends_with('.') {
        input.to_owned()
    } else if input.contains('.') {
        format!("{input}.")
    } else {
        format!("{input}.{zone}")
    };
    let mut name = Name::from_str(&value).with_context(|| format!("invalid name {input:?}"))?;
    name.set_fqdn(true);
    let name = name.to_lowercase();
    if !zone.zone_of(&name) {
        bail!("name {name} is outside zone {zone}");
    }
    Ok(name)
}

fn parse_type(input: &str) -> Result<RecordType> {
    match input.trim().to_ascii_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "CNAME" => Ok(RecordType::CNAME),
        "TXT" => Ok(RecordType::TXT),
        other => bail!("unsupported record type {other}"),
    }
}

fn parse_value(rtype: RecordType, value: &str) -> Result<RecordData> {
    let value = value.trim();
    match rtype {
        RecordType::A => Ok(RecordData::A(
            value
                .parse()
                .with_context(|| format!("invalid IPv4 {value:?}"))?,
        )),
        RecordType::AAAA => Ok(RecordData::Aaaa(
            value
                .parse()
                .with_context(|| format!("invalid IPv6 {value:?}"))?,
        )),
        RecordType::CNAME => Ok(RecordData::Cname(
            Name::from_str(value)
                .with_context(|| format!("invalid CNAME target {value:?}"))?
                .to_lowercase(),
        )),
        RecordType::TXT => {
            if value.len() > 1024 {
                bail!("TXT value is too long");
            }
            Ok(RecordData::Txt(value.to_owned()))
        }
        _ => bail!("unsupported record type {rtype}"),
    }
}

fn resolve_records(zone: &Name, specs: &[RecordSpec]) -> Result<Vec<ResolvedRecord>> {
    let mut records = Vec::with_capacity(specs.len());
    for spec in specs {
        let name = normalize_name(&spec.name, zone)?;
        let rtype = parse_type(&spec.rtype)?;
        let target = match (&spec.value, &spec.from_interface) {
            (Some(_), Some(_)) => {
                bail!("record {} sets both value and from_interface", spec.name)
            }
            (None, None) => bail!("record {} needs value or from_interface", spec.name),
            (Some(value), None) => RecordTarget::Value(parse_value(rtype, value)?),
            (None, Some(interface)) => {
                if !matches!(rtype, RecordType::A | RecordType::AAAA) {
                    bail!(
                        "record {} uses from_interface with unsupported type {rtype}",
                        spec.name
                    );
                }
                RecordTarget::Interface(interface.clone())
            }
        };
        records.push(ResolvedRecord {
            name,
            rtype,
            target,
            ttl: spec.ttl,
            priority: spec.priority,
            publish: spec.publish,
        });
    }
    Ok(records)
}

fn validate_records(records: &[ResolvedRecord]) -> Result<()> {
    use std::collections::HashMap;
    let mut by_name: HashMap<&Name, (bool, u16)> = HashMap::new();
    let mut cname = HashMap::new();
    for record in records {
        let entry = by_name
            .entry(&record.name)
            .or_insert((record.publish, record.priority));
        if entry.0 != record.publish {
            bail!(
                "records for {} disagree on publish; use one value per name",
                record.name
            );
        }
        if entry.1 != record.priority {
            bail!(
                "records for {} disagree on priority; use one value per name",
                record.name
            );
        }
        if record.rtype == RecordType::CNAME {
            cname.insert(record.name.clone(), ());
        }
    }
    for record in records {
        if cname.contains_key(&record.name) && record.rtype != RecordType::CNAME {
            bail!("record {} mixes CNAME with other record types", record.name);
        }
    }
    Ok(())
}

pub fn socket_addr_to_ip(addr: &SocketAddr) -> IpAddr {
    addr.ip()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, text: &str) {
        fs::write(dir.join(name), text).unwrap();
    }

    #[test]
    fn loads_main_and_dropins() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("namae.toml");
        write(
            dir.path(),
            "namae.toml",
            r#"
zone = "example."
secret = "test"
dns_listen = ["127.0.0.1:15353"]
[[records]]
name = "a"
type = "A"
value = "10.0.0.1"
"#,
        );
        let dropin = dir.path().join("namae.d");
        fs::create_dir(&dropin).unwrap();
        write(
            &dropin,
            "b.toml",
            r#"
[[records]]
name = "b.example."
type = "AAAA"
value = "fd00::1"
"#,
        );
        let loaded = LoadedConfig::load(&main, &dropin).unwrap();
        assert_eq!(loaded.records.len(), 2);
        assert_eq!(loaded.zone.to_string(), "example.");
        assert_eq!(loaded.records[0].name.to_string(), "a.example.");
    }

    #[test]
    fn dropin_rejects_top_level() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("namae.toml");
        write(
            dir.path(),
            "namae.toml",
            "zone = \"example.\"\nsecret = \"test\"\n",
        );
        let dropin = dir.path().join("namae.d");
        fs::create_dir(&dropin).unwrap();
        write(&dropin, "bad.toml", "zone = \"other.\"\n");
        assert!(LoadedConfig::load(&main, &dropin).is_err());
    }

    #[test]
    fn proto_parses() {
        assert_eq!(Proto::parse("bird").unwrap().0, Some(12));
        assert_eq!(Proto::parse("any").unwrap().0, None);
        assert_eq!(Proto::parse("12").unwrap().0, Some(12));
    }

    #[test]
    fn zone_and_secret_are_required() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("namae.toml");
        write(dir.path(), "namae.toml", "secret = \"test\"\n");
        assert!(LoadedConfig::load(&main, &dir.path().join("d")).is_err());
        write(dir.path(), "namae.toml", "zone = \"namae.\"\n");
        assert!(LoadedConfig::load(&main, &dir.path().join("d")).is_err());
        write(
            dir.path(),
            "namae.toml",
            "zone = \"namae.\"\nsecret = \"a\"\nsecret_file = \"b\"\n",
        );
        assert!(LoadedConfig::load(&main, &dir.path().join("d")).is_err());
    }
}
