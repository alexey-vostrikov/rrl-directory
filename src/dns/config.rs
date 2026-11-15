//! The `dns:` section: whether to serve the domain's zone, and where to send the rest.
//!
//! Two decisions and no more, because everything else follows from what the server already knows:
//! the zone's name comes from the naming context, and the records in it are derived from the realm,
//! the host name and the listeners that are running. A configuration that repeated any of that would
//! be a second place for it to be wrong.
//!
//! Off unless an operator turns it on, for the reason `cldap` and `smb` are off: answering on 53
//! says "this address resolves the domain", and a server that says so and answers nothing is worse
//! than one that never claimed it - the client has no field in which to say which resolver lied.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

/// The `dns:` section as it is written.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    /// Whether to serve the zone on port 53 at all.
    pub enabled: bool,
    /// The port to listen on, UDP and TCP.
    ///
    /// 53 by default, the only port a resolver asks. A different value exists for one honest reason:
    /// only root may bind below 1024, and a test or a developer without that right still has to be
    /// able to check the exchange end to end.
    pub port: Option<u16>,
    /// Where a name outside this server's own zones is sent.
    ///
    /// Absent means it is not sent anywhere, which is what a domain controller that only answers for
    /// its own domain does: `REFUSED`, and the client asks its own resolver for the rest.
    pub forward: ForwardConfig,
    /// The address the zone publishes for this controller.
    ///
    /// The `A` of `dns_host` and the target every `SRV` names. Absent means the address the LDAP
    /// listener took, which is what a real deployment needs - the controller's own address. It is
    /// writable separately for one honest reason: a stand where the server listens on the loopback
    /// and the client reaches it through an alias has an address the server cannot discover, and a
    /// zone that published `127.0.0.1` would send every client to itself.
    pub address: Option<std::net::Ipv4Addr>,
    /// Where the zone is kept between runs.
    ///
    /// `/dns` by default: a directory of zone files, one per zone, so an operator can read the
    /// records without a directory client and a rebuild does not silently invent a different zone.
    pub zones_dir: Option<PathBuf>,
}

/// Conditional forwarding, in the shape AD calls it: different suffixes to different servers.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForwardConfig {
    /// Servers for everything no `zones` entry covers.
    pub default: Vec<SocketAddr>,
    /// Servers for one suffix, matched on label boundaries.
    ///
    /// `corp.example.com` does not cover `notcorp.example.com`: a suffix is compared label by label,
    /// and a server that compared strings would forward a domain it does not own to somebody else's
    /// resolver.
    pub zones: BTreeMap<String, Vec<SocketAddr>>,
}

/// The resolved section: what a listener and a forwarder need, with every disagreement refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Where to listen, both transports.
    pub bind: SocketAddr,
    /// The domain's own DNS name, `ad.example.com`.
    pub dns_domain: String,
    /// The address this controller's records publish.
    pub address: std::net::Ipv4Addr,
    /// The servers for everything outside the zone, already validated.
    pub forward_default: Vec<SocketAddr>,
    /// The suffix table, lower-cased and stripped of trailing dots.
    pub forward_zones: BTreeMap<String, Vec<SocketAddr>>,
    /// Where the zone is written.
    pub zones_dir: PathBuf,
}

impl Settings {
    /// Resolves the section against the naming context and the address the LDAP listener took.
    ///
    /// Every refusal is a startup error rather than a fallback: a forwarder whose address does not
    /// parse would otherwise be discovered by the first client that asked for a name outside the
    /// zone, and the answer it would get is `SERVFAIL` - which is indistinguishable from a network
    /// fault.
    pub fn resolve(
        config: &DnsConfig,
        base_dn: &str,
        bind_ip: std::net::IpAddr,
    ) -> Result<Settings, String> {
        let dns_domain = domain_of_base(base_dn).ok_or_else(|| {
            format!("the naming context '{base_dn}' has no dc= components to make a DNS name from")
        })?;
        let port = config.port.unwrap_or(53);
        if port == 0 {
            return Err(
                "dns.port is 0: a listener cannot take a port the kernel chooses".to_string(),
            );
        }

        let mut forward_zones = BTreeMap::new();
        for (suffix, servers) in &config.forward.zones {
            let suffix = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
            if suffix.is_empty() {
                return Err("dns.forward.zones has an empty suffix".to_string());
            }
            if !is_domain_name(&suffix) {
                return Err(format!(
                    "dns.forward.zones names '{suffix}', which is not a domain name: a suffix is \
                     labels separated by dots, each 1 to 63 characters"
                ));
            }
            if servers.is_empty() {
                return Err(format!(
                    "dns.forward.zones.{suffix} names no server: an entry that forwards nowhere is \
                     a suffix that will never resolve"
                ));
            }
            if forward_zones
                .insert(suffix.clone(), servers.clone())
                .is_some()
            {
                // Two spellings of one suffix would be two answers, and which one wins would depend
                // on the order of a map.
                return Err(format!(
                    "dns.forward.zones names '{suffix}' twice: one suffix, one set of servers"
                ));
            }
        }
        for address in &config.forward.default {
            if address.port() == 0 {
                return Err(format!(
                    "dns.forward.default has {address}, whose port is 0: a forwarder needs a port"
                ));
            }
        }

        let address = match config.address {
            Some(address) => address,
            None => match bind_ip {
                std::net::IpAddr::V4(address) => address,
                // A zone cannot publish an address it does not have: an `A` is four octets, and a
                // listener on `::` says nothing about the v4 address a client would reach it by.
                std::net::IpAddr::V6(_) => {
                    return Err(format!(
                        "dns: the listener is on {bind_ip}, which is not an IPv4 address: this \
                         build publishes `A` records only, so `dns.address` has to name one"
                    ));
                }
            },
        };

        Ok(Settings {
            bind: SocketAddr::new(bind_ip, port),
            dns_domain,
            address,
            forward_default: config.forward.default.clone(),
            forward_zones,
            zones_dir: config
                .zones_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from("/dns")),
        })
    }

    /// The servers a name outside this zone should be sent to, if any.
    ///
    /// The **longest** suffix wins, and the comparison is on label boundaries: `a.corp.example.com`
    /// matches `corp.example.com` and `example.com`, and the more specific server is the one that
    /// knows more about it. `notcorp.example.com` matches neither, because the label `notcorp` is not
    /// `corp`.
    pub fn forwarder_for(&self, name: &str) -> Option<&[SocketAddr]> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let mut best: Option<(usize, &[SocketAddr])> = None;
        for (suffix, servers) in &self.forward_zones {
            if !is_under(&name, suffix) {
                continue;
            }
            // Longest by character count is longest by labels here: a suffix that matches is always
            // a whole-label comparison, so a longer string is a deeper suffix.
            if best.is_none_or(|(length, _)| suffix.len() > length) {
                best = Some((suffix.len(), servers));
            }
        }
        match best {
            Some((_, servers)) => Some(servers),
            None if !self.forward_default.is_empty() => Some(&self.forward_default),
            None => None,
        }
    }
}

/// Whether `name` is `suffix` or below it, compared label by label.
fn is_under(name: &str, suffix: &str) -> bool {
    if name == suffix {
        return true;
    }
    match name.strip_suffix(suffix) {
        // The octet before the suffix has to be the dot that separates the labels: `notcorp.example.com`
        // ends with `corp.example.com` as a string and not as a name.
        Some(head) => head.ends_with('.'),
        None => false,
    }
}

/// Whether `text` is a domain name: labels of 1 to 63 octets separated by dots.
fn is_domain_name(text: &str) -> bool {
    if text.is_empty() || text.len() > 253 {
        return false;
    }
    text.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|octet| octet.is_ascii_alphanumeric() || octet == b'-' || octet == b'_')
    })
}

/// `dc=ad,dc=example,dc=com` is `ad.example.com`.
///
/// The reader `cldap` and `kerberos` use, repeated here rather than shared: each of the three
/// derives a name from the same input, and a shared helper would have to live in a module none of
/// them owns. Three lines of `dc=` parsing that disagree is what a test catches; a module boundary
/// does not.
fn domain_of_base(base_dn: &str) -> Option<String> {
    let mut labels = Vec::new();
    for rdn in base_dn.split(',') {
        let (kind, value) = rdn.split_once('=')?;
        if !kind.trim().eq_ignore_ascii_case("dc") {
            break;
        }
        labels.push(value.trim().to_ascii_lowercase());
    }
    if labels.len() < 2 {
        return None;
    }
    Some(labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "dc=ad,dc=example,dc=com";

    fn config() -> DnsConfig {
        DnsConfig {
            enabled: true,
            ..DnsConfig::default()
        }
    }

    fn ip(text: &str) -> SocketAddr {
        text.parse().expect("a literal address")
    }

    /// The acceptance: a section with no disagreements resolves to what a listener needs.
    #[test]
    fn a_plain_section_resolves_to_the_domains_own_name() {
        let settings =
            Settings::resolve(&config(), BASE, "127.0.0.1".parse().expect("ip")).expect("resolves");
        assert_eq!(settings.dns_domain, "ad.example.com");
        assert_eq!(settings.bind, ip("127.0.0.1:53"));
        assert_eq!(settings.zones_dir, PathBuf::from("/dns"));
        assert!(settings.forward_default.is_empty());
        assert!(settings.forward_zones.is_empty());
    }

    /// The realm and the zone are one name: a name derived from the naming context cannot disagree
    /// with it, which is why there is no field to write a different one in.
    #[test]
    fn a_naming_context_without_dc_components_is_refused() {
        assert!(Settings::resolve(&config(), "o=acme", "127.0.0.1".parse().expect("ip")).is_err());
        assert!(Settings::resolve(&config(), "dc=com", "127.0.0.1".parse().expect("ip")).is_err());
    }

    /// Two suffixes, one of them a parent of the other: the longest wins, and the comparison is on
    /// labels, so `notcorp.example.com` is not under `corp.example.com`.
    #[test]
    fn the_longest_suffix_wins_and_labels_are_compared_whole() {
        let mut config = config();
        config.forward.default = vec![ip("192.0.2.53:53")];
        config
            .forward
            .zones
            .insert("example.com.".to_string(), vec![ip("192.0.2.1:53")]);
        config
            .forward
            .zones
            .insert("corp.example.com".to_string(), vec![ip("192.0.2.2:53")]);

        let settings =
            Settings::resolve(&config, BASE, "127.0.0.1".parse().expect("ip")).expect("resolves");
        assert_eq!(
            settings.forwarder_for("a.corp.example.com."),
            Some(&[ip("192.0.2.2:53")][..]),
            "the deeper suffix knows more"
        );
        assert_eq!(
            settings.forwarder_for("www.example.com."),
            Some(&[ip("192.0.2.1:53")][..]),
            "the parent covers the rest of its own domain"
        );
        assert_eq!(
            settings.forwarder_for("elsewhere.test."),
            Some(&[ip("192.0.2.53:53")][..]),
            "and the default covers everything else"
        );
        assert!(
            settings.forwarder_for("notcorp.example.com.").is_some(),
            "this name IS under example.com"
        );
        // The boundary the string comparison would get wrong: a zone of `corp.example.com` alone
        // must not claim `notcorp.example.com`.
        let only_corp = Settings::resolve(
            &DnsConfig {
                enabled: true,
                forward: ForwardConfig {
                    default: Vec::new(),
                    zones: BTreeMap::from([(
                        "corp.example.com".to_string(),
                        vec![ip("192.0.2.2:53")],
                    )]),
                },
                ..DnsConfig::default()
            },
            BASE,
            "127.0.0.1".parse().expect("ip"),
        )
        .expect("resolves");
        assert_eq!(only_corp.forwarder_for("notcorp.example.com."), None);
        assert!(
            only_corp.forwarder_for("a.corp.example.com.").is_some(),
            "and its own suffix does match"
        );
    }

    /// A suffix that is not a name, an empty suffix, one with no servers, and a port of zero: each
    /// is refused at start, because each would otherwise be discovered by a client.
    #[test]
    fn a_forwarder_that_cannot_be_honoured_is_refused_at_start() {
        let mut bad = config();
        bad.forward
            .zones
            .insert("a..b".to_string(), vec![ip("192.0.2.1:53")]);
        assert!(Settings::resolve(&bad, BASE, "127.0.0.1".parse().expect("ip")).is_err());

        let mut empty = config();
        empty
            .forward
            .zones
            .insert("corp.test".to_string(), Vec::new());
        assert!(Settings::resolve(&empty, BASE, "127.0.0.1".parse().expect("ip")).is_err());

        let mut no_port = config();
        no_port.forward.default = vec![ip("192.0.2.1:0")];
        assert!(Settings::resolve(&no_port, BASE, "127.0.0.1".parse().expect("ip")).is_err());

        // A suffix written with a trailing dot is the same suffix without it, and spelling one twice
        // is a refusal rather than a silent overwrite.
        let mut twice = config();
        twice
            .forward
            .zones
            .insert("corp.test".to_string(), vec![ip("192.0.2.1:53")]);
        let resolved =
            Settings::resolve(&twice, BASE, "127.0.0.1".parse().expect("ip")).expect("resolves");
        assert!(resolved.forward_zones.contains_key("corp.test"));
    }

    /// A port of zero on the listener is refused for the same reason.
    #[test]
    fn a_port_of_zero_is_refused() {
        let mut config = config();
        config.port = Some(0);
        assert!(Settings::resolve(&config, BASE, "127.0.0.1".parse().expect("ip")).is_err());
    }
}
