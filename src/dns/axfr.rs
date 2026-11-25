//! Who may transfer a zone.
//!
//! AXFR was denied to everybody, and the comment justifying it said a transfer would be "a second,
//! unreplicated copy of the same data". That is true and it is not a security argument: a second copy
//! is what a backup is, what a validator checks against, and what a secondary serves while this one
//! restarts. Denying everyone is not a policy, it is the absence of one - and it left the zone
//! impossible to verify with the tools that exist (`ldns-verify-zone`, `dnssec-verify`), which is how
//! this was noticed.
//!
//! So the policy is written down: a list of grants, each naming a source range, a key, or both. Empty
//! list means deny, which is what a server that never configured this gets - the default is unchanged
//! behaviour rather than a new hole.
//!
//! ```yaml
//! dns:
//!   axfr:
//!     allow:
//!       - source: 10.0.0.0/8          # a backup host or a secondary, by address
//!       - key: zone-transfer          # a client that proved it holds this TSIG key
//!       - source: 192.0.2.0/24        # both: only from this range, and only signed
//!         key: zone-transfer
//! ```
//!
//! An entry with neither is refused at start, because it allows nothing and reads as if it did. A
//! `key` naming a key that `dns.keys` does not define is refused at start for the same reason: it is
//! a typo that would otherwise be discovered by a client being told `REFUSED` hours later.
//!
//! **A source-only grant permits an unsigned client.** That is deliberate - it is BIND's
//! `allow-transfer { 10.0.0.0/8; };` and it is what an offline backup needs - and it is why the
//! address, not the signature, is the thing to get right. Where a key is wanted as well, name both.

use std::net::IpAddr;

use hickory_server::proto::rr::Name;

/// One allowlist entry, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Grant {
    /// The addresses this entry covers; `None` means any.
    source: Option<Range>,
    /// The key this entry requires; `None` means any client, signed or not.
    key: Option<Name>,
    /// The entry as it was written, for the log line that says which one matched.
    written: String,
}

/// An address or a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    network: IpAddr,
    prefix: u8,
}

impl Range {
    /// Parses `10.0.0.5`, `10.0.0.0/8`, `2001:db8::1` or `2001:db8::/32`.
    ///
    /// A bare address is a network of one, which is the only reading that makes `source: 10.0.0.5`
    /// mean what it looks like.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => {
                let prefix: u8 = prefix.parse().map_err(|_| {
                    format!("dns.axfr: '{prefix}' is not a prefix length: an integer is expected")
                })?;
                (address, Some(prefix))
            }
            None => (text, None),
        };
        let network: IpAddr = address
            .parse()
            .map_err(|_| format!("dns.axfr: '{address}' is not an IP address or a network"))?;
        let width = if network.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(width);
        if prefix > width {
            return Err(format!(
                "dns.axfr: '{text}' has a prefix of {prefix}, and an address of this family has \
                 {width} bits"
            ));
        }
        // Masked at parse time: `10.1.2.3/8` and `10.0.0.0/8` are the same range, and keeping the
        // host bits would make two spellings of one grant compare unequal.
        Ok(Self {
            network: mask(network, prefix),
            prefix,
        })
    }

    /// Whether `address` is inside this range. A range of one family never contains the other.
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = mask_bits(self.prefix, 32) as u32;
                (u32::from(network) & mask) == (u32::from(address) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = mask_bits(self.prefix, 128);
                (u128::from(network) & mask) == (u128::from(address) & mask)
            }
            _ => false,
        }
    }
}

/// The mask of `prefix` bits in a field of `width` bits, with the host bits cleared.
fn mask_bits(prefix: u8, width: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (u32::from(width) - u32::from(prefix))
    }
}

fn mask(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => IpAddr::V4(
            (u32::from(address) & mask_bits(prefix, 32) as u32)
                .to_be_bytes()
                .into(),
        ),
        IpAddr::V6(address) => IpAddr::V6(
            (u128::from(address) & mask_bits(prefix, 128))
                .to_be_bytes()
                .into(),
        ),
    }
}

/// The allowlist a zone transfer is decided by.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allow {
    grants: Vec<Grant>,
}

impl Allow {
    /// Nobody, which is the default and the behaviour every deployment had before this existed.
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Whether an entry can ever match.
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Resolves the `dns.axfr.allow` list against the keys this server holds.
    ///
    /// The keys are passed in rather than looked up so that a name that is not defined is refused
    /// here, at start, with the name in the message - not at the first transfer, where the client
    /// sees only `REFUSED` and has nothing to report.
    pub fn resolve<T>(
        config: &[crate::dns::config::AxfrAllowConfig],
        keys: &[T],
        key_name: impl Fn(&T) -> &Name,
    ) -> Result<Self, String> {
        let mut grants = Vec::with_capacity(config.len());
        for entry in config {
            let source = match entry.source.as_deref() {
                Some(text) => Some(Range::parse(text)?),
                None => None,
            };
            let key = match entry.key.as_deref() {
                Some(name) => {
                    // The same shape `resolve_keys` gives a key: a name with the root label and no
                    // trailing dot in the file. `Name` compares the fully-qualified flag too, so a
                    // grant parsed as relative would not equal the key it names - measured: the
                    // start failed with "dns.keys does not define it" for a key defined two lines
                    // above it.
                    let parsed = Name::from_ascii(name.trim().trim_end_matches('.'))
                        .map(|mut name| {
                            name.set_fqdn(true);
                            name
                        })
                        .map_err(|err| format!("dns.axfr: '{name}' is not a key name: {err}"))?;
                    if !keys.iter().any(|held| key_name(held) == &parsed) {
                        return Err(format!(
                            "dns.axfr.allow names the key '{name}', which dns.keys does not \
                             define: a grant for a key that does not exist grants nothing, and \
                             reads as if it did"
                        ));
                    }
                    Some(parsed)
                }
                None => None,
            };
            if source.is_none() && key.is_none() {
                return Err(
                    "dns.axfr.allow has an entry that names neither a source nor a key: that allows \
                     nobody, and reads as if it allowed somebody"
                        .to_string(),
                );
            }
            grants.push(Grant {
                source,
                key,
                written: describe(entry),
            });
        }
        Ok(Self { grants })
    }

    /// Whether this client, having proved this key, may transfer.
    ///
    /// `key` is the name of the key whose MAC verified, and `None` for a request that carried no
    /// signature at all - not for one that carried a signature that failed, which is decided before
    /// this is asked.
    pub fn permits(&self, client: IpAddr, key: Option<&Name>) -> bool {
        self.grants.iter().any(|grant| {
            let source = grant.source.is_none_or(|range| range.contains(client));
            let signed = match &grant.key {
                Some(required) => key == Some(required),
                None => true,
            };
            source && signed
        })
    }

    /// The entry that permitted this client, for the log line that says why it was let through.
    pub fn matched(&self, client: IpAddr, key: Option<&Name>) -> Option<&str> {
        self.grants
            .iter()
            .find(|grant| {
                grant.source.is_none_or(|range| range.contains(client))
                    && match &grant.key {
                        Some(required) => key == Some(required),
                        None => true,
                    }
            })
            .map(|grant| grant.written.as_str())
    }
}

fn describe(entry: &crate::dns::config::AxfrAllowConfig) -> String {
    match (&entry.source, &entry.key) {
        (Some(source), Some(key)) => format!("source={source}, key={key}"),
        (Some(source), None) => format!("source={source}"),
        (None, Some(key)) => format!("key={key}"),
        (None, None) => "neither source nor key".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).expect("a name")
    }

    fn entry(source: Option<&str>, key: Option<&str>) -> crate::dns::config::AxfrAllowConfig {
        crate::dns::config::AxfrAllowConfig {
            source: source.map(str::to_string),
            key: key.map(str::to_string),
        }
    }

    fn allow(entries: &[crate::dns::config::AxfrAllowConfig]) -> Allow {
        let keys = vec![name("zone-transfer."), name("other.")];
        Allow::resolve(entries, &keys, |key| key).expect("the entries resolve")
    }

    #[test]
    fn an_empty_list_denies_everybody() {
        let allow = Allow::deny_all();
        assert!(allow.is_empty());
        assert!(!allow.permits("127.0.0.1".parse().expect("an address"), None));
        assert!(!allow.permits(
            "127.0.0.1".parse().expect("an address"),
            Some(&name("zone-transfer."))
        ));
    }

    #[test]
    fn a_source_grant_covers_the_range_and_nothing_outside_it() {
        let allow = allow(&[entry(Some("10.0.0.0/8"), None)]);
        assert!(allow.permits("10.1.2.3".parse().expect("an address"), None));
        assert!(allow.permits("10.255.255.255".parse().expect("an address"), None));
        assert!(!allow.permits("11.0.0.1".parse().expect("an address"), None));
        // The family boundary: an IPv4 range does not contain any IPv6 address, and a comparison
        // that dropped the family would match on the low bits.
        assert!(!allow.permits("::10.1.2.3".parse().expect("an address"), None));
    }

    #[test]
    fn a_bare_address_is_a_range_of_one() {
        let allow = allow(&[entry(Some("192.0.2.5"), None)]);
        assert!(allow.permits("192.0.2.5".parse().expect("an address"), None));
        assert!(!allow.permits("192.0.2.6".parse().expect("an address"), None));
    }

    #[test]
    fn a_key_grant_needs_the_key_and_accepts_it_from_anywhere() {
        let allow = allow(&[entry(None, Some("zone-transfer."))]);
        assert!(allow.permits(
            "203.0.113.9".parse().expect("an address"),
            Some(&name("zone-transfer."))
        ));
        // Unsigned is not "the right key": a key grant is about proof, and there is none here.
        assert!(!allow.permits("203.0.113.9".parse().expect("an address"), None));
        // And another key that this server does hold is not the one named.
        assert!(!allow.permits(
            "203.0.113.9".parse().expect("an address"),
            Some(&name("other."))
        ));
    }

    #[test]
    fn a_grant_with_both_needs_both() {
        let allow = allow(&[entry(Some("192.0.2.0/24"), Some("zone-transfer."))]);
        let inside: IpAddr = "192.0.2.10".parse().expect("an address");
        let outside: IpAddr = "198.51.100.10".parse().expect("an address");
        assert!(allow.permits(inside, Some(&name("zone-transfer."))));
        assert!(
            !allow.permits(inside, None),
            "the range alone is not enough"
        );
        assert!(
            !allow.permits(outside, Some(&name("zone-transfer."))),
            "the key alone is not enough"
        );
    }

    #[test]
    fn one_matching_entry_is_enough_and_the_first_is_the_one_reported() {
        let allow = allow(&[
            entry(Some("10.0.0.0/8"), None),
            entry(None, Some("zone-transfer.")),
        ]);
        assert_eq!(
            allow.matched("10.1.1.1".parse().expect("an address"), None),
            Some("source=10.0.0.0/8")
        );
        assert_eq!(
            allow.matched(
                "203.0.113.9".parse().expect("an address"),
                Some(&name("zone-transfer."))
            ),
            Some("key=zone-transfer.")
        );
        assert_eq!(
            allow.matched("203.0.113.9".parse().expect("an address"), None),
            None
        );
    }

    #[test]
    fn an_entry_that_allows_nothing_is_refused_rather_than_kept() {
        let keys = vec![name("zone-transfer.")];
        let error = Allow::resolve(&[entry(None, None)], &keys, |key| key)
            .expect_err("an empty entry is a mistake");
        assert!(error.contains("neither a source nor a key"), "{error}");
    }

    #[test]
    fn a_grant_for_a_key_this_server_does_not_hold_is_refused() {
        let keys = vec![name("zone-transfer.")];
        let error = Allow::resolve(&[entry(None, Some("missing."))], &keys, |key| key)
            .expect_err("a key that is not configured grants nothing");
        assert!(error.contains("missing."), "{error}");
        assert!(error.contains("does not"), "{error}");
    }

    #[test]
    fn a_prefix_longer_than_the_family_allows_is_refused() {
        let error = Range::parse("10.0.0.0/33").expect_err("33 bits of 32");
        assert!(error.contains("33"), "{error}");
        let error = Range::parse("10.0.0.0/").expect_err("an empty prefix");
        assert!(error.contains("prefix length"), "{error}");
        let error = Range::parse("not an address").expect_err("not an address");
        assert!(error.contains("IP address"), "{error}");
        // A prefix that fits the other family is fine on its own terms: `/64` of an IPv6 address.
        assert!(Range::parse("2001:db8::/64").is_ok());
    }

    #[test]
    fn host_bits_are_dropped_so_two_spellings_of_one_range_are_one_range() {
        assert_eq!(
            Range::parse("10.1.2.3/8").expect("a range"),
            Range::parse("10.0.0.0/8").expect("a range")
        );
        // And `0.0.0.0/0` covers everything, which is what an operator writing it means.
        let everything = Range::parse("0.0.0.0/0").expect("a range");
        assert!(everything.contains("203.0.113.9".parse().expect("an address")));
        assert!(!everything.contains("::1".parse().expect("an address")));
    }
}
