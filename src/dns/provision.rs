//! The zone a domain has before anybody writes a record: derived, not typed.
//!
//! Every record here is a consequence of something the server already decided elsewhere - the naming
//! context names the zone, the CLDAP section names the host, the ports are the ones this process
//! listens on - and none of them is invented. That is the point of doing it at start rather than
//! asking an operator to write a zone file: a controller whose `A` record named an address it does
//! not hold would pass every test and fail every client.
//!
//! # What a client asks for, in the order it asks
//!
//! 1. `_ldap._tcp.dc._msdcs.<domain>` - the controller to talk to (SRV);
//! 2. the `A` of the target that SRV named;
//! 3. `_kerberos._tcp.<domain>` and `_kerberos._udp.<domain>` - where to get a ticket;
//! 4. `_ldap._tcp.<domain>`, `_kpasswd`, `_gc` - the rest of the locator set;
//! 5. the zone's own `SOA` and `NS`, which a validator and `nslookup` ask for first.
//!
//! All of them are written here, because a set with a hole in it fails at the step after the hole and
//! the client reports the failure as a network problem.
//!
//! # What is deliberately absent
//!
//! `_msdcs` as its own partition (`DC=ForestDnsZones`): this server holds one domain, and the SRV
//! records a forest root would carry live in the domain's own zone. Delegation, glue and DNSSEC are
//! absent for the reasons their tasks give.

use std::net::Ipv4Addr;

use crate::backend::{Backend, EntryChange};
use crate::dns::record::{Data, Record, Soa, Srv, kind};
use crate::dns::zone::{self, APEX};
use crate::model::Entry;

/// The TTL of every record this module writes.
///
/// AD uses 600 for the locator records and the zone's own defaults are the same number; a client
/// caches a controller's address for ten minutes, which is the window in which a moved controller is
/// still reachable under its old address. Shorter would have every client asking constantly, longer
/// would keep a stale answer alive past a maintenance window.
pub const TTL: u32 = 600;

/// What the zone is derived from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The naming context, which places the zone in the tree.
    pub base_dn: String,
    /// The domain's DNS name, `ad.example.com`.
    pub dns_domain: String,
    /// This controller's own name, `dc1.ad.example.com`.
    pub dns_host: String,
    /// The address the SRV records and the host's `A` point at.
    pub address: Ipv4Addr,
    /// The serial the `SOA` carries, `YYYYMMDDnn` at creation and an increasing number after.
    pub serial: u32,
}

impl Facts {
    /// The mailbox a `SOA` names as the zone's administrator: `hostmaster.<domain>`, with the `@`
    /// spelled as a dot because that is what an `RNAME` is.
    fn admin(&self) -> String {
        format!("hostmaster.{}", self.dns_domain)
    }

    /// The label the host has inside the zone: `dc1` for `dc1.ad.example.com` in `ad.example.com`.
    ///
    /// `None` when the host is not in the zone at all - an operator who configured `dns_host` in
    /// another domain has a configuration this module cannot place, and inventing a label would put
    /// a record under a name nobody asked for.
    fn host_label(&self) -> Option<String> {
        let suffix = format!(".{}", self.dns_domain.trim_end_matches('.'));
        let host = self.dns_host.trim_end_matches('.');
        host.strip_suffix(&suffix)
            .map(|label| label.to_ascii_lowercase())
            .filter(|label| !label.is_empty())
    }
}

/// The entries that make up the zone: parents first, then the zone, then its nodes.
///
/// `None` when the host is not inside the zone: the zone object and its apex are still placeable, but
/// a zone whose `SRV` targets a name it does not hold is a zone that sends every client elsewhere -
/// so nothing is written at all, and the caller reports the configuration.
pub fn entries(facts: &Facts) -> Option<Vec<Entry>> {
    let label = facts.host_label()?;
    let zone_dn = zone::zone_dn(&facts.base_dn, &facts.dns_domain);

    let mut out = vec![
        zone::partition_entry(&facts.base_dn),
        zone::container_entry(&facts.base_dn),
        // `for_zone(updates, secure_time)`: dynamic updates are refused until RRL-2.25.8 exists, and
        // a zero secure time says exactly that.
        zone::zone_entry(&facts.base_dn, &facts.dns_domain, 0, 0),
    ];

    let soa = Data::Soa(Soa {
        serial: facts.serial,
        refresh: 900,
        retry: 600,
        expire: 86_400,
        minimum: 300,
        primary: facts.dns_host.clone(),
        admin: facts.admin(),
    });

    // The apex: the zone's own identity, and the address of the server that answers for it. The `A`
    // is at the apex on purpose - a domain controller is reachable by its domain's name, which is
    // what a client with no SRV support falls back to.
    let apex = [
        Record::zone(kind::SOA, TTL, soa),
        Record::zone(kind::NS, TTL, Data::Name(facts.dns_host.clone())),
        Record::zone(kind::A, TTL, Data::A(facts.address)),
    ];

    // The host itself.
    let host = [Record::zone(kind::A, TTL, Data::A(facts.address))];

    out.push(zone::node_entry(&zone_dn, APEX, &apex).ok()?);
    out.push(zone::node_entry(&zone_dn, &label, &host).ok()?);

    // The locator records, grouped by the owner name they share: one node per name, several records
    // inside it, which is the shape AD keeps them in.
    for (owner, services) in LOCATORS {
        let records: Vec<Record> = services
            .iter()
            .map(|(port, _proto)| {
                // Both transports are an `SRV`: what separates them is the owner name
                // (`_kerberos._tcp` against `_kerberos._udp`), not the record type.
                Record::zone(
                    kind::SRV,
                    TTL,
                    Data::Srv(Srv {
                        priority: 0,
                        weight: 100,
                        port: *port,
                        target: facts.dns_host.clone(),
                    }),
                )
            })
            .collect();
        // The `_msdcs` owner names are spelled with the domain appended, and their node's `dc`
        // attribute is the whole relative name, dots and all - AD does the same.
        let relative = owner.replace("%domain%", &facts.dns_domain);
        out.push(zone::node_entry(&zone_dn, &relative, &records).ok()?);
    }

    Some(out)
}

/// The locator set a domain answers with, in AD's own order.
///
/// The owner names are relative to the zone, and the transport is part of the name: `_kerberos._tcp`
/// and `_kerberos._udp` are two owners with one record each, not one owner with two. The second tuple
/// field exists so an entry can gain a second address family or a site name without the table
/// changing shape.
const LOCATORS: &[(&str, &[(u16, ())])] = &[
    ("_ldap._tcp", &[(389, ())]),
    ("_ldap._tcp.dc._msdcs", &[(389, ())]),
    ("_kerberos._tcp", &[(88, ())]),
    ("_kerberos._tcp.dc._msdcs", &[(88, ())]),
    ("_kerberos._udp", &[(88, ())]),
    ("_kpasswd._tcp", &[(464, ())]),
    ("_kpasswd._udp", &[(464, ())]),
    ("_gc._tcp", &[(3268, ())]),
];

/// Writes the zone into the store, and reports the DNs it created.
///
/// Only the entries that are absent are written: an operator who has edited a record keeps it. A zone
/// that rewrote itself on every start would undo exactly the changes a directory is for.
pub async fn ensure(
    backend: &Backend,
    facts: &Facts,
    schema: &crate::schema::Schema,
) -> Result<Vec<String>, String> {
    let Some(entries) = entries(facts) else {
        return Err(format!(
            "'{}' is not inside '{}': a zone whose records name a host it does not hold sends every \
             client elsewhere",
            facts.dns_host, facts.dns_domain
        ));
    };

    let data = backend
        .load()
        .await
        .map_err(|err| format!("the store could not be read: {err}"))?;
    let existing: Vec<String> = data
        .entries
        .iter()
        .map(|entry| entry.dn().to_owned())
        .collect();

    let mut created = Vec::new();
    for entry in entries {
        if existing
            .iter()
            .any(|have| have.eq_ignore_ascii_case(entry.dn()))
        {
            continue;
        }
        let dn = entry.dn().to_string();
        // Stored the way the write funnel stores an entry: AD's `top` class requires
        // `objectCategory`, `instanceType` and `nTSecurityDescriptor`, and a zone node written
        // without them is a node the schema this directory publishes refuses to read back.
        let entry = crate::provision::stored(schema, &facts.base_dn, entry);
        backend
            .apply(&[EntryChange::Upsert { entry }])
            .await
            .map_err(|err| format!("'{dn}' could not be created: {err}"))?;
        created.push(dn);
    }
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::{Directory, Scope};

    fn facts() -> Facts {
        Facts {
            base_dn: "dc=ad,dc=example,dc=com".to_string(),
            dns_domain: "ad.example.com".to_string(),
            dns_host: "dc1.ad.example.com".to_string(),
            address: Ipv4Addr::new(10, 0, 2, 2),
            serial: 2_026_111_501,
        }
    }

    /// The acceptance: a directory holding what this module writes answers the questions a client
    /// asks before it can join, and it answers them through the reader the listener uses.
    #[test]
    fn the_zone_derived_from_the_facts_answers_a_clients_first_questions() {
        let entries = entries(&facts()).expect("the host is inside the zone");
        let directory =
            Directory::from_entries("dc=ad,dc=example,dc=com", "users", "groups", entries);

        let zone = zone::Zone::read(&directory, "dc=ad,dc=example,dc=com", "ad.example.com")
            .expect("the zone reads back");
        let answers = |name: &str| -> Vec<String> {
            zone.records
                .iter()
                .filter(|record| record.name.to_ascii().eq_ignore_ascii_case(name))
                .map(|record| format!("{:?}", record.data))
                .collect()
        };

        let apex = answers("ad.example.com.");
        assert!(
            apex.iter().any(|field| field.starts_with("SOA")),
            "the zone has a SOA: {apex:?}"
        );
        assert!(
            apex.iter().any(|field| field.starts_with("NS")),
            "and an NS: {apex:?}"
        );
        assert_eq!(answers("dc1.ad.example.com.").len(), 1, "the host's A");

        // The one a client asks first, and the target it names.
        let msdcs = answers("_ldap._tcp.dc._msdcs.ad.example.com.");
        assert_eq!(msdcs.len(), 1, "the controller locator: {msdcs:?}");
        assert!(
            msdcs[0].contains("dc1.ad.example.com"),
            "it points at this server: {msdcs:?}"
        );
        assert!(msdcs[0].contains("389"), "on the LDAP port: {msdcs:?}");

        for (owner, port) in [
            ("_kerberos._tcp.ad.example.com.", "88"),
            ("_kerberos._udp.ad.example.com.", "88"),
            ("_kpasswd._tcp.ad.example.com.", "464"),
            ("_gc._tcp.ad.example.com.", "3268"),
            ("_ldap._tcp.ad.example.com.", "389"),
        ] {
            let found = answers(owner);
            assert_eq!(found.len(), 1, "{owner} answers once: {found:?}");
            assert!(
                found[0].contains(port),
                "{owner} names port {port}: {found:?}"
            );
        }

        // And nothing was left unanswerable: a record this build cannot render is one a client asks
        // for and does not get.
        assert!(
            zone.unserved.is_empty(),
            "unserved types: {:?}",
            zone.unserved
        );

        // The zone object is where a directory client would look for it.
        let zone_dn = zone::zone_dn("dc=ad,dc=example,dc=com", "ad.example.com");
        assert!(
            directory.record(&zone_dn).is_some(),
            "the zone object exists"
        );
        let nodes = directory.scope_matches(&zone_dn, Scope::OneLevel, |_| true);
        assert!(
            nodes.len() >= 8,
            "the zone holds its nodes: {} found",
            nodes.len()
        );
    }

    /// A host outside the zone is a configuration this module cannot place, and inventing a label
    /// would put records under a name nobody asked for.
    #[test]
    fn a_host_outside_the_zone_is_refused_rather_than_guessed() {
        let mut outside = facts();
        outside.dns_host = "dc1.other.example".to_string();
        assert!(entries(&outside).is_none());
    }

    /// The serial is the zone's own statement about itself: two runs with different serials must
    /// produce different `SOA` records, or a secondary would never notice a change.
    #[test]
    fn the_soa_carries_the_serial_it_was_given() {
        let mut with_later = facts();
        with_later.serial = 2_026_111_601;
        let directory = |facts: &Facts| {
            Directory::from_entries(
                "dc=ad,dc=example,dc=com",
                "users",
                "groups",
                entries(facts).expect("placeable"),
            )
        };
        let read = |facts: &Facts| {
            zone::Zone::read(
                &directory(facts),
                "dc=ad,dc=example,dc=com",
                "ad.example.com",
            )
            .expect("reads")
            .records
            .into_iter()
            .find(|record| record.record_type() == hickory_server::proto::rr::RecordType::SOA)
            .expect("a SOA")
        };
        assert_ne!(read(&facts()).data, read(&with_later).data);
    }
}
