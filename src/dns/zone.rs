//! The zone as the directory holds it: `dnsNode` entries under `DC=<zone>,CN=RRLDNS,…`.
//!
//! [`crate::dns::record`] reads and writes one `dnsRecord` value, and [`crate::dns::serve`] answers
//! queries out of a list of records. This module is the join between them, and it is the piece that
//! decides whether the zone is *in the directory* or merely *in a file beside the server*: the
//! entries here are the ones an AD tool reads, so a zone written by this server is a zone `samba-tool`
//! or `adsi` can look at, and a zone written by them is one this server answers from.
//!
//! # The shape
//!
//! ```text
//! DC=DomainDnsZones,<base_dn>                  the partition zones live in
//! CN=RRLDNS,DC=DomainDnsZones,<base_dn>        the container (AD: CN=MicrosoftDNS)
//! DC=example.com,CN=RRLDNS,…                   the zone: top + dnsZone, dnsProperty
//! DC=@,DC=example.com,…                        the apex: SOA, NS, A
//! DC=samba,DC=example.com,…                    a host: A
//! DC=_ldap._tcp,DC=example.com,…               a service: SRV
//! ```
//!
//! Two details of that shape are not negotiable, because a tool reading the zone relies on them:
//!
//! - the zone's RDN is the **whole** DNS name in one `dc` component (`DC=example.com`, not
//!   `DC=com,DC=example`), and its nodes are named **relative** to it, so `_ldap._tcp.dc._msdcs`
//!   below `example.com` is one component with dots in it;
//! - the apex is spelled `@`, not `example.com` and not the empty string.
//!
//! # What is served, and what is only carried
//!
//! A record this build cannot render onto the wire - a type [`crate::dns::record::Data`] keeps as
//! `Other` - is **counted**, not silently dropped: [`Zone::unserved`] names the types, and the
//! listener reports them at start. Silence here would look like a zone that is missing records,
//! and the difference between "the directory does not have it" and "this build cannot answer it"
//! is the whole question somebody would be asking.

use hickory_server::proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SOA, SRV};
use hickory_server::proto::rr::{Name, RData, Record};
use thiserror::Error;

use crate::directory::{Directory, Scope};
use crate::dns::property;
use crate::dns::record::{self, Data, kind};
use crate::model::{Attribute, Attributes, Entry};

/// The partition zones live in, as a DN under the naming context.
///
/// AD calls the same thing `DC=DomainDnsZones` and makes it an application partition; here it is an
/// ordinary branch of the domain tree. The name is kept, because a tool that looks for the domain's
/// DNS finds it by this RDN and not by where the server decided to hang it.
pub const PARTITION_RDN: &str = "dc=DomainDnsZones";

/// The container holding zones. `RRLDNS`, not `MicrosoftDNS`: this is not Microsoft's directory,
/// and a client that needs to tell the two apart has only the name to do it with.
pub const CONTAINER_NAME: &str = "RRLDNS";

/// The attribute holding a node's records, one value per record.
pub const ATTR_RECORD: &str = "dnsRecord";

/// The attribute holding a zone's settings.
pub const ATTR_PROPERTY: &str = "dnsProperty";

/// The class of the zone object.
pub const ZONE_CLASS: &str = "dnsZone";

/// The class of a node holding records.
pub const NODE_CLASS: &str = "dnsNode";

/// How the apex is spelled in the RDN of its node.
pub const APEX: &str = "@";

/// Why a zone cannot be read out of the directory.
///
/// Every variant names the entry it came from: a zone read is one pass over entries this server did
/// not write, so "a record could not be decoded" without saying which is a message with no address.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum Error {
    #[error("the directory holds no zone '{name}' at '{dn}'")]
    NoZone { name: String, dn: String },
    #[error("'{name}' is not a DNS name: {detail}")]
    Name { name: String, detail: String },
    #[error("'{dn}' carries no 'dc', so the owner of its records is unknown")]
    NoOwner { dn: String },
    #[error("'{dn}' carries a dnsRecord value that is not base64: '{value}'")]
    NotBase64 { dn: String, value: String },
    #[error("'{dn}' carries a dnsRecord this build cannot read: {detail}")]
    Record { dn: String, detail: String },
}

/// One zone: its origin, where it lives, and the records it answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// The origin as an absolute name, `example.com.`.
    pub origin: Name,
    /// The DN of the zone object, so a write knows where to put a new node.
    pub dn: String,
    /// The records, as the listener wants them: owner names absolute, TTLs per record.
    pub records: Vec<Record>,
    /// Record types the directory holds and this build cannot render onto the wire.
    ///
    /// Sorted and deduplicated, because it is read as a report at start rather than as data.
    pub unserved: Vec<u16>,
}

/// `DC=DomainDnsZones,<base_dn>`.
pub fn partition_dn(base_dn: &str) -> String {
    format!("{PARTITION_RDN},{base_dn}")
}

/// `CN=RRLDNS,DC=DomainDnsZones,<base_dn>`.
pub fn container_dn(base_dn: &str) -> String {
    format!("cn={CONTAINER_NAME},{}", partition_dn(base_dn))
}

/// `DC=<dns_name>,CN=RRLDNS,DC=DomainDnsZones,<base_dn>`.
///
/// The whole DNS name in one component, as AD spells it. A name is escaped for the DN rather than
/// pasted into it: a `dc` value that contains a comma or a plus would otherwise become two
/// components, and the zone would be filed under a name nobody asked for.
pub fn zone_dn(base_dn: &str, dns_name: &str) -> String {
    format!(
        "dc={},{}",
        crate::dn::escape_value(dns_name.trim_end_matches('.')),
        container_dn(base_dn)
    )
}

/// The DN of one node, for a name relative to the zone.
pub fn node_dn(zone_dn: &str, relative: &str) -> String {
    format!("dc={},{}", crate::dn::escape_value(relative), zone_dn)
}

impl Zone {
    /// Reads the zone called `dns_name` out of `directory`.
    ///
    /// Absent zone, absent `dc` and an undecodable value are all errors and none of them is
    /// skipped: a zone that loads with holes answers NXDOMAIN for names it holds, which is worse
    /// than a server that does not start, because the client sees a broken domain rather than a
    /// broken server.
    pub fn read(directory: &Directory, base_dn: &str, dns_name: &str) -> Result<Self, Error> {
        let dn = zone_dn(base_dn, dns_name);
        let origin = absolute(dns_name).ok_or_else(|| Error::Name {
            name: dns_name.to_string(),
            detail: "not a name this crate can parse".to_string(),
        })?;
        if directory.record(&dn).is_none() {
            return Err(Error::NoZone {
                name: dns_name.to_string(),
                dn,
            });
        }

        let mut records = Vec::new();
        let mut unserved = Vec::new();
        for (_, entry) in directory.scope_matches(&dn, Scope::OneLevel, |_| true) {
            let relative = relative_name(entry)?;
            let owner = match relative.as_str() {
                APEX => origin.clone(),
                other => absolute(&format!("{other}.{}", origin.to_ascii())).ok_or_else(|| {
                    Error::Name {
                        name: other.to_string(),
                        detail: format!("a node of '{}' is not a DNS name", origin.to_ascii()),
                    }
                })?,
            };
            let Some(values) = entry.attributes().get(ATTR_RECORD) else {
                // A node with no records is an empty non-terminal: it exists so a name below it can
                // exist, and it answers "yes, but not with that type". Nothing to serve.
                continue;
            };
            for value in values.values.iter() {
                let bytes = crate::model::decode_binary(value).ok_or_else(|| Error::NotBase64 {
                    dn: entry.dn().to_string(),
                    value: value.clone(),
                })?;
                let read = record::Record::decode(&bytes).map_err(|err| Error::Record {
                    dn: entry.dn().to_string(),
                    detail: err.to_string(),
                })?;
                match render(&owner, &read) {
                    Some(rendered) => records.push(rendered),
                    None => unserved.push(read.rtype),
                }
            }
        }
        unserved.sort_unstable();
        unserved.dedup();

        Ok(Self {
            origin,
            dn,
            records,
            unserved,
        })
    }
}

/// The `dc` of a node, which is its owner name relative to the zone.
fn relative_name(entry: &Entry) -> Result<String, Error> {
    entry
        .attributes()
        .get("dc")
        .and_then(|attribute| attribute.values.first())
        .map(|value| value.trim().to_string())
        .ok_or_else(|| Error::NoOwner {
            dn: entry.dn().to_string(),
        })
}

/// An absolute name from text that carries no trailing dot.
///
/// `Name::from_ascii` takes a name as a zone file writes it, where the dot is what makes it
/// absolute; every value in this module comes from a directory and has no dot, so the flag is set
/// here instead of being repeated at each call site. A name left relative is emitted without its
/// root label, which is a record that arrives truncated in a way no client reports as an error.
pub fn absolute(text: &str) -> Option<Name> {
    let mut name = Name::from_ascii(text.trim_end_matches('.')).ok()?;
    name.set_fqdn(true);
    Some(name)
}

/// One directory record as a wire record, or `None` when this build cannot render its type.
fn render(owner: &Name, record: &record::Record) -> Option<Record> {
    let data = match &record.data {
        Data::A(address) => RData::A(A::from(*address)),
        Data::Aaaa(address) => RData::AAAA(AAAA::from(*address)),
        // A name is four types, and which one it is comes from the record, not from the name: the
        // same octets are a `CNAME` in one record and a `PTR` in the next.
        Data::Name(target) => match record.rtype {
            kind::NS => RData::NS(NS(absolute(target)?)),
            kind::CNAME => RData::CNAME(CNAME(absolute(target)?)),
            kind::PTR => RData::PTR(PTR(absolute(target)?)),
            // `DNAME` is read by `record` - it is a name, like `CNAME` - but `hickory-proto` 0.26
            // has no `RData` variant for it, so the value is carried and reported as unserved
            // rather than answered in a shape the crate cannot express.
            _ => return None,
        },
        Data::Soa(soa) => RData::SOA(SOA::new(
            absolute(&soa.primary)?,
            absolute(&soa.admin)?,
            soa.serial,
            // `hickory` keeps the three intervals signed, as RFC 1035 draws them. A value past
            // `i32::MAX` is not clamped: it is a zone nobody can serve as written, and the record
            // is reported as unserved rather than answered with a number it does not have.
            i32::try_from(soa.refresh).ok()?,
            i32::try_from(soa.retry).ok()?,
            i32::try_from(soa.expire).ok()?,
            soa.minimum,
        )),
        Data::Mx {
            preference,
            exchange,
        } => RData::MX(MX::new(*preference, absolute(exchange)?)),
        Data::Srv(srv) => RData::SRV(SRV::new(
            srv.priority,
            srv.weight,
            srv.port,
            absolute(&srv.target)?,
        )),
        // Tombstones are deletions the zone keeps as markers, and `Other` is everything this build
        // does not read. Neither belongs on the wire.
        Data::Tombstone(_) | Data::Other(_) => return None,
    };
    Some(Record::from_rdata(owner.clone(), record.ttl, data))
}

/// `DC=DomainDnsZones,<base_dn>`, as a container.
pub fn partition_entry(base_dn: &str) -> Entry {
    container(
        partition_dn(base_dn),
        "DomainDnsZones",
        "the partition the domain's zones are filed in",
    )
}

/// `CN=RRLDNS,DC=DomainDnsZones,<base_dn>`, as a container.
pub fn container_entry(base_dn: &str) -> Entry {
    container(
        container_dn(base_dn),
        CONTAINER_NAME,
        "the domain's own zones, stored the way a directory stores them",
    )
}

/// A `container` holding nothing but its name and a description.
///
/// Not an `organizationalUnit`, for the reason `CN=Computers` is not one: a client that reads
/// `objectClass` expects the AD class, and the classes differ in what they allow below them.
fn container(dn: String, cn: &str, description: &str) -> Entry {
    let attributes = Attributes::new()
        .push(Attribute::new(
            crate::model::ATTR_OBJECT_CLASS,
            vec!["top".to_string(), "container".to_string()],
        ))
        .push(Attribute::single("cn", cn))
        .push(Attribute::single("description", description));
    Entry::new(dn, attributes)
}

/// The zone object, with the properties [`property::for_zone`] derives from the configuration.
///
/// `updates` and `secure_time` are the two settings a zone has before anything has been written to
/// it: whether dynamic updates are accepted, and the moment from which "secure" is measured. They
/// are arguments rather than defaults because both are decisions an operator makes, and a zone that
/// quietly accepted updates would be a zone anything on the network can rewrite.
pub fn zone_entry(base_dn: &str, dns_name: &str, updates: u32, secure_time: u32) -> Entry {
    let properties: Vec<String> = property::for_zone(updates, secure_time)
        .iter()
        .map(|property| crate::model::encode_binary(&property.encode()))
        .collect();
    let attributes = Attributes::new()
        .push(Attribute::new(
            crate::model::ATTR_OBJECT_CLASS,
            vec!["top".to_string(), ZONE_CLASS.to_string()],
        ))
        .push(Attribute::single("dc", dns_name.trim_end_matches('.')))
        .push(Attribute::new(ATTR_PROPERTY, properties).binary());
    Entry::new(zone_dn(base_dn, dns_name), attributes)
}

/// A node holding `records`, named `relative` to the zone it belongs to.
///
/// The records are encoded here rather than by the caller, so that a value written by this server
/// and a value read by it go through one pair of functions: the round trip is the test, and a
/// second encoder would be a second chance to disagree with [`record::Record::decode`].
pub fn node_entry(
    zone_dn: &str,
    relative: &str,
    records: &[record::Record],
) -> Result<Entry, Error> {
    let values: Vec<String> = records
        .iter()
        .map(|record| {
            record
                .encode()
                .map(|bytes| crate::model::encode_binary(&bytes))
                .map_err(|err| Error::Record {
                    dn: node_dn(zone_dn, relative),
                    detail: err.to_string(),
                })
        })
        .collect::<Result<_, _>>()?;
    let attributes = Attributes::new()
        .push(Attribute::new(
            crate::model::ATTR_OBJECT_CLASS,
            vec!["top".to_string(), NODE_CLASS.to_string()],
        ))
        .push(Attribute::single("dc", relative))
        .push(Attribute::new(ATTR_RECORD, values).binary());
    Ok(Entry::new(node_dn(zone_dn, relative), attributes))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::dns::record::{Record as Stored, Soa, Srv};

    const BASE: &str = "dc=ad,dc=example,dc=com";

    /// `TXT`, `1.2.840.113556.1.4.382`'s most common neighbour in a domain zone, and a type
    /// [`Data`] keeps as `Other`.
    const TXT: u16 = 0x0010;
    const DOMAIN: &str = "ad.example.com";

    fn soa() -> Data {
        Data::Soa(Soa {
            serial: 7,
            refresh: 900,
            retry: 600,
            expire: 86_400,
            minimum: 300,
            primary: format!("dc1.{DOMAIN}"),
            admin: format!("hostmaster.{DOMAIN}"),
        })
    }

    /// A directory holding one zone, with the records a domain actually needs.
    fn directory() -> Directory {
        let zone = zone_entry(BASE, DOMAIN, 0, 0);
        let dn = zone.dn().to_string();
        let entries = vec![
            partition_entry(BASE),
            container_entry(BASE),
            zone,
            node_entry(
                &dn,
                APEX,
                &[
                    Stored::zone(kind::SOA, 600, soa()),
                    Stored::zone(kind::NS, 600, Data::Name(format!("dc1.{DOMAIN}"))),
                ],
            )
            .expect("the apex encodes"),
            node_entry(
                &dn,
                "dc1",
                &[Stored::zone(
                    kind::A,
                    600,
                    Data::A(Ipv4Addr::new(10, 0, 2, 10)),
                )],
            )
            .expect("an address encodes"),
            node_entry(
                &dn,
                "_ldap._tcp",
                &[Stored::zone(
                    kind::SRV,
                    600,
                    Data::Srv(Srv {
                        priority: 0,
                        weight: 100,
                        port: 389,
                        target: format!("dc1.{DOMAIN}"),
                    }),
                )],
            )
            .expect("a service locator encodes"),
        ];
        Directory::from_entries(BASE, "users", "groups", entries)
    }

    /// The acceptance of this task: what the directory holds is what the listener answers with,
    /// owner names and all.
    #[test]
    fn a_zone_reads_its_records_out_of_the_directory() {
        let zone = Zone::read(&directory(), BASE, DOMAIN).expect("the zone reads");

        assert_eq!(zone.origin.to_ascii(), format!("{DOMAIN}."));
        assert_eq!(zone.dn, zone_dn(BASE, DOMAIN));
        assert!(zone.unserved.is_empty());

        let mut seen: Vec<(String, u16)> = zone
            .records
            .iter()
            .map(|record| (record.name.to_ascii(), u16::from(record.record_type())))
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            // Sorted by owner, then by type number: `_` sorts before the letters, and `NS` (2)
            // before `SOA` (6) at the apex.
            vec![
                (format!("_ldap._tcp.{DOMAIN}."), kind::SRV),
                (format!("{DOMAIN}."), kind::NS),
                (format!("{DOMAIN}."), kind::SOA),
                (format!("dc1.{DOMAIN}."), kind::A),
            ]
        );
    }

    /// A name the zone does not hold is not a name the server invents: the apex is `@`, and a node
    /// below it is the relative name appended to the origin.
    #[test]
    fn the_apex_is_the_origin_and_a_node_is_relative_to_it() {
        let zone = Zone::read(&directory(), BASE, DOMAIN).expect("the zone reads");
        let soa = zone
            .records
            .iter()
            .find(|record| record.record_type() == hickory_server::proto::rr::RecordType::SOA)
            .expect("the apex holds a SOA");
        assert_eq!(soa.name.to_ascii(), format!("{DOMAIN}."));
    }

    /// The TTL and the record data survive the encoding the directory forces on them: base64 of a
    /// binary blob, read back by the same pair of functions that wrote it.
    #[test]
    fn a_record_survives_the_round_trip_through_the_directory() {
        let zone = Zone::read(&directory(), BASE, DOMAIN).expect("the zone reads");
        let srv = zone
            .records
            .iter()
            .find(|record| record.record_type() == hickory_server::proto::rr::RecordType::SRV)
            .expect("the zone holds a service locator");
        assert_eq!(srv.ttl, 600);
        match &srv.data {
            RData::SRV(srv) => {
                assert_eq!(srv.port, 389);
                assert_eq!(srv.target.to_ascii(), format!("dc1.{DOMAIN}."));
            }
            other => panic!("a SRV was stored and {} came back", other),
        }
    }

    /// A type this build cannot render is reported, not dropped: a zone that silently loses its
    /// `TXT` values answers NXDOMAIN for names it holds.
    #[test]
    fn a_record_this_build_cannot_render_is_counted() {
        let zone = zone_entry(BASE, DOMAIN, 0, 0);
        let dn = zone.dn().to_string();
        // A type this build does not read: `Data::Other` keeps the octets, and the listener has
        // nothing to put on the wire for them.
        let txt = Stored::zone(TXT, 600, Data::Other(vec![9, 1, 2, 3]));
        let entries = vec![
            zone,
            node_entry(&dn, "txt", std::slice::from_ref(&txt)).expect("it encodes"),
        ];
        let directory = Directory::from_entries(BASE, "users", "groups", entries);

        let read = Zone::read(&directory, BASE, DOMAIN).expect("the zone reads");
        assert!(read.records.is_empty(), "nothing renderable was stored");
        assert_eq!(read.unserved, vec![TXT]);
    }

    /// A node whose `dc` is missing cannot be placed anywhere, and guessing would attach a record
    /// to somebody else's name.
    #[test]
    fn a_node_without_a_name_is_refused_by_its_dn() {
        let zone = zone_entry(BASE, DOMAIN, 0, 0);
        let dn = zone.dn().to_string();
        let nameless = Entry::new(
            format!("dc=nameless,{dn}"),
            Attributes::new()
                .push(Attribute::new(
                    crate::model::ATTR_OBJECT_CLASS,
                    vec!["top".to_string(), NODE_CLASS.to_string()],
                ))
                .push(
                    Attribute::new(ATTR_RECORD, vec![crate::model::encode_binary(&[0u8; 26])])
                        .binary(),
                ),
        );
        let directory = Directory::from_entries(BASE, "users", "groups", vec![zone, nameless]);

        match Zone::read(&directory, BASE, DOMAIN) {
            Err(Error::NoOwner { dn }) => assert!(dn.contains("nameless")),
            other => panic!("expected a nameless node to be refused, got {other:?}"),
        }
    }

    /// A value that is not base64 is a value somebody wrote by hand or a store that lost its mind.
    /// Either way the zone is not loaded with a record missing from it.
    #[test]
    fn a_value_that_is_not_base64_is_named() {
        let zone = zone_entry(BASE, DOMAIN, 0, 0);
        let dn = zone.dn().to_string();
        let broken = Entry::new(
            format!("dc=broken,{dn}"),
            Attributes::new()
                .push(Attribute::new(
                    crate::model::ATTR_OBJECT_CLASS,
                    vec!["top".to_string(), NODE_CLASS.to_string()],
                ))
                .push(Attribute::single("dc", "broken"))
                .push(Attribute::new(ATTR_RECORD, vec!["not base64!".to_string()]).binary()),
        );
        let directory = Directory::from_entries(BASE, "users", "groups", vec![zone, broken]);

        match Zone::read(&directory, BASE, DOMAIN) {
            Err(Error::NotBase64 { dn, value }) => {
                assert!(dn.contains("broken"));
                assert_eq!(value, "not base64!");
            }
            other => panic!("expected a broken value to be refused, got {other:?}"),
        }
    }

    /// A zone the directory does not hold is said so, with both names: the operator configured one
    /// name and the server looked for a DN, and either could be the wrong one.
    #[test]
    fn a_missing_zone_names_the_name_and_the_dn() {
        let directory = Directory::from_entries(BASE, "users", "groups", Vec::new());
        match Zone::read(&directory, BASE, DOMAIN) {
            Err(Error::NoZone { name, dn }) => {
                assert_eq!(name, DOMAIN);
                assert_eq!(dn, zone_dn(BASE, DOMAIN));
            }
            other => panic!("expected a missing zone to be named, got {other:?}"),
        }
    }

    /// The DNs are the shape an AD tool reads, and the escaping is what keeps a name with a comma
    /// from becoming two components.
    #[test]
    fn the_dns_are_the_shape_a_directory_reads() {
        assert_eq!(
            zone_dn(BASE, DOMAIN),
            format!("dc={DOMAIN},cn=RRLDNS,dc=DomainDnsZones,{BASE}")
        );
        assert_eq!(
            node_dn(&zone_dn(BASE, DOMAIN), "_ldap._tcp"),
            format!("dc=_ldap._tcp,dc={DOMAIN},cn=RRLDNS,dc=DomainDnsZones,{BASE}")
        );
    }
}
