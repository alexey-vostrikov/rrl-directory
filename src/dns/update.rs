//! RFC 2136 `UPDATE`: what a client's registration actually asks for, as changes to the directory.
//!
//! # Why a plan and not a write
//!
//! An update is decided against the zone as it stood when the message arrived, and applied as one
//! change set - either the whole message or none of it. So this module is a **pure function**: it
//! reads the stored nodes, decides, and returns the changes. The caller applies them through the
//! same funnel every other write uses (`Source::apply`), which is where the journal, the schema and
//! the replication record live. A writer here would be a second path into the store.
//!
//! # The rules are Samba's, and they are the acceptance
//!
//! Read from `source4/dns_server/dns_update.c` rather than from the RFC alone, because a domain
//! controller is what clients actually test against:
//!
//! * the zone section is one `SOA` question, class `IN` or `ANY`, naming a zone this server holds -
//!   `FORMERR`, `NOTIMPL` and `NOTAUTH` respectively;
//! * a name outside the zone in any section is `NOTZONE`; a name below a node of ours is `NOTIMPL`,
//!   because this server does not delegate;
//! * prescan of the update section: `IN` may not carry `ANY`/`AXFR`/`MAILA`/`MAILB`; `ANY` must have
//!   ttl 0 and no data; `NONE` must have ttl 0 and may not carry the meta types;
//! * semantics: add if the exact value is not there, `ANY`+`ANY` is a no-op, `ANY`+type removes the
//!   whole RRset, `NONE`+type removes one value, and a `CNAME` may not coexist with another type at
//!   one name (RFC 1034 §3.6.2);
//! * the zone's `serial` is incremented by the same change set that changes the records.
//!
//! # What is not here
//!
//! Whether the client may do this at all. That is RRL-13.2/13.4: the grant check runs before this
//! module is called, on the same operations, and a refusal never reaches here.

use std::collections::BTreeMap;

use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::{DNSClass, Name, RData, Record, RecordType};

use crate::dns::record::{self, Data, Record as Stored, Soa, Srv, kind};
use crate::dns::zone::{self, APEX};
use crate::model::{Attribute, Attributes, Entry};

/// The change set an update turns into, or the code that refuses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Node entries to write: created, replaced, or removed from the directory.
    pub changes: Vec<Change>,
    /// The zone's serial after this update, which goes into the apex `SOA`.
    pub serial: u32,
    /// One line per operation that took effect, for the audit trail.
    pub applied: Vec<String>,
}

/// One entry to write or remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The node with this DN is to hold exactly these values, replacing what is there.
    Put { dn: String, entry: Entry },
    /// The node has no records of its own left and is not the apex: it goes.
    Remove { dn: String },
}

/// A node as the directory holds it: its relative name and its values, undecoded from the wire form.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    relative: String,
    records: Vec<Stored>,
}

/// Two records that are the same RR, per RFC 2136 §1: name, type and RDATA - and not the TTL, which
/// is why `PartialEq` on the whole record is the wrong comparison here.
fn same_rr(left: &Stored, right: &Stored) -> bool {
    left.rtype == right.rtype && left.data == right.data
}

impl Node {
    /// Whether this node holds `candidate`, compared as RFC 2136 §1 means by "the same RR": name,
    /// type and RDATA, with the TTL ignored - a client that re-registers with another TTL is
    /// re-registering the same record, not adding a second one.
    fn has_value(&self, candidate: &Stored) -> bool {
        self.records.iter().any(|record| same_rr(record, candidate))
    }

    /// Types other than `rtype` this node holds, which decides whether a `CNAME` may be added.
    fn other_types(&self, rtype: u16) -> Vec<u16> {
        let mut types: Vec<u16> = self
            .records
            .iter()
            .map(|record| record.rtype)
            .filter(|t| *t != rtype)
            .collect();
        types.sort_unstable();
        types.dedup();
        types
    }
}

/// Reads the zone's nodes out of the directory, as stored rather than as rendered.
///
/// Rendered is not enough: a node may hold a type this build cannot put on the wire (`Data::Other`),
/// and a rewrite from the rendered set would delete it. That is the difference between an update and
/// a deletion of everything the server does not understand.
fn nodes(
    directory: &crate::directory::Directory,
    zone_dn: &str,
) -> Result<BTreeMap<String, Node>, ResponseCode> {
    let mut nodes = BTreeMap::new();
    for (_, entry) in directory.records_in_scope(zone_dn, crate::directory::Scope::OneLevel) {
        let Some(relative) = entry
            .attributes()
            .get("dc")
            .and_then(|attribute| attribute.values.first())
            .map(|value| value.trim().to_string())
        else {
            // A node with no `dc` is not placeable, and `Zone::read` refuses the zone over it. An
            // update does not get to be more lenient than the reader: it would write under a name
            // that cannot be read back.
            return Err(ResponseCode::ServFail);
        };

        let mut records = Vec::new();
        for value in entry
            .attributes()
            .get(crate::dns::zone::ATTR_RECORD)
            .map(|attribute| &*attribute.values)
            .unwrap_or_default()
        {
            let bytes =
                crate::model::decode_binary(value.as_str()).ok_or(ResponseCode::ServFail)?;
            records.push(record::Record::decode(&bytes).map_err(|_| ResponseCode::ServFail)?);
        }
        nodes.insert(relative.to_ascii_lowercase(), Node { relative, records });
    }
    Ok(nodes)
}

/// The zone a message names, as a relative-to-`origin` comparison.
///
/// Returns `None` for a name that is not below `origin` at all, which is `NOTZONE`.
fn relative(name: &Name, origin: &str) -> Option<String> {
    let name = name.to_ascii().trim_end_matches('.').to_ascii_lowercase();
    let origin = origin.trim_end_matches('.').to_ascii_lowercase();
    if name == origin {
        return Some(APEX.to_string());
    }
    let head = name.strip_suffix(&format!(".{origin}"))?;
    Some(head.to_string())
}

/// The stored form of one record from a message, at `relative` inside the zone.
///
/// `None` for a type this build cannot store. Refused rather than skipped by the caller: an update
/// that silently drops part of what it was asked to does answer `NOERROR` for something it did not
/// do.
fn stored(record: &Record, _relative: &str, serial: u32) -> Option<Stored> {
    let ttl = record.ttl;
    let data = match &record.data {
        RData::A(a) => Data::A(a.0),
        RData::AAAA(aaaa) => Data::Aaaa(aaaa.0),
        RData::NS(name) => Data::Name(without_root(name)),
        RData::CNAME(name) => Data::Name(without_root(name)),
        RData::PTR(name) => Data::Name(without_root(name)),
        RData::MX(mx) => Data::Mx {
            preference: mx.preference,
            exchange: without_root(&mx.exchange),
        },
        RData::SRV(srv) => Data::Srv(Srv {
            priority: srv.priority,
            weight: srv.weight,
            port: srv.port,
            target: without_root(&srv.target),
        }),
        // A TXT carries octets and this build keeps them as text: every real `TXT` - an ACME token,
        // an SPF policy, a DKIM key - is ASCII, and `from_utf8_lossy` is what keeps a stray high
        // octet from turning a record into a decode failure.
        RData::TXT(txt) => Data::Txt(
            txt.txt_data
                .iter()
                .map(|text| String::from_utf8_lossy(text).to_string())
                .collect(),
        ),
        RData::SOA(soa) => Data::Soa(Soa {
            serial: soa.serial,
            // The intervals are signed in the wire form and unsigned here, which is where the two
            // disagree: a negative interval is a zone nobody can serve, and `Soa` says so by not
            // being able to hold one.
            refresh: u32::try_from(soa.refresh).ok()?,
            retry: u32::try_from(soa.retry).ok()?,
            expire: u32::try_from(soa.expire).ok()?,
            minimum: soa.minimum,
            primary: without_root(&soa.mname),
            admin: without_root(&soa.rname),
        }),
        _ => return None,
    };
    let candidate = Stored {
        rtype: u16::from(record.record_type()),
        ttl,
        rank: record::RANK_ZONE,
        serial,
        timestamp: 0,
        data,
    };
    // The question is not "did this match an `RData` arm" but "can this build store it": a record
    // whose type and data disagree encodes to nothing, and answering `NOERROR` for a write that
    // could not be made is the failure this check exists to prevent.
    candidate.encode().ok()?;
    Some(candidate)
}

/// A name as this build stores it: without the root label the wire form carries.
fn without_root(name: &Name) -> String {
    name.to_ascii().trim_end_matches('.').to_string()
}

/// The plan for one update message against the zone held under `zone_dn`.
///
/// `origin` is the zone's DNS name without the trailing dot. `updates` is the message's authority
/// section, which is where RFC 2136 carries the changes.
pub fn plan(
    directory: &crate::directory::Directory,
    zone_dn: &str,
    origin: &str,
    updates: &[Record],
) -> Result<Plan, ResponseCode> {
    let mut nodes = nodes(directory, zone_dn)?;

    // The serial the records being written remember: their own zone's next value, which is known
    // only after the apex has been read. Taken from the apex `SOA` as it stands.
    let apex = nodes
        .get(APEX)
        .map(|node| node.records.clone())
        .unwrap_or_default();
    let serial_now = apex
        .iter()
        .find_map(|record| match &record.data {
            Data::Soa(soa) => Some(soa.serial),
            _ => None,
        })
        .unwrap_or(1);
    let serial = serial_now.wrapping_add(1).max(1);

    let mut applied = Vec::new();
    let mut touched: BTreeMap<String, Node> = BTreeMap::new();

    for update in updates {
        // Prescan exists so that a message which is malformed is refused before any of it is
        // applied: RFC 2136 §3.4.1 is explicit that this is a whole-message decision.
        let class = update.dns_class;
        let rtype = update.record_type();
        let empty = matches!(&update.data, RData::Update0(_));
        match class {
            DNSClass::IN => {
                if matches!(rtype, RecordType::ANY | RecordType::AXFR | RecordType::IXFR) {
                    return Err(ResponseCode::FormErr);
                }
            }
            DNSClass::ANY => {
                if update.ttl != 0 || !empty {
                    return Err(ResponseCode::FormErr);
                }
            }
            DNSClass::NONE => {
                if update.ttl != 0
                    || matches!(rtype, RecordType::ANY | RecordType::AXFR | RecordType::IXFR)
                {
                    return Err(ResponseCode::FormErr);
                }
            }
            // Every other class - including `CH`, `HS` and anything unknown - is `FORMERR` here.
            // RFC 2136 §3.4.1 lists the permitted ones and nothing else.
            _ => return Err(ResponseCode::FormErr),
        }

        let name = &update.name;
        let relative = relative(name, origin).ok_or(ResponseCode::NotZone)?;

        // A node of this server's own that is not in the directory yet is created from the node it
        // has to be: the update describes it completely.
        let node = match touched.remove(&relative) {
            Some(node) => node,
            None => nodes.get(&relative).cloned().unwrap_or(Node {
                relative: relative.clone(),
                records: Vec::new(),
            }),
        };

        let describe =
            |what: &str| format!("{what} {}{}", display(&relative, origin), type_name(rtype));

        let mut node = node;
        match (class, rtype) {
            // Add an RR: only when the identical value is not already there (RFC 2136 §3.4.2.2).
            (DNSClass::IN, _) => {
                let value = stored(update, &relative, serial).ok_or(ResponseCode::NotImp)?;
                if node.has_value(&value) {
                    applied.push(format!("{} (already present)", describe("keep")));
                } else {
                    let conflicts = node.other_types(value.rtype);
                    let is_cname = value.rtype == kind::CNAME;
                    if (is_cname && !conflicts.is_empty())
                        || (!is_cname && conflicts == vec![kind::CNAME])
                    {
                        // RFC 1034 §3.6.2: a CNAME is alone at its name, in both directions.
                        return Err(ResponseCode::YXDomain);
                    }
                    node.records.push(value);
                    applied.push(describe("add"));
                }
            }
            // Class ANY with type ANY: "delete all RRsets from a name" does nothing at all, per
            // RFC 2136 §3.4.2.3 - it is a `NONE`+`ANY` that deletes a name.
            (DNSClass::ANY, RecordType::ANY) => {
                applied.push(format!("{} (nothing to do)", describe("no-op")));
            }
            // Class ANY with a type: delete the whole RRset of that type at the name.
            (DNSClass::ANY, _) => {
                let before = node.records.len();
                node.records
                    .retain(|record| record.rtype != u16::from(rtype));
                if node.records.len() == before {
                    applied.push(format!("{} (no such RRset)", describe("keep")));
                } else {
                    applied.push(describe("delete RRset"));
                }
            }
            // Class NONE: delete one value.
            (DNSClass::NONE, _) => {
                let value = stored(update, &relative, serial).ok_or(ResponseCode::NotImp)?;
                let before = node.records.len();
                node.records.retain(|record| !same_rr(record, &value));
                if node.records.len() == before {
                    applied.push(format!("{} (no such value)", describe("keep")));
                } else {
                    applied.push(describe("delete"));
                }
            }
            // Unreachable: every class that is not `IN` is `ANY` or `NONE` by the prescan above.
            _ => return Err(ResponseCode::FormErr),
        }

        touched.insert(relative, node);
    }

    // The apex keeps its `SOA`. A zone whose apex lost it cannot be read back - `Zone::read` refuses
    // a zone without one - and the `SOA` is what carries the serial every client and secondary looks
    // at. An update that removes it is refused rather than applied and then unreadable.
    let apex_now = touched.get(APEX);
    let apex_keeps_soa =
        apex_now.is_none_or(|node| node.records.iter().any(|record| record.rtype == kind::SOA));
    if !apex_keeps_soa {
        return Err(ResponseCode::Refused);
    }

    // One change per node, last write wins: a message that adds and then deletes at one name has one
    // answer, not an order the store has to replay. Without this the apex could be written twice -
    // once from what the update did to it and once for the serial - and which of the two landed
    // would depend on the order of a vector.
    let mut changes: BTreeMap<String, Change> = BTreeMap::new();
    let mut bump = false;
    for (relative, mut node) in std::mem::take(&mut touched) {
        if relative == APEX {
            for record in &mut node.records {
                if let Data::Soa(soa) = &mut record.data {
                    soa.serial = serial;
                    bump = true;
                }
            }
        }
        for record in &mut node.records {
            record.serial = serial;
        }

        let dn = zone::node_dn(zone_dn, &node.relative);
        if node.records.is_empty() && relative != APEX {
            changes.insert(dn.clone(), Change::Remove { dn });
            continue;
        }
        let entry = node_entry(&dn, &node.relative, &node.records)?;
        changes.insert(dn.clone(), Change::Put { dn, entry });
    }

    if !bump && serial_now != 0 {
        // The apex itself was not in this message, so it is written only to carry the new serial:
        // a secondary that saw nothing in the `SOA` would never fetch the change.
        if let Some(mut apex) = nodes.remove(APEX) {
            for record in &mut apex.records {
                if let Data::Soa(soa) = &mut record.data {
                    soa.serial = serial;
                }
                record.serial = serial;
            }
            let dn = zone::node_dn(zone_dn, APEX);
            let entry = node_entry(&dn, APEX, &apex.records)?;
            changes.insert(dn.clone(), Change::Put { dn, entry });
        }
    }

    let changes: Vec<Change> = changes.into_values().collect();
    Ok(Plan {
        changes,
        serial,
        applied,
    })
}

/// The stored node entry for `records` at `relative`.
fn node_entry(dn: &str, relative: &str, records: &[Stored]) -> Result<Entry, ResponseCode> {
    let values: Vec<String> = records
        .iter()
        .map(|record| {
            record
                .encode()
                .map(|bytes| crate::model::encode_binary(&bytes))
        })
        .collect::<Result<_, _>>()
        .map_err(|_| ResponseCode::ServFail)?;
    let attributes = Attributes::new()
        .push(Attribute::new(
            crate::model::ATTR_OBJECT_CLASS,
            vec!["top".to_string(), zone::NODE_CLASS.to_string()],
        ))
        .push(Attribute::single("dc", relative))
        .push(Attribute::new(crate::dns::zone::ATTR_RECORD, values).binary());
    Ok(Entry::new(dn, attributes))
}

/// `host.ad.example.com` for a node, and the zone name for the apex.
fn display(relative: &str, origin: &str) -> String {
    if relative == APEX {
        format!("{origin}.")
    } else {
        format!("{relative}.{origin}.")
    }
}

/// The type name as an operator reads it, for the audit line.
fn type_name(rtype: RecordType) -> String {
    format!(" {rtype}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use hickory_server::proto::rr::Record as Wire;
    use hickory_server::proto::rr::rdata::{A, TXT};

    const BASE: &str = "dc=ad,dc=example,dc=com";
    const ORIGIN: &str = "ad.example.com";

    fn soa(serial: u32) -> Stored {
        Stored::zone(
            kind::SOA,
            600,
            Data::Soa(Soa {
                serial,
                refresh: 900,
                retry: 600,
                expire: 86_400,
                minimum: 300,
                primary: format!("dc1.{ORIGIN}"),
                admin: format!("hostmaster.{ORIGIN}"),
            }),
        )
    }

    fn a_record(address: [u8; 4]) -> Stored {
        Stored::zone(kind::A, 600, Data::A(Ipv4Addr::from(address)))
    }

    /// A directory holding one zone with a `SOA` and one host.
    fn directory() -> (crate::directory::Directory, String) {
        let zone = zone::zone_entry(BASE, ORIGIN, 0, 0);
        let zone_dn = zone.dn().to_string();
        let entries = vec![
            zone::partition_entry(BASE),
            zone::container_entry(BASE),
            zone,
            zone::node_entry(&zone_dn, APEX, &[soa(7)]).expect("the apex encodes"),
            zone::node_entry(&zone_dn, "dc1", &[a_record([10, 0, 2, 5])]).expect("a host encodes"),
        ];
        (
            crate::directory::Directory::from_entries(BASE, "users", "groups", entries),
            zone_dn,
        )
    }

    fn wire(name: &str, ttl: u32, class: DNSClass, rtype: RecordType, data: Option<RData>) -> Wire {
        let name = Name::from_ascii(format!("{name}.")).expect("a name");
        let mut record = Wire::from_rdata(name, ttl, data.unwrap_or(RData::Update0(rtype)));
        // The fields are public and the setters are not: an update record is built by hand, which
        // is what `nsupdate` does on the wire.
        record.dns_class = class;
        record
    }

    fn add(host: &str, rtype: RecordType, data: RData) -> Wire {
        wire(host, 600, DNSClass::IN, rtype, Some(data))
    }

    /// Adding a record creates the node it belongs to, and the serial moves - the two things a
    /// client's registration depends on and the two an implementation gets wrong quietly.
    #[test]
    fn adding_a_record_creates_its_node_and_moves_the_serial() {
        let (directory, zone_dn) = directory();
        let plan = plan(
            &directory,
            &zone_dn,
            ORIGIN,
            &[add(
                "host.ad.example.com",
                RecordType::A,
                RData::A(A::from(Ipv4Addr::new(10, 0, 2, 10))),
            )],
        )
        .expect("a well-formed add");

        assert_eq!(plan.serial, 8, "the serial follows the SOA that was there");
        let put = plan
            .changes
            .iter()
            .find(|change| matches!(change, Change::Put { dn, .. } if dn.starts_with("dc=host,")))
            .expect("the new node is written");
        if let Change::Put { entry, .. } = put {
            assert!(
                entry.attributes().get("dnsRecord").is_some(),
                "the node carries its record"
            );
        }
        let apex = plan
            .changes
            .iter()
            .find(|change| matches!(change, Change::Put { dn, .. } if dn.starts_with("dc=@,")))
            .expect("the apex is written to carry the new serial");
        if let Change::Put { entry, .. } = apex {
            let values = entry
                .attributes()
                .get(crate::dns::zone::ATTR_RECORD)
                .expect("a SOA");
            let bytes = crate::model::decode_binary(&values.values[0]).expect("base64");
            let record = Stored::decode(&bytes).expect("a stored record");
            match record.data {
                Data::Soa(soa) => assert_eq!(soa.serial, 8),
                other => panic!("the apex held a {other:?}"),
            }
        }
    }

    /// Adding a value that is already there changes nothing and is not an error: a client
    /// registering itself twice in a minute is the ordinary case, not a fault.
    #[test]
    fn adding_the_same_value_twice_is_not_a_second_value() {
        let (directory, zone_dn) = directory();
        let one = add(
            "dc1.ad.example.com",
            RecordType::A,
            RData::A(A::from(Ipv4Addr::new(10, 0, 2, 5))),
        );
        let plan = plan(&directory, &zone_dn, ORIGIN, &[one.clone(), one]).expect("both are fine");

        let node = plan
            .changes
            .iter()
            .find(|change| matches!(change, Change::Put { dn, .. } if dn.starts_with("dc=dc1,")))
            .expect("the node is rewritten");
        if let Change::Put { entry, .. } = node {
            let values = entry
                .attributes()
                .get(crate::dns::zone::ATTR_RECORD)
                .expect("records");
            assert_eq!(values.values.len(), 1, "one value, not two");
        }
        assert!(
            plan.applied
                .iter()
                .any(|line| line.contains("already present")),
            "and the message says so: {:?}",
            plan.applied
        );
    }

    /// Two addresses at one name are two values, which is what a multi-homed host registers.
    #[test]
    fn a_second_address_is_a_second_value() {
        let (directory, zone_dn) = directory();
        let plan = plan(
            &directory,
            &zone_dn,
            ORIGIN,
            &[add(
                "dc1.ad.example.com",
                RecordType::A,
                RData::A(A::from(Ipv4Addr::new(10, 0, 2, 6))),
            )],
        )
        .expect("a second address");

        let node = plan
            .changes
            .iter()
            .find(|change| matches!(change, Change::Put { dn, .. } if dn.starts_with("dc=dc1,")))
            .expect("the node is rewritten");
        if let Change::Put { entry, .. } = node {
            assert_eq!(
                entry
                    .attributes()
                    .get(crate::dns::zone::ATTR_RECORD)
                    .expect("records")
                    .values
                    .len(),
                2
            );
        }
    }

    /// `ANY`+type deletes the whole RRset; `NONE`+value deletes one value and leaves the rest.
    #[test]
    fn the_two_deletions_remove_different_amounts() {
        let zone = zone::zone_entry(BASE, ORIGIN, 0, 0);
        let zone_dn = zone.dn().to_string();
        let extra = a_record([10, 0, 2, 7]);
        let entries = vec![
            zone,
            zone::node_entry(&zone_dn, APEX, &[soa(3)]).expect("apex"),
            zone::node_entry(&zone_dn, "host", &[a_record([10, 0, 2, 6]), extra]).expect("host"),
        ];
        let directory = crate::directory::Directory::from_entries(BASE, "users", "groups", entries);

        // One value out of two.
        let first = plan(
            &directory,
            &zone_dn,
            ORIGIN,
            &[wire(
                "host.ad.example.com",
                0,
                DNSClass::NONE,
                RecordType::A,
                Some(RData::A(A::from(Ipv4Addr::new(10, 0, 2, 6)))),
            )],
        )
        .expect("a value delete");
        let node = first
            .changes
            .iter()
            .find(|change| matches!(change, Change::Put { dn, .. } if dn.starts_with("dc=host,")))
            .expect("host is rewritten");
        if let Change::Put { entry, .. } = node {
            assert_eq!(
                entry
                    .attributes()
                    .get(crate::dns::zone::ATTR_RECORD)
                    .expect("records")
                    .values
                    .len(),
                1,
                "one of two values is gone, the other stays"
            );
        }

        // The whole RRset, which empties the node and therefore removes it.
        let outcome = plan(
            &directory,
            &zone_dn,
            ORIGIN,
            &[wire(
                "host.ad.example.com",
                0,
                DNSClass::ANY,
                RecordType::A,
                None,
            )],
        )
        .expect("an RRset delete");
        assert!(
            outcome.changes.iter().any(
                |change| matches!(change, Change::Remove { dn } if dn.starts_with("dc=host,"))
            ),
            "an empty node is removed: {:?}",
            outcome.changes
        );
    }

    /// The apex lives on even when its records are all deleted: a zone without its `SOA` cannot be
    /// read at all, and RFC 2136 §3.4.2.3 carves it out for exactly that reason.
    #[test]
    fn the_apex_is_never_removed() {
        let (directory, zone_dn) = directory();
        let plan = plan(
            &directory,
            &zone_dn,
            ORIGIN,
            &[wire(
                "ad.example.com",
                0,
                DNSClass::ANY,
                RecordType::A,
                None,
            )],
        )
        .expect("a delete of a type the apex has not got");
        assert!(
            !plan
                .changes
                .iter()
                .any(|change| matches!(change, Change::Remove { dn } if dn.starts_with("dc=@,"))),
            "the apex stays: {:?}",
            plan.changes
        );
    }

    /// Deleting the apex's `SOA` is refused: a zone that lost it cannot be read back, and the
    /// `SOA` is where the serial lives. A server that applied it would answer `NOERROR` and then
    /// refuse to start.
    #[test]
    fn deleting_the_apex_soa_is_refused() {
        let (directory, zone_dn) = directory();
        assert_eq!(
            plan(
                &directory,
                &zone_dn,
                ORIGIN,
                &[wire(
                    "ad.example.com",
                    0,
                    DNSClass::ANY,
                    RecordType::SOA,
                    None
                )]
            ),
            Err(ResponseCode::Refused)
        );
    }

    /// A message that adds and then deletes at one name has one answer, not an order for the store
    /// to replay: the plan names each node once.
    #[test]
    fn a_node_is_named_once_in_the_plan() {
        let (directory, zone_dn) = directory();
        let outcome = plan(
            &directory,
            &zone_dn,
            ORIGIN,
            &[
                add(
                    "tmp.ad.example.com",
                    RecordType::A,
                    RData::A(A::from(Ipv4Addr::new(10, 0, 2, 11))),
                ),
                wire("tmp.ad.example.com", 0, DNSClass::ANY, RecordType::A, None),
            ],
        )
        .expect("add then delete");

        let named: Vec<&Change> = outcome
            .changes
            .iter()
            .filter(|change| match change {
                Change::Put { dn, .. } | Change::Remove { dn } => dn.starts_with("dc=tmp,"),
            })
            .collect();
        assert_eq!(named.len(), 1, "one node, one change: {named:?}");
        assert!(
            matches!(named[0], Change::Remove { .. }),
            "and it is the last word: {named:?}"
        );
    }

    /// Every malformed message from RFC 2136 §3.4.1 is `FORMERR`, and a name outside the zone is
    /// `NOTZONE`. These are the codes a client branches on, so each one is a test.
    #[test]
    fn a_malformed_message_is_refused_with_the_code_the_rfc_names() {
        let (directory, zone_dn) = directory();

        // Class IN may not carry a meta type.
        for rtype in [RecordType::ANY, RecordType::AXFR, RecordType::ANY] {
            let message = wire("host.ad.example.com", 600, DNSClass::IN, rtype, None);
            assert_eq!(
                plan(&directory, &zone_dn, ORIGIN, &[message]),
                Err(ResponseCode::FormErr),
                "class IN with {rtype}"
            );
        }
        // Class ANY must have ttl 0 and no data.
        assert_eq!(
            plan(
                &directory,
                &zone_dn,
                ORIGIN,
                &[wire(
                    "host.ad.example.com",
                    60,
                    DNSClass::ANY,
                    RecordType::A,
                    None
                )]
            ),
            Err(ResponseCode::FormErr),
            "ttl on an ANY"
        );
        // Class NONE must have ttl 0.
        assert_eq!(
            plan(
                &directory,
                &zone_dn,
                ORIGIN,
                &[wire(
                    "host.ad.example.com",
                    60,
                    DNSClass::NONE,
                    RecordType::A,
                    None
                )]
            ),
            Err(ResponseCode::FormErr),
            "ttl on a NONE"
        );
        // A class this server does not take at all.
        assert_eq!(
            plan(
                &directory,
                &zone_dn,
                ORIGIN,
                &[wire(
                    "host.ad.example.com",
                    60,
                    DNSClass::CH,
                    RecordType::A,
                    None
                )]
            ),
            Err(ResponseCode::FormErr),
            "class CH"
        );
        // A name outside the zone.
        assert_eq!(
            plan(
                &directory,
                &zone_dn,
                ORIGIN,
                &[add(
                    "host.elsewhere.test",
                    RecordType::A,
                    RData::A(A::from(Ipv4Addr::new(10, 0, 2, 9)))
                )]
            ),
            Err(ResponseCode::NotZone),
            "a name outside the zone"
        );
    }

    /// A CNAME may not sit beside another type at one name, in either direction: RFC 1034 §3.6.2.
    #[test]
    fn a_cname_cannot_share_its_name() {
        let (directory, zone_dn) = directory();
        let cname = RData::CNAME(hickory_server::proto::rr::rdata::CNAME(
            Name::from_ascii("elsewhere.example.net.").expect("a name"),
        ));

        // Onto a name that already has an A.
        assert_eq!(
            plan(
                &directory,
                &zone_dn,
                ORIGIN,
                &[add("dc1.ad.example.com", RecordType::CNAME, cname.clone())]
            ),
            Err(ResponseCode::YXDomain)
        );

        // And the other way round: an A onto a name that is a CNAME.
        let zone = zone::zone_entry(BASE, ORIGIN, 0, 0);
        let zone_dn = zone.dn().to_string();
        let alias = Stored {
            rtype: kind::CNAME,
            ttl: 600,
            rank: record::RANK_ZONE,
            serial: 1,
            timestamp: 0,
            data: Data::Name("elsewhere.example.net".to_string()),
        };
        let entries = vec![
            zone,
            zone::node_entry(&zone_dn, APEX, &[soa(1)]).expect("apex"),
            zone::node_entry(&zone_dn, "alias", &[alias]).expect("alias"),
        ];
        let directory = crate::directory::Directory::from_entries(BASE, "users", "groups", entries);
        assert_eq!(
            plan(
                &directory,
                &zone_dn,
                ORIGIN,
                &[add(
                    "alias.ad.example.com",
                    RecordType::A,
                    RData::A(A::from(Ipv4Addr::new(10, 0, 2, 8)))
                )]
            ),
            Err(ResponseCode::YXDomain)
        );
    }

    /// A `TXT` is what an ACME challenge is: written by a client, read back by a validator. It has to
    /// survive the stored form exactly, or the token the validator compares is not the one it issued.
    #[test]
    fn a_txt_round_trips_through_the_stored_form() {
        let (directory, zone_dn) = directory();
        let plan = plan(
            &directory,
            &zone_dn,
            ORIGIN,
            &[add(
                "_acme-challenge.ad.example.com",
                RecordType::TXT,
                RData::TXT(TXT::new(vec!["token-from-the-validator".to_string()])),
            )],
        )
        .expect("a TXT add");

        let node = plan
            .changes
            .iter()
            .find(|change| matches!(change, Change::Put { dn, .. } if dn.starts_with("dc=_acme-challenge,")))
            .expect("the challenge node is written");
        if let Change::Put { entry, .. } = node {
            let values = entry
                .attributes()
                .get(crate::dns::zone::ATTR_RECORD)
                .expect("records");
            let bytes = crate::model::decode_binary(&values.values[0]).expect("base64");
            let record = Stored::decode(&bytes).expect("a stored record");
            assert_eq!(
                record.data,
                Data::Txt(vec!["token-from-the-validator".to_string()]),
                "the token comes back exactly as it went in"
            );
        }
    }

    /// A type with no stored form is refused rather than dropped: an update that answers `NOERROR`
    /// for something it did not do is worse than a refusal.
    #[test]
    fn a_type_this_build_cannot_store_is_refused() {
        let (directory, zone_dn) = directory();
        assert_eq!(
            plan(
                &directory,
                &zone_dn,
                ORIGIN,
                &[add(
                    "host.ad.example.com",
                    RecordType::HINFO,
                    RData::HINFO(hickory_server::proto::rr::rdata::HINFO::new(
                        "x86".to_string(),
                        "linux".to_string()
                    ))
                )]
            ),
            Err(ResponseCode::NotImp),
            "the value does not match the type, so it has no stored form"
        );
    }
}
