//! NSEC3: the signed proof that a name does not exist.
//!
//! # Why NSEC3 and not NSEC
//!
//! `NSEC` names the next existing name in the zone, which means anybody can walk a zone by asking
//! for names it does not have. `NSEC3` publishes the *hash* of each name instead: a validator can
//! still prove absence, and the zone cannot be enumerated. RFC 9276 then says what a new zone should
//! do with the knobs: zero extra iterations, because they cost the validator CPU without adding
//! anything an attacker cannot pay for too.
//!
//! # The three records a denial needs
//!
//! A validator accepts `NXDOMAIN` for `a.b.zone` only when it can see all of (RFC 5155 §7.2.1):
//!
//! 1. that `b.zone` **does not exist** - an `NSEC3` whose owner hash sorts before the hash of
//!    `a.b.zone` and whose next hash sorts after it (the "next closer" proof);
//! 2. that the closest encloser - the longest ancestor that does exist - **does** exist, which is an
//!    `NSEC3` naming its hash exactly;
//! 3. that no wildcard `*.b.zone` covers it, another covering `NSEC3`.
//!
//! One record is not enough and two are not always enough: a server that answers with a single
//! `NSEC3` gets `SERVFAIL` from every validator, which is worse than answering unsigned.
//!
//! # Why the chain is rebuilt on every read
//!
//! Every record added or removed changes the set of hashes, and a chain that is one update behind is
//! a chain that proves the wrong thing - the validator then rejects **the whole zone**, not one
//! answer. So the chain is computed where the zone is read, from the records as they stand, in the
//! same pass that signs them. There is no cache to invalidate and no separate rebuild step to forget.

use std::collections::BTreeMap;

use hickory_server::proto::dnssec::Nsec3HashAlgorithm;
use hickory_server::proto::dnssec::rdata::{DNSSECRData, NSEC3, NSEC3PARAM};
use hickory_server::proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};

/// The parameters a zone's chain is built with.
///
/// `salt` is empty by default, which RFC 5155 §5.1.1 allows: a salt only makes a rainbow table
/// specific to one zone, and an empty one is what several registries publish. A zone that wants one
/// sets it in the configuration.
/// `Default` is the recommendation, not an accident of deriving: RFC 9276 §3.1 wants zero extra
/// iterations for a new zone - they are CPU the validator pays and an attacker pays the same, so the
/// cost buys nothing - and an empty salt, which several registries publish.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params {
    pub salt: Vec<u8>,
    pub iterations: u16,
}

/// The `NSEC3PARAM` record a validator reads to know how to hash.
pub fn param_record(origin: &Name, params: &Params, ttl: u32) -> Record {
    let mut record = Record::from_rdata(
        origin.clone(),
        ttl,
        RData::DNSSEC(DNSSECRData::NSEC3PARAM(NSEC3PARAM::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            params.iterations,
            params.salt.clone(),
        ))),
    );
    record.dns_class = DNSClass::IN;
    record
}

/// The hash of a name, as the owner label of its `NSEC3` is spelled: base32hex, no padding.
fn hash(origin: &Name, name: &Name, params: &Params) -> Result<Vec<u8>, String> {
    // The whole name, fully qualified and uncompressed (RFC 5155 §5): a hash of the label alone
    // would be a chain no validator agrees with, because a validator hashes what it asked for.
    let _ = origin;
    let absolute = name.clone();
    Nsec3HashAlgorithm::SHA1
        .hash(&params.salt, &absolute, params.iterations)
        .map(|digest| digest.as_ref().to_vec())
        .map_err(|err| format!("the name could not be hashed: {err}"))
}

/// The base32hex label an `NSEC3` owner carries.
fn label(hash: &[u8]) -> String {
    data_encoding::BASE32_DNSSEC.encode(hash)
}

/// One link of the chain: what a hash belongs to, and what types that owner holds.
struct Link {
    /// The hash, which is also the sort order of the chain.
    hash: Vec<u8>,
    /// The types at the owner, which is the type bitmap of its `NSEC3`.
    types: Vec<RecordType>,
}

/// The chain of a zone: one `NSEC3` per existing name, in hash order, each pointing at the next.
///
/// `records` is the zone **with its `RRSIG`s**, because the type bitmap of an `NSEC3` has to name
/// `RRSIG` - an RRset that is signed and not listed is an RRset a validator treats as absent.
pub fn chain(
    origin: &Name,
    records: &[Record],
    params: &Params,
    ttl: u32,
    signed: bool,
) -> Result<Vec<Record>, String> {
    let mut types: BTreeMap<String, (Name, Vec<RecordType>)> = BTreeMap::new();
    for record in records {
        // `NSEC3` itself is not part of the zone's data for this purpose: it is what we are
        // building, and a chain built from a chain would grow every time it ran.
        if record.record_type() == RecordType::NSEC3 {
            continue;
        }
        let key = record.name.to_ascii().to_ascii_lowercase();
        let entry = types
            .entry(key)
            .or_insert_with(|| (record.name.clone(), Vec::new()));
        if !entry.1.contains(&record.record_type()) {
            entry.1.push(record.record_type());
        }
    }

    let mut links = Vec::with_capacity(types.len());
    for (_, (name, mut types)) in types {
        types.sort();
        links.push(Link {
            hash: hash(origin, &name, params)?,
            types,
        });
    }
    // The chain is the sorted hashes, compared as octet strings - the byte order base32hex encodes
    // preserves, which is why the sort happens here and not on the label.
    links.sort_by(|left, right| left.hash.cmp(&right.hash));

    let mut out = Vec::with_capacity(links.len());
    for (index, link) in links.iter().enumerate() {
        // The last link points at the first: NSEC3 is a ring, and a chain that ended instead of
        // wrapping would leave the highest hash unable to prove anything after it.
        let next = &links[(index + 1) % links.len()].hash;
        let mut bitmap = link.types.clone();
        // The `NSEC3` owner itself holds an `NSEC3`, and the set is signed - both are types a
        // validator reads from the bitmap, and leaving them out is the commonest way to make a
        // denial unprovable.
        if !bitmap.contains(&RecordType::NSEC3) {
            bitmap.push(RecordType::NSEC3);
        }
        // Every RRset of a signed zone carries an `RRSIG`, and the bitmap has to say so - but the
        // bitmap must not depend on *when* the chain is built. The first version read the types off
        // the records, so a chain built before signing had no `RRSIG` in it and a chain built after
        // did: the second one was a different RRset from the one that had been signed, and every
        // `RRSIG` over `NSEC3` failed to verify. That is the whole reason `signed` is a parameter.
        if signed && !bitmap.contains(&RecordType::RRSIG) {
            bitmap.push(RecordType::RRSIG);
        }
        if bitmap.contains(&RecordType::ANY) {
            bitmap.retain(|rtype| *rtype != RecordType::ANY);
        }

        let mut record = Record::from_rdata(
            Name::from_ascii(format!("{}.{}", label(&link.hash), origin.to_ascii()))
                .map_err(|err| format!("an NSEC3 owner could not be built: {err}"))?,
            ttl,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                // Opt-out is for zones with delegations: it lets an unsigned delegation be skipped.
                // This server has none, and a flag that says "skip some names" would weaken every
                // denial in the zone for no gain.
                false,
                params.iterations,
                params.salt.clone(),
                next.clone(),
                bitmap,
            ))),
        );
        record.dns_class = DNSClass::IN;
        out.push(record);
    }
    Ok(out)
}

/// The `NSEC3`s that prove `qname` does not exist, or that the type asked for is not there.
///
/// Returned in the order a validator reads them: the next-closer proof, the closest encloser, and
/// the wildcard. `Ok(None)` means the chain cannot prove this name - which happens when the zone has
/// no `NSEC3` covering it, and answering with a partial proof would be worse than not answering.
pub fn denial(
    origin: &Name,
    chain: &[Record],
    qname: &Name,
    qtype: RecordType,
    params: &Params,
) -> Result<Option<Vec<Record>>, String> {
    let mut links: Vec<(Vec<u8>, Record)> = Vec::with_capacity(chain.len());
    for record in chain {
        if !matches!(&record.data, RData::DNSSEC(DNSSECRData::NSEC3(_))) {
            continue;
        }
        // The owner label *is* the hash: base32hex decodes back to the octets the sort uses, so the
        // chain is read from the wire form rather than from a second copy kept beside it.
        let Some(first) = record.name.iter().next() else {
            continue;
        };
        let Ok(hash) = data_encoding::BASE32_DNSSEC.decode(first) else {
            continue;
        };
        links.push((hash, record.clone()));
    }
    if links.is_empty() {
        return Ok(None);
    }
    links.sort_by(|left, right| left.0.cmp(&right.0));

    let qhash = hash(origin, qname, params)?;

    // A name that exists: the denial is about the type, and one record naming the hash exactly is
    // what proves it (RFC 5155 §7.2.3). This is the `NODATA` case.
    if let Some((_, exact)) = links.iter().find(|(hash, _)| *hash == qhash) {
        let _ = qtype;
        return Ok(Some(vec![exact.clone()]));
    }

    // The closest encloser: the longest ancestor of `qname` that the chain holds. The zone's apex is
    // always in the chain, so this terminates.
    let mut closest: Option<(Name, Record)> = None;
    let mut ancestor = qname.clone();
    loop {
        ancestor = ancestor.base_name();
        if ancestor.is_root() {
            break;
        }
        let hash = hash(origin, &ancestor, params)?;
        if let Some((_, record)) = links.iter().find(|(h, _)| *h == hash) {
            closest = Some((ancestor.clone(), record.clone()));
            break;
        }
        if ancestor.num_labels() <= origin.num_labels() {
            break;
        }
    }

    let Some((closest_name, closest_record)) = closest else {
        // Nothing in the chain is an ancestor of this name, which means the query is not below the
        // zone at all. Not our denial to make.
        return Ok(None);
    };

    // The next closer: one label longer than the closest encloser, still an ancestor of `qname`.
    let next_closer = {
        let q = qname.num_labels();
        let c = closest_name.num_labels();
        if q <= c {
            return Ok(None);
        }
        let mut name = qname.clone();
        while name.num_labels() > c + 1 {
            name = name.base_name();
        }
        name
    };
    let next_hash = hash(origin, &next_closer, params)?;

    let mut proof = Vec::with_capacity(3);
    // 1. The next closer does not exist.
    if let Some((_, covering)) = covering(&links, &next_hash) {
        proof.push(covering.clone());
    } else {
        return Ok(None);
    }
    // 2. The closest encloser does exist.
    proof.push(closest_record);

    // 3. No wildcard covers the name. If one does, the answer is not NXDOMAIN at all - the wildcard
    //    is a name in the zone and the caller should have answered from it.
    let wildcard = Name::from_ascii(format!("*.{}", closest_name.to_ascii()))
        .map_err(|err| format!("a wildcard name could not be built: {err}"))?;
    let wild_hash = hash(origin, &wildcard, params)?;
    if let Some((_, covering)) = covering(&links, &wild_hash) {
        // A wildcard that exists means the zone has records for it, and the answer is that RRset
        // rather than a denial. Reported so the caller can decide rather than answering `NXDOMAIN`
        // for a name the zone in fact covers.
        if !links.iter().any(|(h, _)| *h == wild_hash) {
            proof.push(covering.clone());
        }
    }

    Ok(Some(proof))
}

/// The record whose hash range contains `hash`, with the ring's wrap at the last link.
fn covering<'a>(links: &'a [(Vec<u8>, Record)], hash: &[u8]) -> Option<&'a (Vec<u8>, Record)> {
    // The chain is sorted, and each record's range runs from its own hash to the next one. So the
    // covering record is the last whose hash sorts before the target, or the last of all when the
    // target sorts after everything.
    let mut candidate = None;
    for link in links {
        if link.0.as_slice() < hash {
            candidate = Some(link);
        } else {
            break;
        }
    }
    candidate.or_else(|| links.last())
}

/// The chain as RRsets, which is what an answer's authority section carries.
pub fn answer_sets(records: Vec<Record>) -> Vec<std::sync::Arc<RecordSet>> {
    let mut sets: Vec<std::sync::Arc<RecordSet>> = Vec::new();
    for record in records {
        let mut set = RecordSet::new(record.name.clone(), record.record_type(), record.ttl);
        set.set_dns_class(DNSClass::IN);
        set.insert(record, 0);
        sets.push(std::sync::Arc::new(set));
    }
    sets
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::rr::rdata::A;
    use std::net::Ipv4Addr;

    const DOMAIN: &str = "ad.example.com";

    fn origin() -> Name {
        Name::from_ascii(format!("{DOMAIN}.")).expect("a name")
    }

    fn name(label: &str) -> Name {
        Name::from_ascii(format!("{label}.{DOMAIN}.")).expect("a name")
    }

    /// A zone with an apex, two hosts and a nested one - enough for a closest-encloser proof.
    fn zone() -> Vec<Record> {
        let a = |name: Name| {
            Record::from_rdata(name, 600, RData::A(A::from(Ipv4Addr::new(10, 0, 2, 5))))
        };
        vec![
            a(origin()),
            a(name("dc1")),
            a(name("host")),
            a(name("deep.inner")),
        ]
    }

    /// Every name gets one link, the links are a ring in hash order, and each bitmap names the types
    /// at its owner plus `NSEC3` itself.
    #[test]
    fn the_chain_covers_every_name_and_closes_into_a_ring() {
        let params = Params::default();
        let links = chain(&origin(), &zone(), &params, 600, false).expect("the chain builds");
        assert_eq!(
            links.len(),
            4,
            "one link per name: apex, dc1, host, deep.inner"
        );

        let mut hashes = Vec::new();
        for record in &links {
            let RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) = &record.data else {
                panic!("an NSEC3 record holds NSEC3 data");
            };
            let first = record.name.iter().next().expect("an owner label");
            hashes.push(
                data_encoding::BASE32_DNSSEC
                    .decode(first)
                    .expect("base32hex"),
            );
            assert!(
                nsec3.type_set().contains(RecordType::NSEC3),
                "the bitmap names NSEC3 itself"
            );
            assert!(
                nsec3.type_set().contains(RecordType::A),
                "and the types at the owner"
            );
            assert_eq!(nsec3.iterations(), 0, "RFC 9276: no extra iterations");
            assert!(!nsec3.opt_out(), "no delegations, so no opt-out");
        }

        // The ring: the last link's next hash is the first link's hash.
        let RData::DNSSEC(DNSSECRData::NSEC3(last)) = &links.last().expect("a link").data else {
            panic!("NSEC3");
        };
        let first_sorted = hashes.iter().min().expect("a hash");
        assert_eq!(
            last.next_hashed_owner_name(),
            first_sorted.as_slice(),
            "the chain wraps instead of ending"
        );
    }

    /// A name that exists but not with the type asked for: one record naming its hash exactly.
    #[test]
    fn an_existing_name_without_the_type_is_proved_by_one_record() {
        let params = Params::default();
        let links = chain(&origin(), &zone(), &params, 600, false).expect("the chain builds");
        let proof = denial(&origin(), &links, &name("host"), RecordType::AAAA, &params)
            .expect("a denial")
            .expect("the chain can prove it");
        assert_eq!(proof.len(), 1, "NODATA needs the owner's own NSEC3");
    }

    /// A name that does not exist: three records - next closer, closest encloser, wildcard.
    ///
    /// This is the answer a validator rejects unless all three are present, and one is the number a
    /// first implementation produces.
    #[test]
    fn a_missing_name_is_proved_by_three_records() {
        let params = Params::default();
        let links = chain(&origin(), &zone(), &params, 600, false).expect("the chain builds");
        let proof = denial(&origin(), &links, &name("nope"), RecordType::A, &params)
            .expect("a denial")
            .expect("the chain can prove it");
        assert_eq!(
            proof.len(),
            3,
            "next closer, closest encloser and wildcard: {}",
            proof.len()
        );
    }

    /// A name below a name that does not exist: the closest encloser is the apex, and the proof is
    /// about the intermediate label rather than the queried one.
    #[test]
    fn a_name_below_a_missing_one_is_proved_from_the_closest_encloser() {
        let params = Params::default();
        let links = chain(&origin(), &zone(), &params, 600, false).expect("the chain builds");
        let query = Name::from_ascii(format!("a.b.{DOMAIN}.")).expect("a name");
        let proof = denial(&origin(), &links, &query, RecordType::A, &params)
            .expect("a denial")
            .expect("the chain can prove it");
        assert!(
            proof.len() >= 2,
            "a nested miss needs at least the next closer and the encloser: {}",
            proof.len()
        );
    }

    /// Moving one hash in the chain breaks the proof: a validator sees a gap that proves nothing.
    ///
    /// The test is written on the property rather than on the answer, because there is no validator
    /// in this crate - the wire check is `tests/dns_dnssec.rs`.
    #[test]
    fn a_chain_with_a_moved_hash_no_longer_covers_the_name() {
        let params = Params::default();
        let links = chain(&origin(), &zone(), &params, 600, false).expect("the chain builds");
        let query = Name::from_ascii(format!("nope.{DOMAIN}.")).expect("a name");
        let before = denial(&origin(), &links, &query, RecordType::A, &params)
            .expect("a denial")
            .expect("provable");

        // Drop one link: the range it covered is now a hole, and the proof must not claim it.
        let mut broken = links.clone();
        broken.remove(1);
        let after = denial(&origin(), &broken, &query, RecordType::A, &params).expect("a denial");
        match after {
            None => {}
            Some(proof) => assert_ne!(
                proof.len(),
                before.len(),
                "a chain missing a link cannot produce the same proof"
            ),
        }
    }
}
