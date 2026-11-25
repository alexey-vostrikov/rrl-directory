//! DNSSEC over the wire: the zone signed, and the signatures checked the way a validator checks them.
//!
//! The signature is `hickory`'s, and this file does not trust it because it is ours. Every `RRSIG`
//! made by the server is verified here with `hickory`'s own verifier, from the `DNSKEY` the zone
//! publishes over UDP - which is the exchange `delv` performs, done in the test so a change that
//! breaks signing fails in CI rather than at a client.
//!
//! What these tests are for, in the order the task named them:
//!
//! * an `RRSIG` covers every RRset, including the apex and the `DNSKEY` itself;
//! * the *key tag* in the signature names the key that signed it - a wrong tag gives a valid
//!   signature nobody can find, which is the failure no validator reports as a signature problem;
//! * the RRSIG's TTL equals the TTL of what it covers, and its `Original TTL` equals the RRset's;
//! * the inception is in the past and the expiration in the future, so a validator with a slow clock
//!   does not reject a fresh signature;
//! * a mutation - one octet of the RDATA changed - fails to verify.
#![cfg(feature = "dns")]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use hickory_server::proto::dnssec::Verifier;
use hickory_server::proto::dnssec::rdata::{DNSKEY, DNSSECRData, RRSIG};
use hickory_server::proto::op::{Message, MessageType, OpCode, Query};
use hickory_server::proto::rr::rdata::A;
use hickory_server::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_server::zone_handler::ZoneHandler as _;
use rrl_directory::dns::config::Settings;
use rrl_directory::dns::dnssec::{DnssecConfig, KeyConfig, Signers};
use rrl_directory::dns::serve::{Answering, InMemory, catalog_with, listen};

const DOMAIN: &str = "ad.example.com";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
}

/// A copy of a fixture that only this process can read.
///
/// A git checkout cannot carry a file mode - the index stores 644 or 755 and nothing else - so the
/// fixture in the repository arrives readable by everybody, which is exactly what the loader refuses.
/// The copy is what makes the check testable rather than a CI failure, and it keeps the production
/// rule strict: a real signing key on a real host is `0600` or the server will not start.
fn key_file(fixture: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = std::env::temp_dir().join(format!("rrl-dnssec-keys-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a temporary directory");
    let target = directory.join(fixture);
    if !target.exists() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/keys")
            .join(fixture);
        std::fs::copy(&source, &target).expect("the fixture is committed");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("the mode can be set");
    }
    target
}

/// The P-256 key committed beside this test, as PKCS#8 DER.
///
/// A test key, and it says so in its name: it signs nothing outside this suite. Generating one per
/// run would be slower and would make a failure impossible to reproduce; a key in the repository is
/// the same choice any other fixture makes.
///
/// How it was made, because the format is not the obvious one:
///
/// ```text
/// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform PEM \
///   | openssl pkcs8 -topk8 -nocrypt -outform DER -out rrl-dnssec-test-p256.der
/// ```
///
/// `genpkey -outform DER` on its own writes a **SEC1** `ECPrivateKey`, which `ring` refuses with
/// `InvalidEncoding` - measured. The `pkcs8 -topk8` pass is what puts the `AlgorithmIdentifier` in
/// front and makes it the format the documentation promises.
fn key_path() -> std::path::PathBuf {
    key_file("rrl-dnssec-test-p256.der")
}

fn signers() -> Signers {
    Signers::new(
        &DnssecConfig {
            keys: vec![KeyConfig {
                algorithm: "ecdsa-p256-sha256".to_string(),
                file: key_path(),
            }],
            signature_days: None,
            // Positive answers only: the denials have their own test, and a chain here would make
            // every other assertion about coverage noisier for no gain.
            nsec3: None,
        },
        DOMAIN,
    )
    .expect("the test key loads")
}

/// A zone with an apex, a host and a service locator - the shapes a domain actually has.
fn records() -> Vec<Record> {
    // The apex is the zone name itself, which is `""` plus the domain without a leading dot -
    // `format!("{label}.{DOMAIN}.")` with an empty label builds `.ad.example.com.`, and hickory
    // refuses it as a malformed label. That refusal is the reason this is spelled out.
    let name = |label: &str| {
        let text = if label.is_empty() {
            format!("{DOMAIN}.")
        } else {
            format!("{label}.{DOMAIN}.")
        };
        Name::from_ascii(text).expect("a name")
    };
    vec![
        Record::from_rdata(
            name(""),
            3600,
            RData::A(A::from(Ipv4Addr::new(10, 0, 2, 5))),
        ),
        Record::from_rdata(
            name("dc1"),
            600,
            RData::A(A::from(Ipv4Addr::new(10, 0, 2, 5))),
        ),
        Record::from_rdata(
            name("host"),
            600,
            RData::A(A::from(Ipv4Addr::new(10, 0, 2, 10))),
        ),
    ]
}

/// The `RRSIG`s in a signed set, as `(covered name, covered type)`.
fn coverage(records: &[Record]) -> Vec<(String, RecordType)> {
    let mut covered: Vec<(String, RecordType)> = records
        .iter()
        .filter_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                Some((record.name.to_ascii(), rrsig.input().type_covered))
            }
            _ => None,
        })
        .collect();
    covered.sort();
    covered.dedup();
    covered
}

/// Every RRset is signed, the apex and the `DNSKEY` included.
///
/// A validator that gets an unsigned RRset in an otherwise signed zone treats the whole answer as
/// bogus, so "which RRsets are covered" is the first question, not a detail.
#[test]
fn every_rrset_is_signed_including_the_key_itself() {
    let signed = signers().sign(&records(), now()).expect("the zone signs");

    // The key is published, and it is signed: `DNSKEY` is an RRset like any other.
    let dnskey = signed
        .iter()
        .find(|record| record.record_type() == RecordType::DNSKEY)
        .expect("the zone publishes its DNSKEY");
    assert_eq!(dnskey.name.to_ascii(), format!("{DOMAIN}."));

    let covered = coverage(&signed);
    for (label, rtype) in [
        (format!("{DOMAIN}."), RecordType::A),
        (format!("{DOMAIN}."), RecordType::DNSKEY),
        (format!("dc1.{DOMAIN}."), RecordType::A),
        (format!("host.{DOMAIN}."), RecordType::A),
    ] {
        assert!(
            covered.contains(&(label.clone(), rtype)),
            "{label} {rtype} is not covered: {covered:?}"
        );
    }
}

/// The signature verifies, and it verifies against the key the tag in it names.
///
/// This is the whole test: `hickory`'s verifier over `hickory`'s signer, over the records the server
/// would put on the wire. A wrong key tag produces a signature that is valid and that no validator
/// can attribute, which is why the tag is looked up by value here rather than trusted.
#[test]
fn a_signature_verifies_against_the_key_its_tag_names() {
    let signed = signers().sign(&records(), now()).expect("the zone signs");

    let dnskey = signed
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(key)) => Some(key.clone()),
            _ => None,
        })
        .expect("a DNSKEY");

    // The RRset of `dc1`: one A record.
    let rrset: Vec<&Record> = signed
        .iter()
        .filter(|record| {
            record.name.to_ascii() == format!("dc1.{DOMAIN}.")
                && record.record_type() == RecordType::A
        })
        .collect();
    assert_eq!(rrset.len(), 1, "one record at dc1");

    let rrsig = signed
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(sig))
                if record.name.to_ascii() == format!("dc1.{DOMAIN}.")
                    && sig.input().type_covered == RecordType::A =>
            {
                Some(sig.clone())
            }
            _ => None,
        })
        .expect("dc1 A is signed");

    // The tag in the RRSIG has to be the tag of the key that signed it.
    assert_eq!(
        rrsig.input().key_tag,
        dnskey
            .calculate_key_tag()
            .expect("the tag of the published key"),
        "the RRSIG names the key that signed it"
    );

    // `impl Verifier for DNSKEY`: the key verifies with the same code a validator runs.
    let verified = dnskey.verify_rrsig(
        &Name::from_ascii(format!("dc1.{DOMAIN}.")).expect("a name"),
        DNSClass::IN,
        &rrsig,
        rrset.iter().copied(),
    );
    assert!(
        verified.is_ok(),
        "the signature has to verify against the published key: {verified:?}"
    );
}

/// The RRSIG's TTL equals the TTL of what it covers, and its `Original TTL` equals the RRset's.
///
/// RFC 4034 §3 for the first, RFC 4035 §5.3.3 for the second: a validator reconstructs the signed
/// data from the *original* TTL, and a mismatch makes every signature in the zone fail at once.
#[test]
fn a_signature_carries_the_ttl_of_what_it_covers() {
    let signed = signers().sign(&records(), now()).expect("the zone signs");

    for record in &signed {
        let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data else {
            continue;
        };
        // The covered record, from the same set.
        let covered = signed
            .iter()
            .find(|candidate| {
                candidate.name == record.name
                    && candidate.record_type() == rrsig.input().type_covered
            })
            .expect("every RRSIG covers a record in the answer");
        assert_eq!(
            record.ttl, covered.ttl,
            "an RRSIG lives as long as the RRset it covers"
        );
        assert_eq!(
            rrsig.input().original_ttl,
            covered.ttl,
            "the original TTL is the RRset's, not the answer's"
        );
    }
}

/// The validity window: inception in the past, expiration after the signature was made.
///
/// A signature whose inception is `now` is rejected by any validator whose clock is a second behind,
/// which is most of them - so the inception is backdated, and this pins it.
#[test]
fn the_window_starts_in_the_past_and_ends_in_the_future() {
    let at = now();
    let signed = signers().sign(&records(), at).expect("the zone signs");

    let rrsig = signed
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Some(sig.clone()),
            _ => None,
        })
        .expect("something is signed");

    let inception = rrsig.input().sig_inception.get();
    let expiration = rrsig.input().sig_expiration.get();
    let at = at as u32;

    assert!(
        inception < at,
        "the inception is backdated: {inception} vs now {at}"
    );
    assert!(
        expiration > at,
        "the signature is still valid: {expiration} vs now {at}"
    );
    // Thirty days by default. `RRSIG::from_rrset` takes the expiration as `inception + duration`,
    // so the window is the duration exactly - the backdating moves both ends, it does not lengthen
    // the signature's life.
    assert_eq!(
        expiration - inception,
        30 * 24 * 3600,
        "thirty days, counted from the backdated inception"
    );
}

/// One octet changed in the RDATA breaks the signature, which is the property DNSSEC exists for.
///
/// This is the mutation the task names, made where it matters: in the record, not in the signature.
#[test]
fn a_record_changed_after_signing_does_not_verify() {
    let at = now();
    let signed = signers().sign(&records(), at).expect("the zone signs");

    let dnskey = signed
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(key)) => Some(key.clone()),
            _ => None,
        })
        .expect("a DNSKEY");
    let rrsig: RRSIG = signed
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(sig))
                if record.name.to_ascii() == format!("host.{DOMAIN}.") =>
            {
                Some(sig.clone())
            }
            _ => None,
        })
        .expect("host is signed");

    let tampered = Record::from_rdata(
        Name::from_ascii(format!("host.{DOMAIN}.")).expect("a name"),
        600,
        RData::A(A::from(Ipv4Addr::new(10, 0, 2, 11))),
    );

    let verified = dnskey.verify_rrsig(
        &Name::from_ascii(format!("host.{DOMAIN}.")).expect("a name"),
        DNSClass::IN,
        &rrsig,
        std::iter::once(&tampered),
    );
    assert!(
        verified.is_err(),
        "a changed address must not verify: {verified:?}"
    );
}

/// The fields a validator checks are the fields the signature covers.
///
/// `TBS` is the RRSIG's own RDATA followed by the RRset, so changing any of the three fields the task
/// names - the key tag, the label count, the expiration - makes the signature fail. One test per
/// field, with the same signature bytes: if a mutation verified, the field would not be authenticated
/// and the task's "a validator must catch it" would be a claim rather than a fact.
#[test]
fn a_signature_does_not_verify_if_the_tag_the_labels_or_the_expiration_is_changed() {
    let signed = signers().sign(&records(), now()).expect("the zone signs");
    let dnskey = signed
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(key)) => Some(key.clone()),
            _ => None,
        })
        .expect("a DNSKEY");
    // The signature and the record it covers, which are two different records: the first version of
    // this test verified the RRSIG against itself and failed on the baseline.
    let host = format!("host.{DOMAIN}.");
    let rrsig = signed
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(sig)) if record.name.to_ascii() == host => {
                Some(sig.clone())
            }
            _ => None,
        })
        .expect("host is signed");
    let covered = signed
        .iter()
        .find(|record| record.name.to_ascii() == host && record.record_type() == RecordType::A)
        .expect("host has an address")
        .clone();

    let name = Name::from_ascii(format!("host.{DOMAIN}.")).expect("a name");
    let verify =
        |sig: &RRSIG| dnskey.verify_rrsig(&name, DNSClass::IN, sig, std::iter::once(&covered));
    assert!(verify(&rrsig).is_ok(), "the signature as made verifies");

    // The three mutations, each rebuilding the RRSIG's input with the signature bytes untouched.
    let mutate = |change: &dyn Fn(&mut hickory_server::proto::dnssec::rdata::SigInput)| {
        let mut input = rrsig.input().clone();
        change(&mut input);
        RRSIG::from_sig(input, rrsig.sig().to_vec())
    };

    let wrong_tag = mutate(&|input| input.key_tag = input.key_tag.wrapping_add(1));
    assert!(
        verify(&wrong_tag).is_err(),
        "a different key tag must not verify - a signature with a wrong tag is valid and unfindable"
    );

    let wrong_labels = mutate(&|input| input.num_labels = input.num_labels.wrapping_add(1));
    assert!(
        verify(&wrong_labels).is_err(),
        "the label count is part of what was signed"
    );

    let expired = mutate(&|input| {
        input.sig_expiration =
            hickory_server::proto::rr::SerialNumber::new(input.sig_inception.get().wrapping_sub(1))
    });
    assert!(
        verify(&expired).is_err(),
        "an expiration before the inception is not the signature that was made"
    );
}

/// With `NSEC3` on, the denial chain is signed too, and its signatures verify.
///
/// The chain is built twice - once before signing and once when a denial is assembled - and a bitmap
/// that differed between the two made the second chain a different RRset from the one that had been
/// signed, so every `RRSIG` over `NSEC3` failed to verify while every other signature passed. That is
/// the failure this test exists to catch, and it is why the TTL/type rules are asserted on the
/// records that a denial would actually carry.
#[test]
fn the_nsec3_chain_is_signed_and_its_signatures_verify() {
    let signers = Signers::new(
        &DnssecConfig {
            keys: vec![KeyConfig {
                algorithm: "ecdsa-p256-sha256".to_string(),
                file: key_path(),
            }],
            signature_days: None,
            nsec3: Some(rrl_directory::dns::dnssec::Nsec3Config {
                salt: Some("aGVsbG8=".to_string()),
                iterations: Some(0),
            }),
        },
        DOMAIN,
    )
    .expect("the key loads");

    let signed = signers.sign(&records(), now()).expect("the zone signs");
    assert!(
        signed
            .iter()
            .any(|record| record.record_type() == RecordType::NSEC3PARAM),
        "the zone publishes its hash parameters"
    );

    let dnskey = signed
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(key)) => Some(key.clone()),
            _ => None,
        })
        .expect("a DNSKEY");

    let chain: Vec<&Record> = signed
        .iter()
        .filter(|record| record.record_type() == RecordType::NSEC3)
        .collect();
    // Three names in this zone: the apex (with its `DNSKEY`), `dc1` and `host`. One link each.
    assert_eq!(chain.len(), 3, "one link per name: {}", chain.len());

    for link in &chain {
        let owner = link.name.to_ascii();
        assert!(
            owner.to_ascii_uppercase().starts_with(
                &owner
                    .split('.')
                    .next()
                    .expect("a label")
                    .to_ascii_uppercase()
            ),
            "the owner is its hash label"
        );
        let rrsig = signed
            .iter()
            .find_map(|candidate| match &candidate.data {
                RData::DNSSEC(DNSSECRData::RRSIG(sig))
                    if candidate.name.to_ascii() == owner
                        && sig.input().type_covered == RecordType::NSEC3 =>
                {
                    Some(sig.clone())
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("{owner} NSEC3 is unsigned"));

        dnskey
            .verify_rrsig(&link.name, DNSClass::IN, &rrsig, std::iter::once(*link))
            .unwrap_or_else(|err| panic!("the NSEC3 signature at {owner} must verify: {err}"));
    }
}

/// All three algorithms this build signs with: 13, 14 and 15.
///
/// The task's acceptance names them, and a build that quietly signs with one of the three is a build
/// whose "algorithms 13/14/15" is a claim about the enum rather than about the wire. Each is loaded
/// from its own fixture, signed with, and verified by `hickory`'s verifier over the records.
#[test]
fn every_algorithm_this_build_offers_signs_and_verifies() {
    for (name, fixture, expected) in [
        ("13", "rrl-dnssec-test-p256.der", 13u8),
        ("14", "rrl-dnssec-test-p384.der", 14),
        ("15", "rrl-dnssec-test-ed25519.der", 15),
    ] {
        let signers = Signers::new(
            &DnssecConfig {
                keys: vec![KeyConfig {
                    algorithm: name.to_string(),
                    file: key_file(fixture),
                }],
                signature_days: None,
                nsec3: None,
            },
            DOMAIN,
        )
        .unwrap_or_else(|err| panic!("algorithm {name} has to load: {err}"));

        let signed = signers
            .sign(&records(), now())
            .unwrap_or_else(|err| panic!("algorithm {name} has to sign: {err}"));

        let dnskey = signed
            .iter()
            .find_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::DNSKEY(key)) => Some(key.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("algorithm {name} publishes a DNSKEY"));
        assert_eq!(
            u8::from(dnskey.algorithm()),
            expected,
            "the published key names algorithm {expected}"
        );

        let host = format!("host.{DOMAIN}.");
        let rrsig = signed
            .iter()
            .find_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::RRSIG(sig))
                    if record.name.to_ascii() == host
                        && sig.input().type_covered == RecordType::A =>
                {
                    Some(sig.clone())
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("algorithm {name} signs host's A"));
        let covered = signed
            .iter()
            .find(|record| record.name.to_ascii() == host && record.record_type() == RecordType::A)
            .expect("the record the signature covers")
            .clone();

        dnskey
            .verify_rrsig(
                &Name::from_ascii(host.clone()).expect("a name"),
                DNSClass::IN,
                &rrsig,
                std::iter::once(&covered),
            )
            .unwrap_or_else(|err| panic!("algorithm {name} must verify: {err}"));
    }
}

/// Two keys sign, and both signatures verify: that is what a rollover looks like from outside.
#[test]
fn two_keys_both_sign_during_a_rollover() {
    let config = DnssecConfig {
        keys: vec![
            KeyConfig {
                algorithm: "ecdsa-p256-sha256".to_string(),
                file: key_path(),
            },
            KeyConfig {
                algorithm: "ecdsa-p256-sha256".to_string(),
                file: key_path(),
            },
        ],
        signature_days: Some(7),
        nsec3: None,
    };
    // The same file twice: two signers over one key, which is the shape a rollover has (two keys)
    // without needing a second fixture. The tags collide and that is visible below.
    let signers = Signers::new(&config, DOMAIN).expect("the keys load");
    assert_eq!(signers.describe().len(), 2, "two keys, both reported");

    let signed = signers.sign(&records(), now()).expect("the zone signs");
    let keys = signed
        .iter()
        .filter(|record| record.record_type() == RecordType::DNSKEY)
        .count();
    assert_eq!(keys, 2, "both keys are published at the apex");

    // Per RRset there are as many signatures as keys.
    let host_signatures = signed
        .iter()
        .filter(|record| {
            record.name.to_ascii() == format!("host.{DOMAIN}.")
                && record.record_type() == RecordType::RRSIG
        })
        .count();
    assert_eq!(host_signatures, 2, "one signature per key, per RRset");
}

/// A server with no keys serves the zone unsigned, and says so by having no DNSKEY at all.
#[test]
fn without_keys_the_zone_is_unsigned() {
    let signers = Signers::none();
    let signed = signers.sign(&records(), now()).expect("nothing to sign");
    assert_eq!(signed.len(), records().len(), "no RRSIG, no DNSKEY");
    assert!(
        signed
            .iter()
            .all(|record| record.record_type() != RecordType::DNSKEY),
        "an unsigned zone has no key to publish"
    );
}

/// The whole path over the wire: a signed zone served on a real socket, the `DNSKEY` asked for by
/// query, and the answer's `RRSIG` verified against it.
///
/// This is what `delv` does, and doing it here means a change that stops signing fails in CI.
#[tokio::test]
async fn a_running_listener_serves_a_verifiable_signature() {
    let signers = std::sync::Arc::new(signers());
    let signed = signers.sign(&records(), now()).expect("the zone signs");

    // The zone handler is given the signed records directly: `InMemory` answers from a list, and
    // what is being checked here is that an `RRSIG` and a `DNSKEY` survive the wire, not where they
    // were assembled.
    // With the root label: a zone filed under a relative name is one `Answering::is_ours` never
    // matches, and the answer is `REFUSED` - measured, and the reason this is spelled out.
    let zone = InMemory::new(&format!("{DOMAIN}."), signed).expect("a zone");
    let ours = zone.origin().clone();
    let catalog = catalog_with(std::sync::Arc::new(zone));
    let settings = Settings {
        bind: "127.0.0.1:0".parse().expect("an address"),
        dns_domain: DOMAIN.to_string(),
        address: Ipv4Addr::new(10, 0, 2, 5),
        forward_default: Vec::new(),
        forward_zones: std::collections::BTreeMap::new(),
        zones_dir: std::path::PathBuf::from("/dns"),
        keys: Vec::new(),
        dnssec: Default::default(),
    };
    let running = listen(
        "127.0.0.1:0".parse().expect("an address"),
        Answering::new(catalog, ours, settings),
    )
    .await
    .expect("the listener started");

    let (dnskey, rrsig, covered) = ask_dnssec(running.bind).await;
    drop(running);

    let verified = dnskey.verify_rrsig(
        &Name::from_ascii(format!("host.{DOMAIN}.")).expect("a name"),
        DNSClass::IN,
        &rrsig,
        std::iter::once(&covered),
    );
    assert!(
        verified.is_ok(),
        "the signature that came over the wire verifies: {verified:?}"
    );
}

/// Asks for `host.<domain> A` and returns the `DNSKEY`, the `RRSIG` covering it and the record.
async fn ask_dnssec(server: SocketAddr) -> (DNSKEY, RRSIG, Record) {
    let ask = |raw: Vec<u8>| async move {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a socket");
        socket.send_to(&raw, server).await.expect("sent");
        let mut buffer = [0u8; 4096];
        let (read, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.recv_from(&mut buffer),
        )
        .await
        .expect("an answer arrives")
        .expect("recv");
        Message::from_vec(&buffer[..read]).expect("the answer parses")
    };

    let mut host = Message::new(1, MessageType::Query, OpCode::Query);
    host.add_query(Query::query(
        Name::from_ascii(format!("host.{DOMAIN}.")).expect("a name"),
        RecordType::A,
    ));
    // `DO` is what asks for the signatures, and it travels in the EDNS OPT record - not in the
    // header. Without it an authoritative server answers with the records alone.
    let mut edns = hickory_server::proto::op::Edns::new();
    edns.set_version(0);
    edns.set_max_payload(1232);
    edns.set_dnssec_ok(true);
    host.set_edns(edns);

    let answer = ask(host.to_vec().expect("encodes")).await;
    assert_eq!(
        answer.metadata.response_code,
        hickory_server::proto::op::ResponseCode::NoError
    );
    let record = answer
        .answers
        .iter()
        .find(|record| record.record_type() == RecordType::A)
        .expect("the A record")
        .clone();
    let rrsig = answer
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Some(sig.clone()),
            _ => None,
        })
        .expect("the RRSIG came with it");

    let mut key = Message::new(2, MessageType::Query, OpCode::Query);
    key.add_query(Query::query(
        Name::from_ascii(format!("{DOMAIN}.")).expect("a name"),
        RecordType::DNSKEY,
    ));
    let answer = ask(key.to_vec().expect("encodes")).await;
    let dnskey = answer
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => Some(dnskey.clone()),
            _ => None,
        })
        .expect("the DNSKEY");

    (dnskey, rrsig, record)
}
