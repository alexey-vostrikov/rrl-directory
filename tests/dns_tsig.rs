//! TSIG over the wire: what this server answers a request that carries a signature.
//!
//! The layout a signature covers - message with a stub TSIG, `arcount` decremented, and for a
//! response the request's MAC prepended - is `hickory`'s, and a second implementation of it here
//! would be a second opinion about which octets were signed. So the unit under test is the part that
//! is ours: which key, which error, and whether the answer is signed the way RFC 8945 requires.
//!
//! Every case travels over UDP to a real listener with real keys, because the questions these tests
//! answer are about the exchange and not about a function: does a signed query get a signed answer,
//! does an unknown key get `BADKEY` with a bare TSIG, does a wrong MAC get `BADSIG`, does a clock
//! three hours off get a **signed** `BADTIME`, and does a signed update get refused without ever
//! reaching a zone.
#![cfg(feature = "dns")]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use hickory_server::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_server::proto::rr::rdata::A;
use hickory_server::proto::rr::rdata::tsig::{TsigAlgorithm, TsigError};
use hickory_server::proto::rr::{Name, RData, Record, RecordType, TSigVerifier, TSigner};
use hickory_server::zone_handler::ZoneHandler as _;
use rrl_directory::dns::config::{Settings, TsigKey};
use rrl_directory::dns::serve::{Answering, InMemory, catalog_with, listen};
use rrl_directory::dns::tsig::Keys;

const DOMAIN: &str = "ad.example.com";
const KEY: &str = "app-acme.";
/// Not a real secret: 16 octets, and every test that needs a different key derives another one.
const SECRET: &[u8] = b"0123456789abcdef";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
}

fn signer(secret: &[u8]) -> TSigner {
    TSigner::new(
        secret.to_vec(),
        TsigAlgorithm::HmacSha256,
        Name::from_ascii(KEY).expect("a key name"),
        300,
    )
    .expect("a signer")
}

fn settings() -> Settings {
    Settings {
        bind: "127.0.0.1:0".parse().expect("an address"),
        dns_domain: DOMAIN.to_string(),
        address: Ipv4Addr::new(10, 0, 0, 5),
        forward_default: Vec::new(),
        forward_zones: std::collections::BTreeMap::new(),
        zones_dir: std::path::PathBuf::from("/dns"),
        // No signing key: these suites are about TSIG and the forwarder.
        dnssec: Default::default(),
        keys: vec![TsigKey {
            name: Name::from_ascii(KEY).expect("a key name"),
            secret: SECRET.to_vec(),
            algorithm: TsigAlgorithm::HmacSha256,
            fudge: 300,
        }],
    }
}

/// The listener, on a kernel-chosen port, over a zone holding one `A`.
async fn start() -> (SocketAddr, rrl_directory::dns::serve::Running) {
    let name = Name::from_ascii(format!("dc.{DOMAIN}.")).expect("a name");
    let record = Record::from_rdata(name, 60, RData::A(A::from(Ipv4Addr::new(10, 0, 0, 5))));
    // With the root label, or the zone is filed under a relative name that no query reaches.
    let zone = InMemory::new(&format!("{DOMAIN}."), vec![record])
        .expect("a zone")
        .with_keys(std::sync::Arc::new(
            Keys::new(&settings().keys).expect("the key loads"),
        ));
    let ours = zone.origin().clone();
    let catalog = catalog_with(std::sync::Arc::new(zone));
    let running = listen(
        "127.0.0.1:0".parse().expect("an address"),
        Answering::new(catalog, ours, settings()),
    )
    .await
    .expect("the listener started");
    (running.bind, running)
}

/// A query for `dc.<domain> A`, signed with `key` at `time`.
///
/// Returns the bytes to put on the wire and the verifier for the answer, which is `None` when the
/// message goes out unsigned.
fn query(key: Option<&TSigner>, time: u64) -> (Vec<u8>, Option<TSigVerifier>) {
    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(
        Name::from_ascii(format!("dc.{DOMAIN}.")).expect("a name"),
        RecordType::A,
    ));
    let mut verifier = None;
    if let Some(key) = key {
        let (tsig, seen) = key.sign_message(&message, time).expect("the message signs");
        message.set_signature(tsig);
        verifier = seen;
    }
    (message.to_vec().expect("the message encodes"), verifier)
}

/// An update adding one `A`, signed with `key`.
fn update(key: Option<&TSigner>, time: u64) -> Vec<u8> {
    let mut message = Message::new(0x4321, MessageType::Query, OpCode::Update);
    message.add_query(Query::query(
        Name::from_ascii(format!("{DOMAIN}.")).expect("a name"),
        RecordType::SOA,
    ));
    // In an update the authority section carries the updates themselves: the question names the
    // zone, the answer section the preconditions, and the authority section what to change.
    message.add_authority(Record::from_rdata(
        Name::from_ascii(format!("host.{DOMAIN}.")).expect("a name"),
        60,
        RData::A(A::from(Ipv4Addr::new(10, 0, 0, 9))),
    ));
    if let Some(key) = key {
        let (tsig, _) = key.sign_message(&message, time).expect("the message signs");
        message.set_signature(tsig);
    }
    message.to_vec().expect("the message encodes")
}

/// The raw answer bytes and the parsed message.
///
/// Both: the MAC covers the octets that travelled, and re-encoding a parsed message is not the same
/// byte stream - name compression decides where the pointers go, so a verified re-encoding would be
/// a test of hickory's encoder rather than of what this server sent.
async fn ask(server: SocketAddr, bytes: &[u8]) -> (Vec<u8>, Message) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a client socket");
    socket.send_to(bytes, server).await.expect("sent");
    let mut buffer = [0u8; 4096];
    let (read, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut buffer),
    )
    .await
    .expect("an answer arrives")
    .expect("recv");
    let raw = buffer[..read].to_vec();
    let message = Message::from_vec(&raw).expect("the answer parses");
    (raw, message)
}

/// A signed question is answered, and the answer carries a signature that verifies against it.
///
/// RFC 8945 §5.3: a server that accepts a signed request signs the response with the same key. An
/// unsigned answer to a signed question is a protocol error the client reports as a timeout, which
/// is why this is the first test rather than a detail.
#[tokio::test]
async fn a_signed_question_gets_a_signed_answer() {
    let (server, _running) = start().await;
    let key = signer(SECRET);
    let (bytes, mut verifier) = query(Some(&key), now());

    let (raw, answer) = ask(server, &bytes).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    assert!(!answer.answers.is_empty(), "the A record is answered");
    assert!(
        answer.signature().is_some(),
        "an answer to a signed question is signed"
    );

    // The MAC, not just the presence of a TSIG record: a signature that does not verify is a client
    // failure with no clue in it, and the verifier is the same code a client runs.
    verifier
        .as_mut()
        .expect("the request was signed")
        .verify(&raw)
        .expect("the answer's MAC verifies");
}

/// An unsigned question is answered unsigned - every ordinary resolver sends this.
#[tokio::test]
async fn an_unsigned_question_is_answered_without_a_signature() {
    let (server, _running) = start().await;
    let (bytes, _) = query(None, now());

    let (_raw, answer) = ask(server, &bytes).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    assert!(!answer.answers.is_empty());
    assert!(
        answer.signature().is_none(),
        "nothing was signed, so nothing is signed back"
    );
}

/// A key this server does not have: `NOTAUTH` and `BADKEY`, in a TSIG record with no MAC.
///
/// `BADKEY` cannot be signed - the key is the thing that is missing - and RFC 8945 §5.2 says the TSIG
/// record goes back anyway, carrying the error.
#[tokio::test]
async fn an_unknown_key_is_refused_as_badkey() {
    let (server, _running) = start().await;
    let stranger = TSigner::new(
        SECRET.to_vec(),
        TsigAlgorithm::HmacSha256,
        Name::from_ascii("not-ours.").expect("a name"),
        300,
    )
    .expect("a signer");
    let (bytes, _) = query(Some(&stranger), now());

    let (_raw, answer) = ask(server, &bytes).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NotAuth);
    let signature = answer.signature().expect("the refusal carries a TSIG");
    assert_eq!(signature.data.error, Some(TsigError::BadKey));
    assert!(
        signature.data.mac.is_empty(),
        "a key that is not known cannot produce a MAC"
    );
}

/// A MAC that does not verify: `NOTAUTH` and `BADSIG`.
///
/// Signed with the right key name and a different secret, which is the failure a wrong shared key
/// produces - the one an operator actually hits.
#[tokio::test]
async fn a_mac_that_does_not_verify_is_refused_as_badsig() {
    let (server, _running) = start().await;
    let (bytes, _) = query(Some(&signer(b"fedcba9876543210")), now());

    let (_raw, answer) = ask(server, &bytes).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NotAuth);
    let signature = answer.signature().expect("the refusal carries a TSIG");
    assert_eq!(signature.data.error, Some(TsigError::BadSig));
    assert!(
        signature.data.mac.is_empty(),
        "nothing is signed with a key that just failed to prove itself"
    );
}

/// A clock three hours off: `NOTAUTH` and `BADTIME`, and this refusal **is** signed.
///
/// RFC 8945 §5.2 again: the client has to be able to trust the time in the answer before it can
/// decide its own clock is what needs fixing, so this one goes back with a real MAC.
#[tokio::test]
async fn a_clock_outside_the_window_is_refused_as_badtime_and_signed() {
    let (server, _running) = start().await;
    let key = signer(SECRET);
    let (bytes, _) = query(Some(&key), now() - 3 * 3600);

    let (_raw, answer) = ask(server, &bytes).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NotAuth);
    let signature = answer.signature().expect("the refusal carries a TSIG");
    assert_eq!(signature.data.error, Some(TsigError::BadTime));
    assert!(
        !signature.data.mac.is_empty(),
        "BADTIME is signed with the same key, or the client cannot trust the time it carries"
    );
}

/// A signed update: the key verifies, and the update is still refused - updates are RRL-2.25.8.
///
/// The order matters and this is what pins it: `REFUSED` says "this server does not take updates",
/// `NOTAUTH` would say "your key is wrong", and a client that got the second would stop fixing a key
/// that is fine.
#[tokio::test]
async fn a_signed_update_is_refused_and_the_refusal_is_signed() {
    let (server, _running) = start().await;
    let bytes = update(Some(&signer(SECRET)), now());

    let (_raw, answer) = ask(server, &bytes).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::Refused);
    assert!(
        answer.signature().is_some(),
        "the request proved its key, so the answer is signed with it"
    );
}

/// An update with no signature at all: refused, and nothing is invented to sign it with.
#[tokio::test]
async fn an_unsigned_update_is_refused() {
    let (server, _running) = start().await;
    let bytes = update(None, now());

    let (_raw, answer) = ask(server, &bytes).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::Refused);
    assert!(answer.signature().is_none());
}
