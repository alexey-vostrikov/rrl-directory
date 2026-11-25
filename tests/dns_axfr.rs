//! Zone transfer: who is allowed to take a copy of the whole zone, and what they get.
//!
//! The policy is decided by address, by key, or by both, and the test travels over a real TCP socket
//! to a real listener - because the thing under test is exactly the thing a unit test cannot reach:
//! the source address of the connection. A test that called the decision function directly would pass
//! while the handler read the wrong field, and reading the wrong field is how an allowlist for
//! `10.0.0.0/8` becomes an allowlist for everybody.
//!
//! The address is varied by binding the client side: the whole of `127.0.0.0/8` is loopback, so a
//! connection from `127.0.0.2` is a connection from somewhere the server can see and refuse.
#![cfg(feature = "dns")]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use hickory_server::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_server::proto::rr::rdata::A;
use hickory_server::proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_server::proto::rr::{Name, RData, Record, RecordType, TSigner};
use hickory_server::zone_handler::ZoneHandler as _;
use rrl_directory::dns::axfr::Allow;
use rrl_directory::dns::config::{AxfrAllowConfig, Settings, TsigKey};
use rrl_directory::dns::serve::{Answering, InMemory, catalog_with, listen};
use rrl_directory::dns::tsig::Keys;

const DOMAIN: &str = "ad.example.com";
const KEY: &str = "zone-transfer.";
const SECRET: &[u8] = b"0123456789abcdef";

fn entry(source: Option<&str>, key: Option<&str>) -> AxfrAllowConfig {
    AxfrAllowConfig {
        source: source.map(str::to_string),
        key: key.map(str::to_string),
    }
}

fn settings() -> Settings {
    Settings {
        bind: "127.0.0.1:0".parse().expect("an address"),
        dns_domain: DOMAIN.to_string(),
        address: Ipv4Addr::new(10, 0, 2, 5),
        forward_default: Vec::new(),
        forward_zones: std::collections::BTreeMap::new(),
        zones_dir: std::path::PathBuf::from("/dns"),
        keys: vec![TsigKey {
            name: Name::from_ascii(KEY).expect("a key name"),
            secret: SECRET.to_vec(),
            algorithm: TsigAlgorithm::HmacSha256,
            fudge: 300,
        }],
        dnssec: Default::default(),
        axfr: Default::default(),
    }
}

/// The zone the transfer copies: an `SOA` and an `A`, which is the smallest thing that is a zone.
fn zone() -> InMemory {
    let soa = Record::from_rdata(
        Name::from_ascii(format!("{DOMAIN}.")).expect("a name"),
        600,
        RData::SOA(hickory_server::proto::rr::rdata::SOA::new(
            Name::from_ascii(format!("dc1.{DOMAIN}.")).expect("a name"),
            Name::from_ascii(format!("hostmaster.{DOMAIN}.")).expect("a name"),
            2026112501,
            900,
            600,
            86_400,
            300,
        )),
    );
    let a = Record::from_rdata(
        Name::from_ascii(format!("dc1.{DOMAIN}.")).expect("a name"),
        600,
        RData::A(A::from(Ipv4Addr::new(192, 0, 2, 5))),
    );
    InMemory::new(&format!("{DOMAIN}."), vec![soa, a])
        .expect("a zone")
        .with_keys(std::sync::Arc::new(
            Keys::new(&settings().keys).expect("the key loads"),
        ))
}

/// A listener over [`zone`], permitting the clients `entries` name.
async fn start(entries: &[AxfrAllowConfig]) -> (SocketAddr, rrl_directory::dns::serve::Running) {
    let allow =
        Allow::resolve(entries, &settings().keys, |key| &key.name).expect("the entries resolve");
    let handler = zone().with_axfr(std::sync::Arc::new(allow));
    let ours = handler.origin().clone();
    let catalog = catalog_with(std::sync::Arc::new(handler));
    let running = listen(
        "127.0.0.1:0".parse().expect("an address"),
        Answering::new(catalog, ours, settings()),
    )
    .await
    .expect("the listener started");
    (running.bind, running)
}

/// An `AXFR` request for the zone, signed with `signer` when one is given.
fn request(id: u16, signer: Option<&TSigner>, time: u64) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(
        Name::from_ascii(format!("{DOMAIN}.")).expect("a name"),
        RecordType::AXFR,
    ));
    if let Some(signer) = signer {
        let (tsig, _) = signer
            .sign_message(&message, time)
            .expect("the request signs");
        message.set_signature(tsig);
    }
    message.to_vec().expect("the request encodes")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
}

fn signer_with(secret: &[u8]) -> TSigner {
    TSigner::new(
        secret.to_vec(),
        TsigAlgorithm::HmacSha256,
        Name::from_ascii(KEY).expect("a key name"),
        300,
    )
    .expect("a signer")
}

/// Every message of the transfer, read until the closing `SOA` or until the server stops answering.
///
/// `from` is the address the client side binds to, which is the whole point: the server decides on the
/// address it sees, and `127.0.0.2` is not `127.0.0.1` even though both are loopback.
fn transfer(bind: SocketAddr, from: IpAddr, payload: Vec<u8>) -> Vec<Message> {
    // `socket2` and not `std::net::TcpSocket`: this toolchain has no `TcpSocket`, and binding the
    // client side is the only way to arrive from an address the server can refuse.
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .expect("a socket");
    socket
        .bind(&SocketAddr::new(from, 0).into())
        .unwrap_or_else(|err| panic!("binding the client side to {from}: {err}"));
    socket
        .connect(&bind.into())
        .unwrap_or_else(|err| panic!("connecting to {bind} from {from}: {err}"));
    let mut stream: std::net::TcpStream = socket.into();

    let length = u16::try_from(payload.len()).expect("a message that fits a frame");
    stream
        .write_all(&length.to_be_bytes())
        .expect("the length prefix");
    stream.write_all(&payload).expect("the request");

    let mut messages = Vec::new();
    let mut soa = 0;
    // A transfer is several messages; the closing one carries the SOA again. Two SOAs is the end,
    // and a refusal or an error is one message.
    for _ in 0..16 {
        let mut header = [0u8; 2];
        if stream.read_exact(&mut header).is_err() {
            break;
        }
        let length = usize::from(u16::from_be_bytes(header));
        let mut body = vec![0u8; length];
        stream
            .read_exact(&mut body)
            .expect("a whole message, as its length promised");
        let message = Message::from_vec(&body).expect("the answer parses");
        let response = message.metadata.response_code;
        soa += message
            .answers
            .iter()
            .filter(|record| record.record_type() == RecordType::SOA)
            .count();
        messages.push(message);
        if response != ResponseCode::NoError || soa >= 2 {
            break;
        }
    }
    messages
}

/// Every record of the transfer, in the order the server sent them.
fn records(messages: &[Message]) -> Vec<Record> {
    messages
        .iter()
        .flat_map(|message| message.answers.iter().cloned())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transfer_from_a_permitted_range_arrives_whole() {
    let (bind, _running) = start(&[entry(Some("127.0.0.0/8"), None)]).await;
    let messages = transfer(
        bind,
        "127.0.0.1".parse().expect("an address"),
        request(1, None, now()),
    );

    assert_eq!(
        messages[0].metadata.response_code,
        ResponseCode::NoError,
        "a permitted client is answered"
    );
    let records = records(&messages);
    let soa = records
        .iter()
        .filter(|record| record.record_type() == RecordType::SOA)
        .count();
    assert_eq!(
        soa, 2,
        "RFC 5936 §2.2: the SOA opens and closes the transfer"
    );
    assert_eq!(
        records.first().map(Record::record_type),
        Some(RecordType::SOA),
        "the first record is the SOA"
    );
    assert_eq!(
        records.last().map(Record::record_type),
        Some(RecordType::SOA),
        "the last record is the SOA"
    );
    assert!(
        records
            .iter()
            .any(|record| record.record_type() == RecordType::A),
        "and the zone's own record is in the middle"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transfer_from_outside_the_range_is_refused() {
    // `127.0.0.1/32` and not `/8`: the whole point is that the neighbouring address is outside.
    let (bind, _running) = start(&[entry(Some("127.0.0.1/32"), None)]).await;
    let messages = transfer(
        bind,
        "127.0.0.2".parse().expect("an address"),
        request(2, None, now()),
    );
    assert_eq!(
        messages[0].metadata.response_code,
        ResponseCode::Refused,
        "127.0.0.2 is not 127.0.0.1, and the allowlist said one address"
    );

    // And the permitted one still works, so the refusal above was the policy and not a broken stand.
    let messages = transfer(
        bind,
        "127.0.0.1".parse().expect("an address"),
        request(3, None, now()),
    );
    assert_eq!(messages[0].metadata.response_code, ResponseCode::NoError);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_grant_needs_a_signature_and_accepts_the_right_one() {
    let (bind, _running) = start(&[entry(None, Some(KEY))]).await;
    let client: IpAddr = "127.0.0.1".parse().expect("an address");

    let refused = transfer(bind, client, request(4, None, now()));
    assert_eq!(
        refused[0].metadata.response_code,
        ResponseCode::Refused,
        "a key grant is about proof, and an unsigned request offers none"
    );

    let signed = transfer(bind, client, request(5, Some(&signer_with(SECRET)), now()));
    assert_eq!(
        signed[0].metadata.response_code,
        ResponseCode::NoError,
        "the key this server holds, proved, is enough"
    );
    assert!(
        signed[0].signature().is_some(),
        "and the answer is signed, which is how the client knows the transfer is the server's"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signature_that_does_not_verify_is_not_a_permission() {
    let (bind, _running) = start(&[entry(None, Some(KEY))]).await;
    // The right name, the wrong secret: the MAC cannot verify, and the answer is `NOTAUTH` rather
    // than `REFUSED` - the client has to be able to tell "your key is wrong" from "not for you".
    let wrong = signer_with(b"fedcba9876543210");
    let messages = transfer(
        bind,
        "127.0.0.1".parse().expect("an address"),
        request(6, Some(&wrong), now()),
    );
    assert_eq!(messages[0].metadata.response_code, ResponseCode::NotAuth);
    assert!(
        messages
            .iter()
            .flat_map(|message| message.answers.iter())
            .all(|record| record.record_type() != RecordType::A),
        "and nothing of the zone leaked"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_allowlist_refuses_everybody_including_the_right_key() {
    let (bind, _running) = start(&[]).await;
    let client: IpAddr = "127.0.0.1".parse().expect("an address");
    for (id, signer) in [(7, None), (8, Some(signer_with(SECRET)))] {
        let messages = transfer(bind, client, request(id, signer.as_ref(), now()));
        assert_eq!(
            messages[0].metadata.response_code,
            ResponseCode::Refused,
            "the default is deny, and a configured key does not change the default"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grant_naming_both_requires_both() {
    let (bind, _running) = start(&[entry(Some("127.0.0.1/32"), Some(KEY))]).await;
    let client: IpAddr = "127.0.0.1".parse().expect("an address");

    let unsigned = transfer(bind, client, request(9, None, now()));
    assert_eq!(unsigned[0].metadata.response_code, ResponseCode::Refused);

    let signed = transfer(bind, client, request(10, Some(&signer_with(SECRET)), now()));
    assert_eq!(signed[0].metadata.response_code, ResponseCode::NoError);

    // The same key from an address the entry does not name: the key is right and it is not enough.
    let elsewhere = transfer(
        bind,
        "127.0.0.2".parse().expect("an address"),
        request(11, Some(&signer_with(SECRET)), now()),
    );
    assert_eq!(
        elsewhere[0].metadata.response_code,
        ResponseCode::Refused,
        "a grant that names both means both"
    );
}
