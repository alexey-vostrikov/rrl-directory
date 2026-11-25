//! The forwarder by domain, over the wire: what a stand asks when a name is not ours.
//!
//! `src/dns/forward.rs` tests the exchange with one upstream, and `src/dns/config.rs` tests which
//! suffix wins. Neither tests the thing a stand actually does - start the listener with a suffix
//! table and ask it questions - which is what this file is for. Every query here travels over UDP to
//! a real listener, and every answer comes from a real upstream on a real socket, so the path under
//! test is the path a client's resolver takes.
//!
//! Four rules from the epic are what these assert, one per test group:
//!
//! * the zone this server holds is answered from here and **never** leaves, even when an upstream
//!   would answer the same name differently;
//! * a suffix goes to its own servers, so `corp.example.com` and `lab.example.net` can have
//!   different upstreams and get different answers;
//! * the **longest** matching suffix wins, and suffixes are compared on label boundaries, so
//!   `notcorp.example.com` is not under `corp.example.com`;
//! * what nothing covers is `REFUSED`, and a configured upstream that does not answer is
//!   `SERVFAIL` - never `NXDOMAIN`, which would cache an absence nobody established.
#![cfg(feature = "dns")]

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};

use hickory_server::proto::op::Query;
use hickory_server::proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_server::proto::rr::rdata::A;
use hickory_server::proto::rr::{LowerName, Name, RData, Record, RecordType};
use hickory_server::zone_handler::Catalog;
use rrl_directory::dns::config::Settings;
use rrl_directory::dns::serve::{Answering, InMemory, catalog_with, listen};

/// An upstream that answers every `A` question with one address, over UDP and TCP on one port.
///
/// A real socket rather than a mock, because half of what is being checked is that the listener's
/// answer carries the upstream's records through unchanged.
async fn upstream(answer: &'static str) -> SocketAddr {
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp");
    let addr = udp.local_addr().expect("an address");
    let tcp = tokio::net::TcpListener::bind(addr).await.expect("tcp");
    let ip: Ipv4Addr = answer.parse().expect("an address");

    tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        loop {
            let Ok((read, peer)) = udp.recv_from(&mut buffer).await else {
                return;
            };
            let Some(request) = Message::from_vec(&buffer[..read]).ok() else {
                continue;
            };
            let reply = answer_with(&request, ip);
            let _ = udp.send_to(&reply.to_vec().expect("encodes"), peer).await;
        }
    });
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut stream, _)) = tcp.accept().await else {
                return;
            };
            let mut head = [0u8; 2];
            if stream.read_exact(&mut head).await.is_err() {
                continue;
            }
            let mut body = vec![0u8; usize::from(u16::from_be_bytes(head))];
            if stream.read_exact(&mut body).await.is_err() {
                continue;
            }
            let Some(request) = Message::from_vec(&body).ok() else {
                continue;
            };
            let reply = answer_with(&request, ip);
            let bytes = reply.to_vec().expect("encodes");
            let _ = stream
                .write_all(&u16::try_from(bytes.len()).expect("short").to_be_bytes())
                .await;
            let _ = stream.write_all(&bytes).await;
        }
    });
    addr
}

fn answer_with(request: &Message, ip: Ipv4Addr) -> Message {
    let mut reply = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
    reply.metadata.recursion_available = true;
    for query in request.queries.iter() {
        reply.add_query(query.clone());
        reply.add_answer(Record::from_rdata(
            query.name().clone(),
            60,
            RData::A(A::from(ip)),
        ));
    }
    reply
}

/// A port nothing listens on: bound and dropped, so the address is real and empty.
async fn dead() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp");
    let addr = socket.local_addr().expect("an address");
    drop(socket);
    addr
}

/// The zone this server holds: `ad.example.com` with one host.
fn our_zone() -> (Catalog, LowerName) {
    let name = Name::from_ascii("dc.ad.example.com.").expect("a name");
    let record = Record::from_rdata(name, 60, RData::A(A::from(Ipv4Addr::new(10, 0, 0, 5))));
    let zone = InMemory::new("ad.example.com.", vec![record]).expect("a zone");
    let ours = LowerName::from(Name::from_ascii("ad.example.com.").expect("a name"));
    (catalog_with(std::sync::Arc::new(zone)), ours)
}

fn settings(
    forward_default: Vec<SocketAddr>,
    forward_zones: BTreeMap<String, Vec<SocketAddr>>,
) -> Settings {
    Settings {
        bind: "127.0.0.1:0".parse().expect("an address"),
        dns_domain: "ad.example.com".to_string(),
        address: Ipv4Addr::new(10, 0, 0, 5),
        forward_default,
        forward_zones,
        zones_dir: std::path::PathBuf::from("/dns"),
    }
}

/// The listener, over `settings`, on a kernel-chosen port.
async fn start(settings: Settings) -> (SocketAddr, rrl_directory::dns::serve::Running) {
    let (catalog, ours) = our_zone();
    let handler = Answering::new(catalog, ours, settings);
    let running = listen("127.0.0.1:0".parse().expect("an address"), handler)
        .await
        .expect("the listener started");
    (running.bind, running)
}

/// One question, asked over UDP, answered as it arrives.
async fn ask(server: SocketAddr, name: &str, rtype: RecordType) -> Message {
    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).expect("a name"), rtype));
    let bytes = message.to_vec().expect("encodes");

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp");
    socket.connect(server).await.expect("connect");
    socket.send(&bytes).await.expect("send");
    let mut buffer = [0u8; 4096];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv(&mut buffer))
        .await
        .expect("an answer in time")
        .expect("an answer");
    Message::from_vec(&buffer[..read]).expect("parses")
}

/// The `A` addresses an answer carries.
fn addresses(message: &Message) -> Vec<Ipv4Addr> {
    message
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .collect()
}

/// The rule that keeps local data local: a name in our zone is answered here even when an upstream
/// holds a different opinion about it.
#[tokio::test]
async fn our_zone_is_answered_here_and_never_forwarded() {
    // An upstream that would answer our own name with something else, if it were ever asked.
    let upstream = upstream("203.0.113.99").await;
    let (server, running) = start(settings(vec![upstream], BTreeMap::new())).await;

    let answer = ask(server, "dc.ad.example.com.", RecordType::A).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        addresses(&answer),
        vec![Ipv4Addr::new(10, 0, 0, 5)],
        "the zone's own record, not what the upstream would have said"
    );
    running.stop().await;
}

/// Each suffix has its own servers, and an answer comes back from the one that owns the name.
#[tokio::test]
async fn a_suffix_is_sent_to_its_own_server() {
    let corp = upstream("192.0.2.10").await;
    let lab = upstream("192.0.2.20").await;
    let default = upstream("192.0.2.30").await;

    let mut zones = BTreeMap::new();
    zones.insert("corp.example.com".to_string(), vec![corp]);
    zones.insert("lab.example.net".to_string(), vec![lab]);
    let (server, running) = start(settings(vec![default], zones)).await;

    assert_eq!(
        addresses(&ask(server, "host.corp.example.com.", RecordType::A).await),
        vec![Ipv4Addr::new(192, 0, 2, 10)]
    );
    assert_eq!(
        addresses(&ask(server, "host.lab.example.net.", RecordType::A).await),
        vec![Ipv4Addr::new(192, 0, 2, 20)]
    );
    // Nothing named a suffix for this one, so it goes to the server for everything else.
    assert_eq!(
        addresses(&ask(server, "www.elsewhere.test.", RecordType::A).await),
        vec![Ipv4Addr::new(192, 0, 2, 30)]
    );
    running.stop().await;
}

/// The longest suffix wins, and a suffix matches whole labels only.
#[tokio::test]
async fn the_longest_suffix_wins_and_labels_are_whole() {
    let inner = upstream("192.0.2.40").await;
    let outer = upstream("192.0.2.41").await;
    let default = upstream("192.0.2.42").await;

    let mut zones = BTreeMap::new();
    zones.insert("corp.example.com".to_string(), vec![inner]);
    zones.insert("example.com".to_string(), vec![outer]);
    let (server, running) = start(settings(vec![default], zones)).await;

    // Deeper than `example.com`: the more specific server is the one that knows more about it.
    assert_eq!(
        addresses(&ask(server, "a.corp.example.com.", RecordType::A).await),
        vec![Ipv4Addr::new(192, 0, 2, 40)]
    );
    // Under `example.com` and nothing more specific.
    assert_eq!(
        addresses(&ask(server, "a.example.com.", RecordType::A).await),
        vec![Ipv4Addr::new(192, 0, 2, 41)]
    );
    // `notcorp.example.com` ends with `corp.example.com` as a string and is not under it as a name,
    // so it belongs to the broader suffix.
    assert_eq!(
        addresses(&ask(server, "notcorp.example.com.", RecordType::A).await),
        vec![Ipv4Addr::new(192, 0, 2, 41)]
    );
    running.stop().await;
}

/// Nothing covers the name and nothing is configured to: `REFUSED`, which tells a client to ask
/// somebody else, rather than `NXDOMAIN`, which would cache an absence nobody established.
#[tokio::test]
async fn an_uncovered_name_with_no_default_is_refused() {
    let (server, running) = start(settings(Vec::new(), BTreeMap::new())).await;

    let answer = ask(server, "www.elsewhere.test.", RecordType::A).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::Refused);
    assert!(answer.answers.is_empty());
    running.stop().await;
}

/// Configured and it did not work: `SERVFAIL`, and not an invented absence.
#[tokio::test]
async fn a_configured_upstream_that_does_not_answer_is_servfail() {
    let (server, running) = start(settings(vec![dead().await], BTreeMap::new())).await;

    let answer = ask(server, "www.elsewhere.test.", RecordType::A).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);
    running.stop().await;
}

/// A zone transfer is refused rather than forwarded: a transfer through a forwarder would make this
/// server a secondary of a zone it never agreed to hold.
#[tokio::test]
async fn a_zone_transfer_is_not_forwarded() {
    let upstream = upstream("192.0.2.50").await;
    let (server, running) = start(settings(vec![upstream], BTreeMap::new())).await;

    let answer = ask(server, "elsewhere.test.", RecordType::AXFR).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::Refused);
    running.stop().await;
}
