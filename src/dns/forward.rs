//! Sending a query on, for a name this server does not hold.
//!
//! A domain controller answers for its own domain and refuses everything else, which is the right
//! default: a server that resolved the whole internet would be a resolver, and a resolver that
//! answers for a domain it does not hold is a man in the middle. But a stand - and plenty of real
//! deployments - need the one name that lives in another zone to resolve, and that is what this is:
//! an explicit, configured, per-suffix forwarder.
//!
//! # What this is not
//!
//! Not a recursor. The query travels with `RD` set and whatever the upstream answers is returned as
//! it came: no cache, no validation, no second guess. A recursor is a different program with a
//! different threat model, and half of one is worse than none - a cache that forgot a TTL is a name
//! that never expires.
//!
//! # Transport
//!
//! The client's transport is not the upstream's problem: this always asks over UDP first, because
//! that is what a resolver expects and what costs one round trip, and only switches to TCP when the
//! answer comes back truncated (`TC`), which is the only time a resolver needs the stream. Doing
//! otherwise would mean holding a connection open per upstream for every client that ever asked.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_server::proto::op::{Message, MessageType, OpCode, Query};
use hickory_server::proto::rr::RecordType;

/// How long one upstream is given before the next one is tried.
///
/// Three seconds, and not a round number chosen for looks: a client's own resolver gives up after
/// about five, so an upstream that has not answered in three is one whose answer would arrive too
/// late to be worth sending.
pub const TIMEOUT: Duration = Duration::from_secs(3);

/// The largest answer this will accept over UDP.
///
/// 1232 is the EDNS0 payload every modern resolver assumes; anything larger arrives truncated and is
/// fetched again over TCP, which is the protocol's own way of saying so.
const UDP_BUFFER: usize = 1232;

/// Asks `servers` for `query`, in order, and returns the first answer.
///
/// `None` when every server timed out or answered with something that is not a response to this
/// question: the caller then answers `SERVFAIL`, which is the only honest code for "configured, and
/// it did not work". Returning `NXDOMAIN` instead would cache the absence of a name that may well
/// exist.
pub async fn ask(query: &Query, servers: &[SocketAddr]) -> Option<Message> {
    for server in servers {
        if let Some(answer) = ask_one(query, *server).await {
            return Some(answer);
        }
    }
    None
}

/// One upstream, UDP first and TCP when the answer does not fit.
async fn ask_one(query: &Query, server: SocketAddr) -> Option<Message> {
    let mut message = Message::new(0x4242, MessageType::Query, OpCode::Query);
    // Recursion is what makes the upstream do the work: this server sends what it was given, and a
    // forwarder asked without `RD` is a forwarder that gets `REFUSED` from its own upstream.
    message.metadata.recursion_desired = true;
    message.add_query(query.clone());
    let bytes = message.to_vec().ok()?;

    let answer = ask_udp(&bytes, server).await?;
    if answer.metadata.truncation {
        return ask_tcp(&bytes, server).await;
    }
    Some(answer)
}

async fn ask_udp(bytes: &[u8], server: SocketAddr) -> Option<Message> {
    let bind: SocketAddr = match server {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().ok()?,
        SocketAddr::V6(_) => "[::]:0".parse().ok()?,
    };
    let socket = tokio::net::UdpSocket::bind(bind).await.ok()?;
    socket.connect(server).await.ok()?;
    socket.send(bytes).await.ok()?;

    let mut buffer = vec![0u8; UDP_BUFFER];
    let read = tokio::time::timeout(TIMEOUT, socket.recv(&mut buffer))
        .await
        .ok()?
        .ok()?;
    let answer = Message::from_vec(&buffer[..read]).ok()?;
    // An identifier that does not match is not an answer to this question, whatever else it holds:
    // a socket that accepted it would hand a client somebody else's records.
    (answer.metadata.id == 0x4242).then_some(answer)
}

async fn ask_tcp(bytes: &[u8], server: SocketAddr) -> Option<Message> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect(server))
        .await
        .ok()?
        .ok()?;
    let length = u16::try_from(bytes.len()).ok()?;
    stream.write_all(&length.to_be_bytes()).await.ok()?;
    stream.write_all(bytes).await.ok()?;

    let mut head = [0u8; 2];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut head))
        .await
        .ok()?
        .ok()?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(head))];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut body))
        .await
        .ok()?
        .ok()?;
    let answer = Message::from_vec(&body).ok()?;
    (answer.metadata.id == 0x4242).then_some(answer)
}

/// The query a request asks, when it asks exactly one.
///
/// A request with no query, or with several, is not something this server answers by forwarding: the
/// protocol has one question per message, and a forwarder of several would have to guess which
/// answer belongs to which question.
pub fn single_query(message: &Message) -> Option<&Query> {
    let mut queries = message.queries.iter();
    let first = queries.next()?;
    queries.next().is_none().then_some(first)
}

/// Whether `rtype` is one a forwarder must carry rather than refuse.
///
/// `AXFR` and `IXFR` are excluded: a zone transfer through a forwarder is a transfer of a zone this
/// server does not hold, and handing one out would make this server a secondary it never agreed to
/// be.
pub fn is_forwardable(rtype: RecordType) -> bool {
    !matches!(rtype, RecordType::AXFR | RecordType::IXFR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::op::MessageType;
    use hickory_server::proto::rr::rdata::A;
    use hickory_server::proto::rr::{RData, Record};
    use std::net::Ipv4Addr;

    /// An upstream that answers every question with one `A`, over UDP and TCP on one port.
    ///
    /// Written here rather than mocked, because what is being tested is the exchange: the framing,
    /// the identifier, and the switch to TCP when the answer says it was truncated.
    async fn upstream(answer_ip: &'static str, truncate: bool) -> SocketAddr {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp");
        let addr = udp.local_addr().expect("an address");
        let tcp = tokio::net::TcpListener::bind(addr).await.expect("tcp");

        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            loop {
                let Ok((read, peer)) = udp.recv_from(&mut buffer).await else {
                    return;
                };
                let Some(request) = Message::from_vec(&buffer[..read]).ok() else {
                    continue;
                };
                let reply = answer(&request, answer_ip, truncate);
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
                // Over TCP the answer is never truncated: that is the whole point of the stream.
                let reply = answer(&request, answer_ip, false);
                let bytes = reply.to_vec().expect("encodes");
                let _ = stream
                    .write_all(&u16::try_from(bytes.len()).expect("short").to_be_bytes())
                    .await;
                let _ = stream.write_all(&bytes).await;
            }
        });
        addr
    }

    fn answer(request: &Message, ip: &str, truncate: bool) -> Message {
        let mut reply = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
        reply.metadata.recursion_available = true;
        for query in request.queries.iter() {
            reply.add_query(query.clone());
            if !truncate {
                reply.add_answer(Record::from_rdata(
                    query.name().clone(),
                    60,
                    RData::A(A::from(ip.parse::<Ipv4Addr>().expect("an address"))),
                ));
            }
        }

        if truncate {
            reply.metadata.truncation = true;
        }
        reply
    }

    fn query(name: &str) -> Query {
        Query::query(
            hickory_server::proto::rr::Name::from_ascii(name).expect("a name"),
            RecordType::A,
        )
    }

    /// The acceptance: a question this server does not hold travels to the configured server and
    /// comes back as an answer.
    #[tokio::test]
    async fn a_query_reaches_the_upstream_and_its_answer_comes_back() {
        let server = upstream("192.0.2.10", false).await;
        let answer = ask(&query("elsewhere.test."), &[server])
            .await
            .expect("the upstream answered");
        assert_eq!(
            answer.metadata.response_code,
            hickory_server::proto::op::ResponseCode::NoError
        );
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(answer.answers[0].name.to_ascii(), "elsewhere.test.");
    }

    /// A truncated answer is fetched again over TCP, which is the only reason a resolver needs the
    /// stream at all.
    #[tokio::test]
    async fn a_truncated_answer_is_fetched_again_over_tcp() {
        let server = upstream("192.0.2.11", true).await;
        let answer = ask(&query("big.test."), &[server])
            .await
            .expect("the second attempt answered");
        assert_eq!(
            answer.answers.len(),
            1,
            "the TCP answer carries the record the UDP one only promised"
        );
    }

    /// Nothing listening is `None`, and the caller answers `SERVFAIL`: the alternative - inventing
    /// `NXDOMAIN` - would have every client cache the absence of a name nobody checked.
    #[tokio::test]
    async fn an_upstream_that_does_not_answer_is_not_an_answer() {
        // A port nothing listens on: bound and dropped, so the address is syntactically real and
        // there is no server behind it.
        let dead = {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("udp");
            let addr = socket.local_addr().expect("an address");
            drop(socket);
            addr
        };
        assert!(ask(&query("nothing.test."), &[dead]).await.is_none());
    }

    /// The second server is tried when the first does not answer: a forwarder list is a list, not a
    /// single address with decoration.
    #[tokio::test]
    async fn a_second_server_is_tried_when_the_first_is_silent() {
        let dead = {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("udp");
            let addr = socket.local_addr().expect("an address");
            drop(socket);
            addr
        };
        let live = upstream("192.0.2.12", false).await;
        let answer = ask(&query("second.test."), &[dead, live])
            .await
            .expect("the second server answered");
        assert_eq!(answer.answers.len(), 1);
    }
}
