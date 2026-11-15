//! Port 53: UDP and TCP on one address, with `hickory-server` doing the wire format.
//!
//! A domain controller has to answer a validator's questions about the protocol itself - compression,
//! truncation, EDNS, the shape of a response - and hand-writing RFC 1035 would be a second place to
//! be wrong about all of it. So the protocol comes from `hickory-proto` and the server loop from
//! `hickory-server`; what stays ours is the zone: `ZoneHandler` is implemented over whatever holds the
//! records, and there are two such things - [`InMemory`] for a list handed over at start, and
//! [`FromSource`] for the zone [`crate::dns::zone`] reads out of the directory.
//!
//! The interface this file has to fit is the one the crate actually publishes, and it was read from
//! the source rather than from prose: `Catalog::upsert(LowerName, Vec<Arc<dyn ZoneHandler>>)`,
//! `Server::new(handler)`, `register_socket(UdpSocket)`, `register_listener(TcpListener, timeout,
//! buffer)`. The zone handler answers `lookup` (one name and type), `search` (whatever the query
//! asks), `nsec_records`/`nsec3_records` (proof of absence) and `update` (RFC 2136, not yet).
//!
//! Deliberately not here: the records a domain needs, derived from what the server already knows
//! (RRL-2.25.6), and dynamic updates with their signatures (2.25.7/2.25.8), which land on
//! `ZoneHandler::update` beside the two `nsec` methods this file already leaves to `Skip`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::{LowerName, Record, RecordSet, RecordType, TSigResponseContext};
use hickory_server::server::{Request, RequestInfo, Server};
use hickory_server::zone_handler::{
    AuthLookup, AxfrPolicy, Catalog, LookupControlFlow, LookupError, LookupOptions, LookupRecords,
    ZoneHandler, ZoneType,
};

/// How long a TCP connection may sit between requests before it is closed.
///
/// Five seconds is what `hickory`'s own examples use, and it is a defence against a connection that
/// is opened and never spoken to: TCP DNS is rare enough that a slow client is not a workload here.
const TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// The buffer a TCP response is assembled in. 1232 is the EDNS0 payload every modern resolver
/// assumes, and a response larger than it is cut with TC instead of being written into a bigger one.
const TCP_BUFFER: usize = 1232;

/// A zone held in memory, which is what a zone looks like to this module.
///
/// The records carry their own owner names, so the lookup is a filter over them: a domain's zone is
/// tens of records and not millions, and a map keyed by `(name, type)` would be a second structure to
/// keep in step with this one for no measured gain.
#[derive(Debug, Default)]
pub struct InMemory {
    origin: Option<LowerName>,
    records: Vec<Record>,
}

impl InMemory {
    /// A zone at `origin`, holding `records`.
    ///
    /// Returns `None` when `origin` is not a name: a zone without an origin is one the catalog cannot
    /// place, and guessing would put its records under somebody else's domain.
    pub fn new(origin: &str, records: Vec<Record>) -> Option<Self> {
        let origin = LowerName::from(hickory_server::proto::rr::Name::from_ascii(origin).ok()?);
        Some(Self {
            origin: Some(origin),
            records,
        })
    }

    /// The answer to a lookup, in the shape the trait wants.
    fn answer(
        &self,
        name: &LowerName,
        rtype: RecordType,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        answer_over(&self.records, name, rtype, options)
    }
}

/// The records for `name` and `rtype`, with `ANY` meaning every type.
///
/// Free rather than a method because two handlers answer out of a list of records: one that was
/// handed the list at start, and one that reads it out of the directory on every query. The
/// answering rules - NXDOMAIN against an empty answer, one `RecordSet` per type - are the part
/// that must not differ between them.
fn matching(records: &[Record], name: &LowerName, rtype: RecordType) -> Vec<Record> {
    records
        .iter()
        .filter(|record| {
            LowerName::from(record.name.clone()) == *name
                && (rtype == RecordType::ANY || record.record_type() == rtype)
        })
        .cloned()
        .collect()
}

/// The answer to a lookup, in the shape the trait wants.
///
/// The records are grouped into one `RecordSet` per type, because that is the unit `hickory`
/// answers with: a set carries the TTL and the class of its records, and a list of loose records
/// would make the server infer what the set already knows.
fn answer_over(
    records: &[Record],
    name: &LowerName,
    rtype: RecordType,
    options: LookupOptions,
) -> LookupControlFlow<AuthLookup> {
    let found = matching(records, name, rtype);
    if found.is_empty() {
        // A name this zone knows with other types is not NXDOMAIN: telling a client the name does
        // not exist would stop it asking for the type that does.
        let known = records
            .iter()
            .any(|record| LowerName::from(record.name.clone()) == *name);
        return if known {
            LookupControlFlow::Continue(Err(LookupError::NameExists))
        } else {
            LookupControlFlow::Continue(Err(LookupError::ResponseCode(ResponseCode::NXDomain)))
        };
    }

    let mut sets: Vec<Arc<RecordSet>> = Vec::new();
    for record in found {
        match sets
            .iter_mut()
            .find(|set| set.record_type() == record.record_type())
        {
            Some(set) => {
                Arc::make_mut(set).insert(record, 0);
            }
            None => {
                let mut set = RecordSet::new(record.name.clone(), record.record_type(), 0);
                set.set_dns_class(record.dns_class);
                set.set_ttl(record.ttl);
                set.insert(record, 0);
                sets.push(Arc::new(set));
            }
        }
    }
    LookupControlFlow::Continue(Ok(AuthLookup::Records {
        answers: LookupRecords::many(options, sets),
        additionals: None,
    }))
}

#[async_trait::async_trait]
impl ZoneHandler for InMemory {
    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        // No zone transfer: the records live in a directory that replicates them by its own means,
        // and an AXFR would be a second, unreplicated copy of the same data.
        AxfrPolicy::Deny
    }

    fn origin(&self) -> &LowerName {
        // `new` refuses to build one without an origin, so this cannot be reached on a value that
        // came through it; the panic names the invariant instead of answering with `example.com`.
        self.origin
            .as_ref()
            .expect("a zone without an origin is not built")
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.answer(name, rtype, lookup_options)
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        // `Request` derefs to its `MessageRequest`, which carries the queries it was parsed from.
        // A request with no query at all is a form the caller has already rejected; answering
        // `Skip` here hands it to the next zone instead of inventing a name.
        let Some(question) = request.queries.queries().first() else {
            return (LookupControlFlow::Skip, None);
        };
        let name = question.name().clone();
        let rtype = question.query_type();
        (self.answer(&name, rtype, lookup_options), None)
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        // Unsigned zone: there is no proof of absence to hand out, and claiming one would be worse
        // than saying nothing.
        LookupControlFlow::Skip
    }
}

/// Where a zone's records come from, as the listener asks for them.
///
/// A trait and not a `Vec`, because the two answers differ in *when* the records are read. The zone
/// the stand provisions is read once and handed over; the zone in the directory is read on every
/// query, so a record an administrator adds over LDAP - or a dynamic update writes - is answered on
/// the next question rather than after a restart. A domain has tens of records, and a subtree walk
/// over them is cheaper than the working hours a stale zone costs.
#[async_trait::async_trait]
pub trait ZoneSource: Send + Sync {
    /// The zone as it stands now.
    async fn read(&self) -> Result<crate::dns::zone::Zone, crate::dns::zone::Error>;
}

/// The zone read out of this server's own directory, one read per query.
///
/// The `Source` is the same handle the LDAP side uses, which is what makes a reload visible here:
/// `reload` swaps the snapshot behind it, and the next query sees the new one without anybody
/// telling the listener that something changed.
pub struct InDirectory {
    source: Arc<crate::reload::Source>,
    base_dn: String,
    dns_name: String,
}

impl InDirectory {
    /// Reads `dns_name` out of `source`'s directory.
    pub fn new(source: Arc<crate::reload::Source>, base_dn: &str, dns_name: &str) -> Self {
        Self {
            source,
            base_dn: base_dn.to_string(),
            dns_name: dns_name.trim_end_matches('.').to_string(),
        }
    }
}

#[async_trait::async_trait]
impl ZoneSource for InDirectory {
    async fn read(&self) -> Result<crate::dns::zone::Zone, crate::dns::zone::Error> {
        let directory = self.source.directory().await;
        crate::dns::zone::Zone::read(&directory, &self.base_dn, &self.dns_name)
    }
}

/// A zone handler that asks its [`ZoneSource`] on every query.
///
/// The last zone it managed to read is kept, and answered when the next read fails. That is
/// deliberate: a zone read out of a directory fails when the directory does, and a domain whose
/// name resolution stops because one subtree walk went wrong is worse than one answering from the
/// records it had a moment ago - which is what DNS already asks every client to tolerate, since a
/// TTL is permission to serve a stale answer. The failure is logged every time it happens, so a
/// broken zone is visible rather than silently frozen.
pub struct FromSource {
    source: Arc<dyn ZoneSource>,
    origin: LowerName,
    /// What the last successful read returned, for the case above.
    last: std::sync::Mutex<Option<crate::dns::zone::Zone>>,
}

impl FromSource {
    /// A handler for the zone `source` answers with, filed under `origin`.
    ///
    /// The origin is an argument rather than read from the source because the catalog needs it
    /// before the first query: `Catalog::upsert` files the handler by name, and a name that came
    /// from a read would make the catalog empty until somebody asked a question.
    pub fn new(source: Arc<dyn ZoneSource>, origin: &str) -> Option<Self> {
        let origin = hickory_server::proto::rr::Name::from_ascii(origin.trim_end_matches('.'))
            .ok()
            .map(|mut name| {
                name.set_fqdn(true);
                name
            })?;
        Some(Self {
            source,
            origin: LowerName::from(origin),
            last: std::sync::Mutex::new(None),
        })
    }

    /// The answer, from the source if it can be read and from the previous read if it cannot.
    ///
    /// The one case with nothing to answer from is the first query of a listener whose source has
    /// never worked - and [`listen_from_directory`] refuses to start in that state, so it is
    /// reachable only through a handler built directly. It returns `SERVFAIL`, and `hickory` 0.26
    /// does not pass that code on for an authoritative zone: `build_authoritative_response` keeps
    /// the code of `Refused` and `NotAuth` and turns everything else into `NXDOMAIN` or an empty
    /// `NOERROR`. So the client sees `NODATA`, and this comment is the record of why the honest
    /// code is not the one on the wire.
    async fn answer(
        &self,
        name: &LowerName,
        rtype: RecordType,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        match self.source.read().await {
            Ok(zone) => {
                if !zone.unserved.is_empty() {
                    // Said on every query rather than once: the types are few, the line is short,
                    // and a listener that quietly answers with records missing from the zone is the
                    // failure this whole module is written to avoid.
                    tracing::debug!(
                        types = ?zone.unserved,
                        "dns: the zone holds records this build cannot render"
                    );
                }
                if let Ok(mut held) = self.last.lock() {
                    *held = Some(zone.clone());
                }
                answer_over(&zone.records, name, rtype, options)
            }
            Err(err) => {
                tracing::warn!(%err, "dns: the zone could not be read");
                let previous = self
                    .last
                    .lock()
                    .ok()
                    .and_then(|held| held.as_ref().cloned());
                match previous {
                    Some(zone) => {
                        tracing::warn!(
                            records = zone.records.len(),
                            "dns: answering from the zone read before this failure"
                        );
                        answer_over(&zone.records, name, rtype, options)
                    }
                    None => LookupControlFlow::Continue(Err(LookupError::ResponseCode(
                        ResponseCode::ServFail,
                    ))),
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl ZoneHandler for FromSource {
    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        // The same reason `InMemory` denies it: the records are the directory's, and a transfer
        // would be a second copy that nobody replicates.
        AxfrPolicy::Deny
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.answer(name, rtype, lookup_options).await
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        let Some(question) = request.queries.queries().first() else {
            return (LookupControlFlow::Skip, None);
        };
        let name = question.name().clone();
        let rtype = question.query_type();
        (self.answer(&name, rtype, lookup_options).await, None)
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        // Unsigned, as `InMemory` is: no proof of absence exists to hand out.
        LookupControlFlow::Skip
    }
}

/// A catalog holding the zone a [`ZoneSource`] answers with.
pub fn catalog_from(zone: Arc<FromSource>) -> Catalog {
    let mut catalog = Catalog::new();
    catalog.upsert(zone.origin().clone(), vec![zone]);
    catalog
}

/// Serves the directory's zone on `bind`.
///
/// The first read happens here, before the port is taken, and its failure is the return value: a
/// listener bound to 53 for a zone that does not exist answers every query with `SERVFAIL`, which
/// is indistinguishable from a network fault at the client. Failing to start says which zone and
/// which DN in one line.
pub async fn listen_from_directory(
    bind: SocketAddr,
    source: Arc<crate::reload::Source>,
    base_dn: &str,
    dns_name: &str,
    forward: crate::dns::config::Settings,
) -> Result<Running, String> {
    let in_directory = InDirectory::new(Arc::clone(&source), base_dn, dns_name);
    match in_directory.read().await {
        Ok(zone) => {
            if !zone.unserved.is_empty() {
                tracing::warn!(
                    zone = %zone.origin.to_ascii(),
                    types = ?zone.unserved,
                    "dns: the zone holds records this build cannot render; they are not answered"
                );
            }
        }
        Err(err) => return Err(format!("dns zone '{dns_name}': {err}")),
    }
    let handler = FromSource::new(Arc::new(in_directory), dns_name)
        .ok_or_else(|| format!("dns zone '{dns_name}' is not a DNS name"))?;
    let handler = Arc::new(handler);
    let ours = handler.origin().clone();
    let catalog = catalog_from(Arc::clone(&handler));
    // The forwarder is told the bind address, because the settings come from the configuration and
    // the port may have been chosen by the kernel: a listener that reported a different address than
    // it took would be one nobody can find.
    let forward = crate::dns::config::Settings {
        bind,
        ..forward
    };
    listen(bind, Answering::new(catalog, ours, forward)).await
}

/// A catalog plus a forwarder: the zone this server holds, and everywhere else it was told to ask.
///
/// The split is by name, and the boundary is the whole reason this type exists rather than a second
/// zone handler: a name inside our zone is answered from the directory and **never** leaves, which is
/// what keeps a local record from being overridden by an upstream that has a different idea about the
/// same name. Anything else goes to the configured servers, or is refused.
pub struct Answering {
    catalog: Catalog,
    /// The origin below which every name is ours.
    ours: LowerName,
    /// The servers for everything else, empty when nothing is forwarded.
    forward: crate::dns::config::Settings,
}

impl Answering {
    /// A handler over `catalog` (which answers `ours`) and `forward` for the rest.
    pub fn new(catalog: Catalog, ours: LowerName, forward: crate::dns::config::Settings) -> Self {
        Self {
            catalog,
            ours,
            forward,
        }
    }

    /// Whether `name` is this server's to answer.
    fn is_ours(&self, name: &LowerName) -> bool {
        // `zone_of` walks the labels up, so a name below the origin is ours and the origin itself is
        // ours: `Catalog::find` does the same walk, and a second rule would put a name on one side of
        // the boundary here and the other side there.
        let mut candidate = name.clone();
        loop {
            if candidate == self.ours {
                return true;
            }
            if candidate.is_root() {
                return false;
            }
            candidate = candidate.base_name();
        }
    }
}

#[async_trait::async_trait]
impl hickory_server::server::RequestHandler for Answering {
    async fn handle_request<R: hickory_server::server::ResponseHandler, T: hickory_server::net::runtime::Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> hickory_server::server::ResponseInfo {
        let Some(query) = request.queries.queries().first() else {
            return self.catalog.handle_request::<R, T>(request, response_handle).await;
        };
        if self.is_ours(query.name()) {
            return self.catalog.handle_request::<R, T>(request, response_handle).await;
        }
        if !crate::dns::forward::is_forwardable(query.query_type()) {
            return answer_with(
                request,
                response_handle,
                ResponseCode::Refused,
                Vec::new(),
                Vec::new(),
            )
            .await;
        }

        let Some(servers) = self
            .forward
            .forwarder_for(&query.name().to_ascii())
            .map(<[std::net::SocketAddr]>::to_vec)
        else {
            // Nothing configured for this name: the honest answer is `REFUSED`, which tells a client
            // to ask its own resolver. `NXDOMAIN` would cache an absence nobody established.
            return answer_with(
                request,
                response_handle,
                ResponseCode::Refused,
                Vec::new(),
                Vec::new(),
            )
            .await;
        };

        match crate::dns::forward::ask(query.original(), &servers).await {
            Some(answer) => {
                tracing::debug!(
                    name = %query.name(),
                    rtype = ?query.query_type(),
                    servers = servers.len(),
                    answers = answer.answers.len(),
                    "dns: forwarded"
                );
                let code = answer.metadata.response_code;
                let answers: Vec<Record> = answer.answers;
                let authorities: Vec<Record> = answer.authorities;
                answer_with(request, response_handle, code, answers, authorities).await
            }
            None => {
                // Configured and did not work: `SERVFAIL` is the code for exactly that.
                tracing::warn!(
                    name = %query.name(),
                    servers = servers.len(),
                    "dns: no upstream answered"
                );
                answer_with(
                    request,
                    response_handle,
                    ResponseCode::ServFail,
                    Vec::new(),
                    Vec::new(),
                )
                .await
            }
        }
    }
}

/// Writes one answer, with the records as they are.
async fn answer_with<R: hickory_server::server::ResponseHandler>(
    request: &Request,
    mut response_handle: R,
    code: ResponseCode,
    answers: Vec<Record>,
    authorities: Vec<Record>,
) -> hickory_server::server::ResponseInfo {
    use hickory_server::zone_handler::MessageResponseBuilder;

    let mut metadata = hickory_server::proto::op::Metadata::response_from_request(
        &request.metadata,
    );
    metadata.response_code = code;
    metadata.authoritative = false;
    // The recursion flag describes this server's own behaviour: it forwarded, so it was available.
    metadata.recursion_available = !answers.is_empty() || code == ResponseCode::NXDomain;

    let response = MessageResponseBuilder::new(&request.queries, request.edns.as_ref()).build(
        metadata,
        answers.iter(),
        authorities.iter(),
        std::iter::empty(),
        std::iter::empty(),
    );
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(err) => {
            // The write failed, which for a forwarder's answer is the client's problem and not
            // this server's: a UDP client that never sees an answer asks again, and a TCP one gets
            // a closed connection. Reported, and described as the `SERVFAIL` it would have been -
            // there is no `ResponseInfo` for "nothing was sent", and claiming the records went out
            // would put a count in the metrics that never reached a wire.
            tracing::warn!(%err, "dns: the answer could not be written");
            // `Metadata` is `#[non_exhaustive]`, so it is adjusted rather than rebuilt.
            let mut failed = metadata;
            failed.response_code = ResponseCode::ServFail;
            hickory_server::server::ResponseInfo::from(hickory_server::proto::op::Header {
                metadata: failed,
                counts: hickory_server::proto::op::HeaderCounts::default(),
            })
        }
    }
}

/// What a started listener is: where it took the port and the task serving it.
pub struct Running {
    pub bind: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    /// Stops the listener and waits for the task to finish.
    pub async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Serves `catalog` on `bind`, over UDP and TCP at the same address.
///
/// One port for both is what the protocol requires and what a client expects: a resolver asks over
/// UDP and retries over TCP when the answer does not fit, and it does not ask on a different port.
/// So the UDP socket is bound to the TCP listener's address rather than to an address of its own.
///
/// A failure to bind either transport is an error here, not a listener that silently answers half the
/// questions: a zone reachable over UDP and not TCP is one whose large answers are truncated forever.
pub async fn listen<H>(bind: SocketAddr, handler: H) -> Result<Running, String>
where
    H: hickory_server::server::RequestHandler,
{
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|err| format!("dns {bind} tcp: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("dns {bind} tcp: {err}"))?;
    let socket = tokio::net::UdpSocket::bind(addr)
        .await
        .map_err(|err| format!("dns {addr} udp: {err}"))?;

    let mut server = Server::new(handler);
    server.register_socket(socket);
    server.register_listener(listener, TCP_TIMEOUT, TCP_BUFFER);

    let task = tokio::spawn(async move {
        if let Err(err) = server.block_until_done().await {
            eprintln!("dns: {err}");
        }
    });
    Ok(Running { bind: addr, task })
}

/// A catalog holding one zone, which is what a domain is: one name, one set of records.
pub fn catalog_with(zone: Arc<InMemory>) -> Catalog {
    let mut catalog = Catalog::new();
    catalog.upsert(zone.origin().clone(), vec![zone]);
    catalog
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::op::{Message, MessageType, OpCode, Query};
    use hickory_server::proto::rr::rdata::SRV;
    use hickory_server::proto::rr::{Name, RData};

    use crate::dns::zone;
    use std::net::Ipv4Addr;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).expect("a name")
    }

    /// The zone a domain needs, as far as this test is concerned: an address and a service locator.
    fn zone() -> Arc<InMemory> {
        let origin = name("ad.example.com.");
        // `from_rdata` writes the IN class and the TTL asked for, which is every record a domain
        // serves: the class is a constant of the protocol here and not a per-record choice.
        let a = Record::from_rdata(
            name("samba.ad.example.com."),
            600,
            RData::A(Ipv4Addr::new(10, 0, 2, 2).into()),
        );
        let srv = Record::from_rdata(
            name("_ldap._tcp.ad.example.com."),
            600,
            RData::SRV(SRV::new(0, 100, 389, name("samba.ad.example.com."))),
        );
        Arc::new(InMemory::new(origin.to_string().as_str(), vec![a, srv]).expect("a zone"))
    }

    fn query(name: &str, rtype: RecordType, id: u16) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(Name::from_ascii(name).expect("a name"), rtype));
        message.to_vec().expect("encoded")
    }

    async fn ask_udp(addr: SocketAddr, packet: &[u8]) -> Message {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("socket");
        socket.send_to(packet, addr).await.expect("sent");
        let mut buffer = vec![0u8; 4096];
        let read = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buffer))
            .await
            .expect("an answer in time")
            .expect("read");
        Message::from_vec(&buffer[..read]).expect("decoded")
    }

    async fn ask_tcp(addr: SocketAddr, packet: &[u8]) -> Message {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let length = u16::try_from(packet.len()).expect("a short query");
        stream
            .write_all(&length.to_be_bytes())
            .await
            .expect("length");
        stream.write_all(packet).await.expect("written");
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.expect("length back");
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut body).await.expect("body");
        Message::from_vec(&body).expect("decoded")
    }

    /// The acceptance of this task: one zone, one port, the same answer over both transports.
    ///
    /// A zone that answers on UDP and not TCP is one whose large answers are truncated forever, and
    /// the difference would only show up on a real validator; here it shows up in four assertions.
    #[tokio::test]
    async fn a_zone_answers_the_same_way_over_udp_and_tcp() {
        let running = listen(
            "127.0.0.1:0".parse().expect("an address"),
            catalog_with(zone()),
        )
        .await
        .expect("started");
        let addr = running.bind;

        for (question, rtype, expected) in [
            ("samba.ad.example.com.", RecordType::A, RecordType::A),
            (
                "_ldap._tcp.ad.example.com.",
                RecordType::SRV,
                RecordType::SRV,
            ),
        ] {
            let packet = query(question, rtype, 7);
            let over_udp = ask_udp(addr, &packet).await;
            let over_tcp = ask_tcp(addr, &packet).await;

            for (transport, answer) in [("udp", &over_udp), ("tcp", &over_tcp)] {
                assert_eq!(
                    answer.response_code,
                    ResponseCode::NoError,
                    "{question} over {transport}"
                );
                let answers = &answer.answers;
                assert_eq!(answers.len(), 1, "{question} over {transport}");
                assert_eq!(answers[0].record_type(), expected);
                assert_eq!(answers[0].name.to_string(), question);
            }
            assert_eq!(
                over_udp.answers[0].data, over_tcp.answers[0].data,
                "the same record over both transports"
            );
        }
        running.stop().await;
    }

    /// A source that answers from a queue, one answer per read, and repeats the last one after
    /// the queue is spent. The counter is what proves the handler reads per query.
    struct Counting {
        answers: std::sync::Mutex<std::collections::VecDeque<Result<zone::Zone, zone::Error>>>,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl Counting {
        fn new(answers: Vec<Result<zone::Zone, zone::Error>>) -> Arc<Self> {
            Arc::new(Self {
                answers: std::sync::Mutex::new(answers.into()),
                reads: std::sync::atomic::AtomicUsize::new(0),
            })
        }
    }

    #[async_trait::async_trait]
    impl ZoneSource for Counting {
        async fn read(&self) -> Result<zone::Zone, zone::Error> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut answers = self.answers.lock().expect("the lock is not poisoned");
            if answers.len() > 1 {
                return answers.pop_front().expect("the queue is not empty");
            }
            answers.front().cloned().unwrap_or_else(|| {
                Err(zone::Error::NoZone {
                    name: "ad.example.com".to_string(),
                    dn: "dc=ad.example.com".to_string(),
                })
            })
        }
    }

    fn address(name: &str, octet: u8) -> Record {
        Record::from_rdata(
            zone::absolute(name).expect("the test uses names this crate reads"),
            600,
            RData::A(Ipv4Addr::new(10, 0, 2, octet).into()),
        )
    }

    fn zone_with(records: Vec<Record>) -> zone::Zone {
        zone::Zone {
            origin: zone::absolute("ad.example.com.").expect("a name"),
            dn: "dc=ad.example.com,cn=RRLDNS,dc=DomainDnsZones,dc=ad,dc=example,dc=com".to_string(),
            records,
            unserved: Vec::new(),
        }
    }

    /// The acceptance of the directory-backed handler: a query is answered from the source, and the
    /// source is read again for the next one - which is what makes a record added over LDAP visible
    /// without a restart.
    #[tokio::test]
    async fn a_query_is_answered_from_the_source_and_the_source_is_read_each_time() {
        let counting = Counting::new(vec![
            Ok(zone_with(vec![address("samba.ad.example.com", 2)])),
            Ok(zone_with(vec![address("samba.ad.example.com", 3)])),
        ]);
        let running = start(Arc::clone(&counting)).await;
        let addr = running.bind;

        let first = ask_udp(addr, &query("samba.ad.example.com.", RecordType::A, 1)).await;
        let second = ask_udp(addr, &query("samba.ad.example.com.", RecordType::A, 2)).await;
        running.stop().await;

        assert_eq!(first.response_code, ResponseCode::NoError);
        assert_eq!(
            first.answers[0].data,
            RData::A(Ipv4Addr::new(10, 0, 2, 2).into())
        );
        assert_eq!(
            second.answers[0].data,
            RData::A(Ipv4Addr::new(10, 0, 2, 3).into()),
            "the second answer is the second read, not a copy of the first"
        );
        assert_eq!(counting.reads.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    /// A zone that cannot be read is answered from the last one that could: a directory that fails
    /// one walk must not take the domain's name resolution with it, and DNS has a word for serving
    /// a stale answer - a TTL.
    #[tokio::test]
    async fn a_failed_read_is_answered_from_the_zone_read_before_it() {
        let counting = Counting::new(vec![
            Ok(zone_with(vec![address("samba.ad.example.com", 2)])),
            Err(zone::Error::NoZone {
                name: "ad.example.com".to_string(),
                dn: "dc=ad.example.com,cn=RRLDNS,dc=DomainDnsZones,dc=ad,dc=example,dc=com"
                    .to_string(),
            }),
        ]);
        let running = start(Arc::clone(&counting)).await;
        let addr = running.bind;

        let first = ask_udp(addr, &query("samba.ad.example.com.", RecordType::A, 1)).await;
        let second = ask_udp(addr, &query("samba.ad.example.com.", RecordType::A, 2)).await;
        running.stop().await;

        assert_eq!(first.response_code, ResponseCode::NoError);
        assert_eq!(second.response_code, ResponseCode::NoError);
        assert_eq!(
            second.answers[0].data,
            RData::A(Ipv4Addr::new(10, 0, 2, 2).into()),
            "the answer is the last successful read"
        );
    }

    /// Starts a listener over one source, the way the daemon builds one.
    async fn start(source: Arc<Counting>) -> Running {
        let handler =
            FromSource::new(source as Arc<dyn ZoneSource>, "ad.example.com").expect("a name");
        listen(
            "127.0.0.1:0".parse().expect("an address"),
            catalog_from(Arc::new(handler)),
        )
        .await
        .expect("started")
    }

    /// A name the zone does not hold is NXDOMAIN, and a type it does not hold is an empty answer:
    /// the two tell a client different things, and confusing them makes it stop asking.
    #[tokio::test]
    async fn an_absent_name_and_an_absent_type_answer_differently() {
        let running = listen(
            "127.0.0.1:0".parse().expect("an address"),
            catalog_with(zone()),
        )
        .await
        .expect("started");

        let absent = ask_udp(
            running.bind,
            &query("nobody.ad.example.com.", RecordType::A, 1),
        )
        .await;
        assert_eq!(absent.response_code, ResponseCode::NXDomain);

        let wrong_type = ask_udp(
            running.bind,
            &query("samba.ad.example.com.", RecordType::TXT, 2),
        )
        .await;
        assert_eq!(
            wrong_type.response_code,
            ResponseCode::NoError,
            "the name exists, so this is not NXDOMAIN"
        );
        assert!(wrong_type.answers.is_empty());
        running.stop().await;
    }
}
