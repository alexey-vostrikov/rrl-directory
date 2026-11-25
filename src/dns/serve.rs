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

use hickory_server::proto::dnssec::rdata::DNSSECRData;
use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType, TSigResponseContext,
};
use hickory_server::server::{Request, RequestInfo, Server};
use hickory_server::zone_handler::{
    AuthLookup, AxfrPolicy, AxfrRecords, Catalog, LookupControlFlow, LookupError, LookupOptions,
    LookupRecords, ZoneHandler, ZoneTransfer, ZoneType,
};

/// The whole zone as one transfer, from the records a lookup would answer with.
///
/// `hickory` transfers `RecordSet`s, one per owner and type, with the `RRSIG` attached to the set it
/// covers - so the grouping happens here rather than being handed over as a flat list. A signature in
/// a set of its own is a signature a client cannot use: it would arrive, and prove nothing.
///
/// The SOA is lifted out of the list and put at both ends, which is the shape RFC 5936 §2.2 requires:
/// a transfer starts and ends with the SOA, and a zone whose SOA also appears mid-stream is one a
/// strict consumer can read as two.
fn transfer_of(records: &[Record], lookup_options: LookupOptions) -> ZoneTransfer {
    use std::collections::BTreeMap;

    let mut sets: BTreeMap<(Name, RecordType), RecordSet> = BTreeMap::new();
    let mut signatures = Vec::new();
    for record in records {
        if record.record_type() == RecordType::RRSIG {
            signatures.push(record.clone());
            continue;
        }
        sets.entry((record.name.clone(), record.record_type()))
            .or_insert_with(|| RecordSet::new(record.name.clone(), record.record_type(), 0))
            .insert(record.clone(), 0);
    }
    for record in signatures {
        let covered = match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => rrsig.input().type_covered,
            // Not reachable through a zone this crate builds, and skipping is the honest answer: an
            // `RRSIG` whose data is not one covers nothing this can name.
            _ => continue,
        };
        if let Some(set) = sets.get_mut(&(record.name.clone(), covered)) {
            set.insert_rrsig(record);
        }
    }

    // A zone has exactly one `SOA`, at its apex - that is what makes it a zone.
    let apex = sets
        .keys()
        .find(|(_, rtype)| *rtype == RecordType::SOA)
        .cloned();
    let soa = apex.and_then(|key| sets.remove(&key));
    let (start_soa, end_soa) = match soa {
        Some(set) => (
            LookupRecords::new(lookup_options, Arc::new(set.clone())),
            // The closing `SOA` is asked for without DNSSEC: it is a terminator, and a signature on
            // it would be a signature in the middle of the stream rather than at the end where RFC
            // 5936 puts the last record.
            LookupRecords::new(LookupOptions::default(), Arc::new(set)),
        ),
        None => (LookupRecords::Empty, LookupRecords::Empty),
    };

    ZoneTransfer {
        start_soa,
        end_soa,
        records: AxfrRecords::new(
            lookup_options.dnssec_ok,
            sets.into_values().map(Arc::new).collect(),
        ),
    }
}

/// Whether this request may have the zone, and why not.
///
/// Split out because both handlers ask it and neither can answer it alone: the source address comes
/// from the request, the key from the signature, and the verdict from the configuration. `Err` carries
/// the response code and the context that signs it, which is `None` for a request that never signed.
fn permitted(
    request: &Request,
    info: &RequestInfo<'_>,
    keys: &crate::dns::tsig::Keys,
    allow: &crate::dns::axfr::Allow,
    now: u64,
) -> (Result<(), ResponseCode>, Option<TSigResponseContext>) {
    let (verdict, context) = keys.verified(request, now);
    if let Err(code) = verdict {
        // The signature was meant to prove something and did not. `NOTAUTH` with the matching TSIG
        // error is what the client needs to fix its own side; `REFUSED` would say "not for you".
        tracing::warn!(client = %info.src.ip(), id = info.metadata.id, "dns: a signed transfer did not verify");
        return (Err(code), context);
    }
    let key = verdict.ok().flatten();
    match allow.matched(info.src.ip(), key) {
        Some(grant) => {
            tracing::info!(
                client = %info.src.ip(),
                key = ?key.map(hickory_server::proto::rr::Name::to_ascii),
                grant,
                id = info.metadata.id,
                "dns: a zone transfer was permitted"
            );
            (Ok(()), context)
        }
        None => {
            // Refused, and refused loudly: a silent refusal is a backup that stops working and a
            // person who finds out when they need the backup.
            tracing::warn!(
                client = %info.src.ip(),
                key = ?key.map(hickory_server::proto::rr::Name::to_ascii),
                signed = key.is_some(),
                id = info.metadata.id,
                "dns: a zone transfer was refused: no dns.axfr.allow entry covers this client"
            );
            (Err(ResponseCode::Refused), context)
        }
    }
}

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
    /// The keys a signed request may use. Empty unless somebody set them, which is what a test and
    /// a stand without keys look like.
    keys: Arc<crate::dns::tsig::Keys>,
    /// Who may transfer the zone. Deny-all unless somebody set it, which is the behaviour this had
    /// before the policy existed.
    axfr: Arc<crate::dns::axfr::Allow>,
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
            keys: Arc::new(crate::dns::tsig::Keys::none()),
            axfr: Arc::new(crate::dns::axfr::Allow::deny_all()),
        })
    }

    /// The same zone, checking signatures against `keys`.
    #[must_use]
    pub fn with_keys(mut self, keys: Arc<crate::dns::tsig::Keys>) -> Self {
        self.keys = keys;
        self
    }

    /// The same zone, transferable by the clients `allow` names.
    #[must_use]
    pub fn with_axfr(mut self, allow: Arc<crate::dns::axfr::Allow>) -> Self {
        self.axfr = allow;
        self
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
        //
        // "Knows" includes the names that hold nothing themselves and exist because something is
        // below them - an empty non-terminal, `_msdcs` above `_ldap._tcp.dc._msdcs`. The `NSEC3` chain
        // publishes one for each of them (RFC 5155 §7.1), so answering `NXDOMAIN` for such a name
        // hands a validator a denial that contradicts the chain it was given: measured with `delv`,
        // which answered `broken trust chain` for `_msdcs.ad.example.com` while every other name
        // validated. The proof was right and the code was not.
        // The hashed owners of the chain are not names of the zone, and counting them as ancestors
        // would make `x.<hash>.ad.example.com` "exist". They are the one kind of owner here that has
        // to be left out.
        let hashed: Vec<LowerName> = records
            .iter()
            .filter(|record| record.record_type() == RecordType::NSEC3)
            .map(|record| LowerName::from(record.name.clone()))
            .collect();
        let known = records.iter().any(|record| {
            let owner = LowerName::from(record.name.clone());
            if hashed.contains(&owner) {
                return false;
            }
            // `name.zone_of(owner)` is "the query is the same as or above this owner", which is the
            // relation an empty non-terminal has to the records below it. Written the other way round
            // it is true for the apex and every name in the zone, so every miss became `NODATA` with a
            // denial that proved `NXDOMAIN` - measured with `delv`: `nosuch` came back `broken trust
            // chain` where it had validated a minute earlier.
            owner == *name || name.zone_of(&owner)
        });
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

    // The signatures travel inside their RRset, not beside it: `LookupOptions::rrset_with_rrigs`
    // decides whether they are emitted, which is the `DO` bit of the request. Attaching them here -
    // and only here - is what makes a `dig +dnssec` answer verifiable while an ordinary query stays
    // the size it was.
    //
    // A signature is matched to its set by the type it covers, because that is what an `RRSIG` says
    // about itself; matching by position would assume the records arrive in the order they were
    // signed.
    for record in records {
        let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data else {
            continue;
        };
        if LowerName::from(record.name.clone()) != *name {
            continue;
        }
        let covered = rrsig.input().type_covered;
        if let Some(set) = sets.iter_mut().find(|set| set.record_type() == covered) {
            Arc::make_mut(set).insert_rrsig(record.clone());
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

    /// `hickory` 0.26.3 declares `axfr_policy` but never consults it on this path - the trait's
    /// default `zone_transfer` answers `NotImp` - so the decision is made here instead.
    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }

    async fn zone_transfer(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
        now: u64,
    ) -> Option<(
        Result<ZoneTransfer, LookupError>,
        Option<TSigResponseContext>,
    )> {
        let info = match request.request_info() {
            Ok(info) => info,
            Err(err) => return Some((Err(err), None)),
        };
        let (verdict, context) = permitted(request, &info, &self.keys, &self.axfr, now);
        if let Err(code) = verdict {
            return Some((Err(LookupError::ResponseCode(code)), context));
        }
        Some((Ok(transfer_of(&self.records, lookup_options)), context))
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
        // The signature first: a request that cannot prove which key it speaks for is not one to
        // answer from the zone. The context goes back with the refusal, because RFC 8945 wants even
        // that answer to carry a TSIG - bare for `BADKEY`/`BADSIG`, signed for `BADTIME`.
        let (verdict, signer) = self.keys.authorize(request, crate::dns::tsig::now());
        if let Err(code) = verdict {
            return (
                LookupControlFlow::Continue(Err(LookupError::ResponseCode(code))),
                signer,
            );
        }

        // `Request` derefs to its `MessageRequest`, which carries the queries it was parsed from.
        // A request with no query at all is a form the caller has already rejected; answering
        // `Skip` here hands it to the next zone instead of inventing a name.
        let Some(question) = request.queries.queries().first() else {
            return (LookupControlFlow::Skip, signer);
        };
        let name = question.name().clone();
        let rtype = question.query_type();
        (self.answer(&name, rtype, lookup_options), signer)
    }

    /// RFC 2136 `OPCODE=5`. Verifies the signature and refuses the update: the machine that turns
    /// the message into `dnsRecord` writes is RRL-2.25.8, and a half-implemented one would answer
    /// `NOERROR` without changing anything - the one answer a client must never get.
    ///
    /// The signature is checked **before** that refusal on purpose. A key that does not verify earns
    /// `NOTAUTH` with `BADKEY`/`BADSIG`/`BADTIME`, which is a different statement from "this server
    /// does not accept updates", and a client that got the second could stop trying to fix a key that
    /// is actually wrong.
    async fn update(
        &self,
        update: &Request,
        now: u64,
    ) -> (Result<bool, ResponseCode>, Option<TSigResponseContext>) {
        let (verdict, signer) = self.keys.authorize(update, now);
        match verdict {
            Err(code) => (Err(code), signer),
            Ok(()) => (Err(ResponseCode::Refused), signer),
        }
    }

    async fn nsec3_records(
        &self,
        _info: hickory_server::zone_handler::Nsec3QueryInfo<'_>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        // A zone with no NSEC3PARAM holds no chain to walk: `Skip` hands the question to the next
        // handler, which is the honest answer for a zone that does not sign (RRL-2.25.10).
        LookupControlFlow::Skip
    }

    fn nx_proof_kind(&self) -> Option<&hickory_server::dnssec::NxProofKind> {
        // Nothing to prove absence with: the zone is not signed, and claiming a proof kind would
        // make the catalog ask for records that do not exist.
        None
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

    /// The keys a signed request may use, as they stand now.
    ///
    /// Default: none. A source that holds no directory - a zone handed over at start - cannot have
    /// keys, and answering `none` is the honest thing rather than an empty set pretending to be a
    /// decision.
    async fn keys(&self) -> Arc<crate::dns::tsig::Keys> {
        Arc::new(crate::dns::tsig::Keys::none())
    }

    /// The zone as it stands, signed - or unsigned when no key is configured.
    ///
    /// The default reads the zone and returns it as it is, which is what a source that holds no key
    /// material can honestly do. A source that has keys overrides this and signs at read time, which
    /// is what keeps a signature consistent with an RFC 2136 update applied a moment ago.
    async fn signed(&self) -> Result<Vec<Record>, crate::dns::zone::Error> {
        Ok(self.read().await?.records)
    }

    /// Applies one RFC 2136 update message, or says why not.
    ///
    /// Default: refused. A source with no directory to write to cannot register anything, and
    /// `NotImp` is the honest code rather than a silent success.
    async fn apply_update(
        &self,
        _updates: &[Record],
    ) -> Result<crate::dns::update::Plan, ResponseCode> {
        Err(ResponseCode::NotImp)
    }
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
    /// The keys `dns.keys` names, beside the ones the directory holds.
    configured: Vec<crate::dns::config::TsigKey>,
    /// The keys that sign the zone, or none: a zone served unsigned is what every zone was until
    /// `dns.dnssec` existed.
    signers: std::sync::Arc<crate::dns::dnssec::Signers>,
}

impl InDirectory {
    /// Reads `dns_name` out of `source`'s directory.
    pub fn new(source: Arc<crate::reload::Source>, base_dn: &str, dns_name: &str) -> Self {
        Self {
            source,
            base_dn: base_dn.to_string(),
            dns_name: dns_name.trim_end_matches('.').to_string(),
            configured: Vec::new(),
            signers: std::sync::Arc::new(crate::dns::dnssec::Signers::none()),
        }
    }

    /// The same source, signing every answer with `signers`.
    #[must_use]
    pub fn with_signers(mut self, signers: std::sync::Arc<crate::dns::dnssec::Signers>) -> Self {
        self.signers = signers;
        self
    }

    /// The same source, also accepting the keys `dns.keys` names.
    ///
    /// Both lists are served, because they answer different questions: `dns.keys` is what a machine
    /// with no directory client can be given, and a key entry is what can be issued at runtime.
    #[must_use]
    pub fn with_configured_keys(mut self, configured: Vec<crate::dns::config::TsigKey>) -> Self {
        self.configured = configured;
        self
    }
}

#[async_trait::async_trait]
impl ZoneSource for InDirectory {
    async fn read(&self) -> Result<crate::dns::zone::Zone, crate::dns::zone::Error> {
        let directory = self.source.directory().await;
        crate::dns::zone::Zone::read(&directory, &self.base_dn, &self.dns_name)
    }

    /// The zone with its `RRSIG`s, made now.
    ///
    /// Signing here rather than at start is what keeps a signature honest across an RFC 2136 update:
    /// the zone is read per query, so the signature covers the zone as it is at the moment of the
    /// answer. A failure to sign is logged and the zone is answered **unsigned** - a validator then
    /// reports unproven data, which is true, instead of the server refusing to answer at all.
    async fn signed(&self) -> Result<Vec<Record>, crate::dns::zone::Error> {
        let zone = self.read().await?;
        if !zone.unserved.is_empty() {
            tracing::debug!(
                types = ?zone.unserved,
                "dns: the zone holds records this build cannot render"
            );
        }
        if self.signers.is_empty() {
            return Ok(zone.records);
        }
        let now = crate::dns::tsig::now();
        match self.signers.sign(&zone.records, now) {
            Ok(signed) => Ok(signed),
            Err(err) => {
                tracing::error!(%err, "dns: the zone could not be signed; answering it unsigned");
                Ok(zone.records)
            }
        }
    }

    /// Read on every check, so an issued key works and a deleted one stops working without a
    /// restart. A broken entry is reported once per check at `warn` - it is the operator's typo, and
    /// the alternative is refusing to verify every signature in the zone over it.
    async fn keys(&self) -> Arc<crate::dns::tsig::Keys> {
        let directory = self.source.directory().await;
        let (from_directory, broken) = crate::dns::keys::load(&directory, &self.base_dn);
        for reason in &broken {
            tracing::warn!(reason, "dns: a key entry is not usable and is not accepted");
        }

        let mut keys = self.configured.clone();
        keys.extend(from_directory);
        match crate::dns::tsig::Keys::new(&keys) {
            Ok(keys) => Arc::new(keys),
            Err(err) => {
                // A configured key that does not build is a start-up failure and was already
                // refused there; one read from an entry that parsed but will not build is refused
                // here rather than answering with a key set that silently lost an entry.
                tracing::error!(%err, "dns: the key set could not be built");
                Arc::new(crate::dns::tsig::Keys::none())
            }
        }
    }

    /// Decides the update against the zone as it stands, then applies the whole change set through
    /// the funnel every other write uses - one transaction, the journal, the schema, replication.
    ///
    /// The plan is made against one read of the directory and applied to whatever is there when the
    /// write lands. That window is the same one any read-then-write takes, and it is closed by the
    /// grant check and by the fact that a zone has one writer: `Source::apply` serialises.
    async fn apply_update(
        &self,
        updates: &[hickory_server::proto::rr::Record],
    ) -> Result<crate::dns::update::Plan, ResponseCode> {
        let zone_dn = crate::dns::zone::zone_dn(&self.base_dn, &self.dns_name);
        let directory = self.source.directory().await;
        let plan = crate::dns::update::plan(&directory, &zone_dn, &self.dns_name, updates)?;

        let changes: Vec<crate::backend::EntryChange> = plan
            .changes
            .iter()
            .map(|change| match change {
                crate::dns::update::Change::Put { entry, .. } => {
                    crate::backend::EntryChange::Upsert {
                        entry: entry.clone(),
                    }
                }
                crate::dns::update::Change::Remove { dn } => crate::backend::EntryChange::Delete {
                    dn: dn.clone(),
                    kind: None,
                },
            })
            .collect();

        self.source.apply(&changes).await.map_err(|err| {
            tracing::error!(%err, "dns: the update could not be written to the directory");
            ResponseCode::ServFail
        })?;
        Ok(plan)
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
    /// What the last successful read returned, for the case where the next one fails. The records
    /// rather than the zone: the signed set is what an answer is built from.
    last: std::sync::Mutex<Option<Vec<Record>>>,
    /// How this zone proves absence, or `None` when it publishes no denials. `hickory` reads this to
    /// decide whether to ask for `NSEC3`s at all, so it is a fact about the zone rather than a
    /// decision taken per query.
    proof: Option<hickory_server::dnssec::NxProofKind>,
    /// The keys and the chain parameters, so a denial can be built without asking the source twice.
    signers: std::sync::Arc<crate::dns::dnssec::Signers>,
    /// Who may transfer this zone.
    axfr: Arc<crate::dns::axfr::Allow>,
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
            proof: None,
            signers: std::sync::Arc::new(crate::dns::dnssec::Signers::none()),
            axfr: Arc::new(crate::dns::axfr::Allow::deny_all()),
        })
    }

    /// The same handler, transferable by the clients `allow` names.
    #[must_use]
    pub fn with_axfr(mut self, allow: Arc<crate::dns::axfr::Allow>) -> Self {
        self.axfr = allow;
        self
    }

    /// The same handler, signing and proving with `signers`.
    #[must_use]
    pub fn with_signers(mut self, signers: std::sync::Arc<crate::dns::dnssec::Signers>) -> Self {
        if signers.has_denials() {
            self.proof = Some(hickory_server::dnssec::NxProofKind::Nsec3 {
                algorithm: hickory_server::proto::dnssec::Nsec3HashAlgorithm::SHA1,
                salt: signers.nsec3_salt().into(),
                iterations: signers.nsec3_iterations(),
                opt_out: false,
            });
        }
        self.signers = signers;
        self
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
        // `signed` and not `read`: the records come back with their `RRSIG`s, made at this moment
        // against the zone as it stands. That is what keeps a signature consistent with an update
        // applied a second ago - and an unsigned zone is what a source without keys returns.
        match self.source.signed().await {
            Ok(records) => {
                if let Ok(mut held) = self.last.lock() {
                    *held = Some(records.clone());
                }
                answer_over(&records, name, rtype, options)
            }
            Err(err) => {
                tracing::warn!(%err, "dns: the zone could not be read");
                let previous = self.last.lock().ok().and_then(|held| held.clone());
                match previous {
                    Some(records) => {
                        tracing::warn!(
                            records = records.len(),
                            "dns: answering from the zone read before this failure"
                        );
                        answer_over(&records, name, rtype, options)
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
        // Unread by `hickory` 0.26.3 on this path; the decision is in `zone_transfer` below.
        AxfrPolicy::Deny
    }

    async fn zone_transfer(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
        now: u64,
    ) -> Option<(
        Result<ZoneTransfer, LookupError>,
        Option<TSigResponseContext>,
    )> {
        let info = match request.request_info() {
            Ok(info) => info,
            Err(err) => return Some((Err(err), None)),
        };
        // The keys as they stand now, not as they stood at start: a key added to the directory
        // works for a transfer without a restart, and the same is true of one removed.
        let keys = self.source.keys().await;
        let (verdict, context) = permitted(request, &info, &keys, &self.axfr, now);
        if let Err(code) = verdict {
            return Some((Err(LookupError::ResponseCode(code)), context));
        }

        // The zone as a lookup would answer it, signed - so a client transferring gets the same
        // records, with the same signatures, that it would get one name at a time.
        let records = match self.source.signed().await {
            Ok(records) => records,
            Err(err) => {
                tracing::error!(error = %err, "dns: the zone could not be read for a transfer");
                return Some((
                    Err(LookupError::ResponseCode(ResponseCode::ServFail)),
                    context,
                ));
            }
        };
        Some((Ok(transfer_of(&records, lookup_options)), context))
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
        // The same order as `InMemory`: the signature decides whether there is a question to answer.
        // The key set is asked of the source on every check, which is what makes an issued key work
        // and a deleted one stop working without a restart.
        let keys = self.source.keys().await;
        let (verdict, signer) = keys.authorize(request, crate::dns::tsig::now());
        if let Err(code) = verdict {
            return (
                LookupControlFlow::Continue(Err(LookupError::ResponseCode(code))),
                signer,
            );
        }
        let Some(question) = request.queries.queries().first() else {
            return (LookupControlFlow::Skip, signer);
        };
        let name = question.name().clone();
        let rtype = question.query_type();
        (self.answer(&name, rtype, lookup_options).await, signer)
    }

    /// RFC 2136 `OPCODE=5`. Verifies the signature and refuses the update: the machine that turns
    /// the message into `dnsRecord` writes is RRL-2.25.8, and a half-implemented one would answer
    /// `NOERROR` without changing anything - the one answer a client must never get.
    ///
    /// The signature is checked **before** that refusal on purpose. A key that does not verify earns
    /// `NOTAUTH` with `BADKEY`/`BADSIG`/`BADTIME`, which is a different statement from "this server
    /// does not accept updates", and a client that got the second could stop trying to fix a key that
    /// is actually wrong.
    async fn update(
        &self,
        update: &Request,
        now: u64,
    ) -> (Result<bool, ResponseCode>, Option<TSigResponseContext>) {
        // The order is the whole point of this body: the signature is checked first, so a key that
        // does not verify earns `NOTAUTH` with the TSIG error that says why, and only a client that
        // proved itself reaches the update itself. A client told `NOTAUTH` when the real problem was
        // something else would go and rewrite a key that is fine.
        let keys = self.source.keys().await;
        let (verdict, signer) = keys.authorize(update, now);
        if let Err(code) = verdict {
            return (Err(code), signer);
        }

        // An unsigned update is refused, and the decision is recorded here because the task asked
        // for one: `REFUSED` says "this server does not take an unsigned update", which is a policy
        // the client can act on, while `NOTAUTH/BADKEY` would say a key was wrong - and there was no
        // key. A zone in a domain is changed only by a client that proved which key it speaks for.
        if signer.is_none() {
            tracing::warn!("dns: an unsigned update was refused");
            return (Err(ResponseCode::Refused), None);
        }

        match self.source.apply_update(&update.authorities).await {
            Ok(plan) => {
                for line in &plan.applied {
                    tracing::info!(key = ?signer.as_ref().map(|_| "signed"), op = %line, serial = plan.serial, "dns: update applied");
                }
                (Ok(true), signer)
            }
            Err(code) => (Err(code), signer),
        }
    }

    async fn nsec3_records(
        &self,
        info: hickory_server::zone_handler::Nsec3QueryInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        // The chain is built from the zone as it stands now, which is the only chain that proves
        // anything: an update changes the set of hashes, and a chain one update behind makes a
        // validator reject the whole zone rather than one answer.
        let Ok(signed) = self.source.signed().await else {
            return LookupControlFlow::Continue(Err(LookupError::ResponseCode(
                ResponseCode::ServFail,
            )));
        };
        let qname = hickory_server::proto::rr::Name::from(info.qname.clone());
        let Some(proof) = self.signers.denial(&signed, &qname, info.qtype) else {
            // No chain, or no proof for this name: `Skip` rather than a partial answer, because a
            // denial with one record missing is one every validator rejects.
            return LookupControlFlow::Skip;
        };

        let sets = crate::dns::nsec3::answer_sets(proof);
        LookupControlFlow::Continue(Ok(AuthLookup::Records {
            answers: LookupRecords::many(lookup_options, sets),
            additionals: None,
        }))
    }

    fn nx_proof_kind(&self) -> Option<&hickory_server::dnssec::NxProofKind> {
        // `Some` only when the zone really publishes a chain: telling the catalog to ask for
        // `NSEC3`s a zone does not have is how an answer comes back with no proof in it.
        self.proof.as_ref()
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        // `NSEC` walking is what `NSEC3` exists to avoid; this zone publishes no unhashed chain.
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
    // `dns.keys` beside the entries the directory holds: both are served, and both have to parse
    // before a port is taken.
    let configured = forward.keys.clone();
    // The signing keys, loaded here for the same reason the TSIG keys are: a key that does not load
    // is a start-up error with the port not yet taken, rather than a zone that answers unsigned and
    // a validator that reports it at a client, hours later.
    let signers = crate::dns::dnssec::Signers::new(&forward.dnssec, &forward.dns_domain)?;
    if !signers.is_empty() {
        tracing::info!(
            keys = ?signers.describe(),
            "dns: the zone is signed; a validator needs one of these DNSKEYs as its trust anchor"
        );
    }
    let signers = Arc::new(signers);
    let in_directory = InDirectory::new(Arc::clone(&source), base_dn, dns_name)
        .with_configured_keys(configured.clone())
        .with_signers(Arc::clone(&signers));
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
    // Built here rather than inside the handler: a key that does not load is a start-up error, and
    // this is the only place in this path that can return one. The handler itself asks the source on
    // every check, so an issued key needs no restart - this set is the one `Answering` answers with
    // when it refuses a name it does not hold.
    let keys = Arc::new(crate::dns::tsig::Keys::new(&configured)?);
    if !keys.is_empty() {
        tracing::info!(keys = ?keys.names(), "dns: signed requests are checked against these keys");
    }
    let axfr = Arc::new(forward.axfr.clone());
    if !axfr.is_empty() {
        tracing::info!("dns: the zone may be transferred by the clients dns.axfr.allow names");
    }
    let handler = FromSource::new(Arc::new(in_directory), dns_name)
        .ok_or_else(|| format!("dns zone '{dns_name}' is not a DNS name"))?
        .with_signers(Arc::clone(&signers))
        .with_axfr(axfr);
    let handler = Arc::new(handler);
    let ours = handler.origin().clone();
    let catalog = catalog_from(Arc::clone(&handler));
    // The forwarder is told the bind address, because the settings come from the configuration and
    // the port may have been chosen by the kernel: a listener that reported a different address than
    // it took would be one nobody can find.
    let forward = crate::dns::config::Settings { bind, ..forward };
    listen(bind, Answering::new(catalog, ours, forward).with_keys(keys)).await
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
    /// The keys a signed request may use, shared with the zone handler.
    ///
    /// Here as well as there because two kinds of request never reach a zone handler: one for a
    /// name that is not ours, and one whose signature names a key it does not have. Both are still
    /// answered, and RFC 8945 wants an answer to a signed request to say what happened to the
    /// signature - `REFUSED` signed with the same key, or `NOTAUTH` with `BADKEY`.
    keys: Arc<crate::dns::tsig::Keys>,
}

impl Answering {
    /// A handler over `catalog` (which answers `ours`) and `forward` for the rest.
    pub fn new(catalog: Catalog, ours: LowerName, forward: crate::dns::config::Settings) -> Self {
        Self {
            catalog,
            ours,
            forward,
            keys: Arc::new(crate::dns::tsig::Keys::none()),
        }
    }

    /// The same handler, checking signatures against `keys`.
    #[must_use]
    pub fn with_keys(mut self, keys: Arc<crate::dns::tsig::Keys>) -> Self {
        self.keys = keys;
        self
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
    async fn handle_request<
        R: hickory_server::server::ResponseHandler,
        T: hickory_server::net::runtime::Time,
    >(
        &self,
        request: &Request,
        response_handle: R,
    ) -> hickory_server::server::ResponseInfo {
        let Some(query) = request.queries.queries().first() else {
            return self
                .catalog
                .handle_request::<R, T>(request, response_handle)
                .await;
        };
        if self.is_ours(query.name()) {
            return self
                .catalog
                .handle_request::<R, T>(request, response_handle)
                .await;
        }
        // A signed question for a name that is not ours has two honest answers and no third: a
        // signature that does not verify earns `NOTAUTH` with the TSIG error that says why, and one
        // that does earns `REFUSED` - signed with the same key, because an unsigned answer to a
        // signed question is a protocol error the client can only report as a timeout.
        if request.signature.is_some() {
            let (verdict, signer) = self.keys.authorize(request, crate::dns::tsig::now());
            let code = match verdict {
                Ok(()) => {
                    tracing::debug!(
                        name = %query.name(),
                        "dns: a signed query for a name this server does not hold: refused, not forwarded"
                    );
                    ResponseCode::Refused
                }
                Err(code) => code,
            };
            return answer_with(
                request,
                response_handle,
                code,
                Vec::new(),
                Vec::new(),
                signer,
            )
            .await;
        }
        if !crate::dns::forward::is_forwardable(query.query_type()) {
            return answer_with(
                request,
                response_handle,
                ResponseCode::Refused,
                Vec::new(),
                Vec::new(),
                None,
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
                None,
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
                answer_with(request, response_handle, code, answers, authorities, None).await
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
                    None,
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
    signer: Option<TSigResponseContext>,
) -> hickory_server::server::ResponseInfo {
    use hickory_server::proto::serialize::binary::BinEncoder;
    use hickory_server::zone_handler::MessageResponseBuilder;

    let mut metadata =
        hickory_server::proto::op::Metadata::response_from_request(&request.metadata);
    metadata.response_code = code;
    metadata.authoritative = false;
    // The recursion flag describes this server's own behaviour: it forwarded, so it was available.
    metadata.recursion_available = !answers.is_empty() || code == ResponseCode::NXDomain;

    // Two builds when a signature is asked for, and that is not a style choice: the MAC covers the
    // message as it travels, `destructive_emit` consumes the response to produce those octets, and a
    // signature added afterwards would have to be covered by a second encoding - which is a
    // different byte stream the moment name compression picks another pointer. So the octets are
    // produced from one copy, signed, and the signature is set on the copy that is sent.
    let signature = match signer {
        None => None,
        Some(signer) => {
            let tbs_response = MessageResponseBuilder::new(&request.queries, request.edns.as_ref())
                .build(
                    metadata,
                    answers.iter(),
                    authorities.iter(),
                    std::iter::empty(),
                    std::iter::empty(),
                );
            let mut tbs = Vec::with_capacity(256);
            let mut encoder = BinEncoder::new(&mut tbs);
            let mut signature = None;
            match tbs_response.destructive_emit(&mut encoder) {
                Ok(_counts) => match signer.sign(&tbs) {
                    Ok(record) => signature = Some(record),
                    // Reported, not retried with a different code: an HMAC failure here means this
                    // machine cannot produce the answer at all. The client rejects an unsigned answer
                    // to a signed question, which is the right outcome and needs no second path.
                    Err(err) => tracing::error!(%err, "dns: the answer could not be signed"),
                },
                Err(err) => {
                    tracing::error!(%err, "dns: the answer could not be encoded for signing")
                }
            }
            signature
        }
    };

    let mut response = MessageResponseBuilder::new(&request.queries, request.edns.as_ref()).build(
        metadata,
        answers.iter(),
        authorities.iter(),
        std::iter::empty(),
        std::iter::empty(),
    );
    if let Some(signature) = signature {
        response.set_signature(signature);
    }

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
