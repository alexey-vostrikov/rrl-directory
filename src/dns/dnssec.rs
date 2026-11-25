//! DNSSEC: the zone signed, so a validator can tell a corrected answer from an invented one.
//!
//! # What is ours and what is the crate's
//!
//! The signature, the canonical form of the RRset and the `RRSIG` RDATA are `hickory-proto`'s
//! (`dnssec::tbs`, `dnssec::rdata`). A second implementation of "which octets were signed" would be
//! a second opinion about it, and DNSSEC is exactly that opinion. What is here is the part a library
//! cannot decide for a server:
//!
//! * which key signs, and how it is read from disk - PKCS#8 DER, the format `ring` and every tool
//!   that emits a modern key agree on;
//! * the key tag that goes into every `RRSIG` and into the parent's `DS`: wrong, and the signature
//!   is valid and unfindable;
//! * the validity window, which has to start in the past or a validator whose clock lags rejects a
//!   fresh signature;
//! * the `RRSIG`'s TTL, which RFC 4034 §3 requires to equal the TTL of what it covers, and the
//!   RRset's own original TTL inside the signature.
//!
//! # Why signing happens where the answer is assembled
//!
//! A signature covers an RRset as it stands. An update that changes a record and leaves the old
//! signature beside it produces the exact failure DNSSEC exists to prevent: the validator sees a
//! signature that does not match, answers `SERVFAIL` for the whole name, and the zone looks broken
//! rather than unsigned. So the signature is made at read time - the same path an RFC 2136 update
//! goes through - and an update needs no second hook to stay consistent.
//!
//! # Algorithms
//!
//! 13 (ECDSA P-256), 14 (P-384), 15 (Ed25519). RSA is absent on purpose: a 2048-bit RSA signature
//! is 256 octets of every answer, per RRset, and SHA-1 is not a thing to offer new software.
//! Verifying an older algorithm is a different function, and not this one.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use hickory_server::proto::dnssec::crypto::{EcdsaSigningKey, Ed25519SigningKey};
use hickory_server::proto::dnssec::rdata::{DNSKEY, DNSSECRData};
use hickory_server::proto::dnssec::{Algorithm, DnssecSigner};
use hickory_server::proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
use rustls::pki_types::PrivatePkcs8KeyDer;
use time::OffsetDateTime;

/// How far in the past a signature starts.
///
/// RFC 4034 §3 requires the inception to be no later than the moment of signing, and every
/// implementation backdates it: a validator whose clock lags by minutes would otherwise reject a
/// signature that is merely newer than its own idea of now. An hour is what BIND and `ldns` use.
const INCEPTION_BACKDATE: i64 = 3600;

/// The octets of a private key, from a PEM file or a DER one.
///
/// A PEM file is a DER document between `-----BEGIN <label>-----` and `-----END <label>-----`, with
/// the base64 wrapped at whatever width the tool chose. Nothing else in it matters, so the markers
/// are stripped and the rest decoded - and a file with a header whose body does not decode is named
/// as such rather than handed to `ring` to fail with a message about DER.
fn decode_key_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.is_empty() {
        return Err("the file is empty".to_string());
    }

    // A DER SEQUENCE starts with `0x30`. Anything else that is not PEM is reported as such, because
    // "ring error: InvalidEncoding" does not tell an operator which of the two they wrote.
    let looks_pem = bytes.starts_with(b"-----BEGIN") || bytes.starts_with(b"\n-----BEGIN");
    if !looks_pem {
        if bytes[0] != 0x30 {
            return Err(format!(
                "the file is neither PEM nor DER: it starts with 0x{:02x}, and a DER PKCS#8 key \
                 starts with 0x30 (a '0' in ASCII)",
                bytes[0]
            ));
        }
        return Ok(bytes.to_vec());
    }

    let text = std::str::from_utf8(bytes)
        .map_err(|_| "the file says it is PEM but is not text".to_string())?;
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    if body.is_empty() {
        return Err("the PEM block is empty".to_string());
    }
    crate::model::decode_binary(&body).ok_or_else(|| "the PEM body is not base64".to_string())
}

/// The TTL a `DNSKEY` and its `RRSIG` carry.
///
/// 3600 is what BIND publishes for a zone key: long enough that a resolver is not asking on every
/// query, short enough that a rollover is visible within the hour.
const KEY_TTL: u32 = 3600;

/// One `dns.dnssec.keys` entry as it is written.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// `ecdsa-p256-sha256` (13), `ecdsa-p384-sha384` (14), `ed25519` (15) - or the number.
    pub algorithm: String,
    /// The private key in PKCS#8 DER: what `openssl genpkey -outform DER` writes.
    pub file: PathBuf,
}

/// The `dns.dnssec` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnssecConfig {
    /// The keys that sign the zone. Two at once is what a rollover looks like: both publish a
    /// `DNSKEY`, both sign, and the old one stops once its signatures have expired.
    pub keys: Vec<KeyConfig>,
    /// How long a signature is valid, in days. Thirty unless said otherwise.
    pub signature_days: Option<u32>,
    /// Publish `NSEC3` denials, so a validator accepts `NXDOMAIN` as well as the positive answers.
    ///
    /// Off by default, and that is honest rather than lazy: a zone whose denials are unproven is one
    /// where every positive answer validates and every miss is `SERVFAIL` - a state a server should
    /// enter deliberately. `Some` with an empty salt is what RFC 9276 recommends for a new zone.
    pub nsec3: Option<Nsec3Config>,
}

/// The knobs of a zone's `NSEC3` chain.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Nsec3Config {
    /// The salt, base64. Absent means empty, which several registries publish.
    pub salt: Option<String>,
    /// Extra hash iterations. Zero unless said otherwise - RFC 9276 §3.1.
    pub iterations: Option<u16>,
}

/// A key that loaded: what signs, and what the zone has to publish for a validator to find it.
pub struct Key {
    signer: DnssecSigner,
    key_tag: u16,
    algorithm: Algorithm,
}

/// By tag and algorithm, never by material: `DnssecSigner` holds the private key and has no `Debug`
/// of its own, which is the right default - a struct that printed it is one whose key reaches a log.
impl std::fmt::Debug for Key {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Key")
            .field("key_tag", &self.key_tag)
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl Key {
    /// Reads one key, or says which file and which algorithm are wrong.
    ///
    /// Every failure is a start-up failure. A key that does not load is a zone that silently answers
    /// unsigned - which a validator reports as `SERVFAIL`, at a client, hours later.
    fn load(config: &KeyConfig, origin: &Name, validity: Duration) -> Result<Self, String> {
        let algorithm = algorithm_from(&config.algorithm).ok_or_else(|| {
            format!(
                "dns.dnssec.keys names algorithm '{}', which this build does not sign with: use \
                 ecdsa-p256-sha256, ecdsa-p384-sha384 or ed25519 (or 13, 14, 15)",
                config.algorithm
            )
        })?;

        // The private key is a secret like any other, and a world-readable one is a secret in name
        // only: a `0600` file is what `master.key` beside it already is. Refused rather than warned,
        // because a warning at start is a line nobody reads and the exposure is permanent - and it
        // is the same call this crate makes for every other secret it holds.
        if let Ok(metadata) = std::fs::metadata(&config.file) {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "dns.dnssec.keys: {} is readable by others (mode {mode:o}): a signing key has \
                     to be 0600, or anybody on the host can sign a zone as this server",
                    config.file.display()
                ));
            }
        }

        let bytes = std::fs::read(&config.file).map_err(|err| {
            format!(
                "dns.dnssec.keys: {} could not be read: {err}",
                config.file.display()
            )
        })?;
        // PEM or DER, both, because both are what the tools emit: `openssl genpkey` writes PEM
        // unless told otherwise, `dnssec-keygen` and `ldap-keygen` write their own, and a DER dump
        // is what a secret store hands out. Sniffing the header is the whole difference - a PEM
        // file is the same octets between two markers.
        let der = decode_key_bytes(&bytes)
            .map_err(|detail| format!("dns.dnssec.keys: {}: {detail}", config.file.display()))?;
        let pkcs8 = PrivatePkcs8KeyDer::from(der);

        // One arm per algorithm, because a P-256 key and an Ed25519 key are different types in
        // `ring` and the only thing they share is the trait this box erases.
        let boxed: Box<dyn hickory_server::proto::dnssec::SigningKey> = match algorithm {
            Algorithm::ED25519 => Box::new(Ed25519SigningKey::from_pkcs8(&pkcs8).map_err(|err| {
                // `ring` wants PKCS#8 **v2** for Ed25519 - version 1 plus the `[1] publicKey` field
                // (RFC 8410 §10.3) - and `openssl pkey -outform DER` writes v1, so its keys are
                // rejected with a message that says nothing an operator can act on. Measured: the
                // two encodings differ in two octets (`0201 00` against `0201 01`, and the trailing
                // public key), and v1 is what every openssl invocation produces.
                format!(
                    "{}: {err}. An Ed25519 key has to be PKCS#8 **v2** - version 1 with the public \
                     key attached, RFC 8410 §10.3. `openssl pkey` writes v1, which `ring` refuses: \
                     use a key generated by the library (or `ldns-keygen -a ED25519`), or wrap the \
                     v2 document. ECDSA keys (13, 14) have no such requirement.",
                    config.file.display()
                )
            })?),
            other => Box::new(
                EcdsaSigningKey::from_pkcs8(&pkcs8, other)
                    .map_err(|err| format!("{}: {err}", config.file.display()))?,
            ),
        };

        let public_key = boxed
            .to_public_key()
            .map_err(|err| format!("{}: {err}", config.file.display()))?;
        // `DNSKEY::from_key` sets flags 257: the zone bit (256) and the SEP bit (1). SEP is what a
        // parent's `DS` points at, and a single key that both signs the zone and stands in for it is
        // what a zone with one key has - a two-key KSK/ZSK split is RRL-2.25.11.
        let dnskey = DNSKEY::from_key(&public_key);

        // The signer name is the zone apex: it is what an `RRSIG` names as the owner of the key, and
        // a validator picks the `DNSKEY` to try by it.
        let signer = DnssecSigner::new(dnskey, boxed, origin.clone(), validity);
        let key_tag = signer.calculate_key_tag().map_err(|err| {
            format!(
                "{}: the key tag could not be computed: {err}",
                config.file.display()
            )
        })?;

        Ok(Self {
            signer,
            key_tag,
            algorithm,
        })
    }

    /// The key tag, which every `RRSIG` carries and the parent's `DS` names.
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The `DNSKEY` record a validator looks up by tag.
    pub fn dnskey_record(&self, origin: &Name) -> Record {
        let mut record = Record::from_rdata(
            origin.clone(),
            KEY_TTL,
            RData::DNSSEC(DNSSECRData::DNSKEY(self.signer.to_dnskey())),
        );
        record.dns_class = DNSClass::IN;
        record
    }
}

/// The keys a zone is signed with.
#[derive(Debug, Default)]
pub struct Signers {
    keys: Vec<Key>,
    origin: Option<Name>,
    /// The `NSEC3` parameters, when the zone publishes denials. `None` means positive answers only.
    nsec3: Option<crate::dns::nsec3::Params>,
}

impl Signers {
    /// No keys: the zone is served unsigned, which is what a server without `dns.dnssec` does.
    pub fn none() -> Self {
        Self::default()
    }

    /// Loads the configured keys for the zone `origin` (`ad.example.com`).
    pub fn new(config: &DnssecConfig, origin: &str) -> Result<Self, String> {
        let validity = match config.signature_days {
            None => Duration::from_secs(30 * 24 * 3600),
            // A zero-day signature expires on the instant it is made, so the configuration says
            // something impossible. Refused rather than quietly replaced by the default.
            Some(0) => {
                return Err(
                    "dns.dnssec.signature_days is 0: a signature that expires on the \
                            instant it is made validates nothing"
                        .to_string(),
                );
            }
            Some(days) => Duration::from_secs(u64::from(days) * 24 * 3600),
        };

        let apex = Name::from_ascii(origin.trim_end_matches('.')).map_err(|err| {
            format!("dns.dnssec: the zone name '{origin}' is not a DNS name: {err}")
        })?;
        let mut apex = apex;
        apex.set_fqdn(true);

        let nsec3 = match &config.nsec3 {
            None => None,
            Some(nsec3) => {
                let salt = match nsec3.salt.as_deref() {
                    None => Vec::new(),
                    Some(text) => crate::model::decode_binary(text).ok_or_else(|| {
                        format!(
                            "dns.dnssec.nsec3.salt is '{text}', which is not base64: a salt is \
                             octets, written the way every DNSSEC tool prints them"
                        )
                    })?,
                };
                Some(crate::dns::nsec3::Params {
                    salt,
                    iterations: nsec3.iterations.unwrap_or(0),
                })
            }
        };

        let mut keys = Vec::with_capacity(config.keys.len());
        for key in &config.keys {
            keys.push(Key::load(key, &apex, validity)?);
        }
        if keys.is_empty() {
            return Ok(Self::none());
        }
        Ok(Self {
            keys,
            origin: Some(apex),
            nsec3,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// `(key tag, algorithm)` per key, for the line an operator reads at start.
    pub fn describe(&self) -> Vec<(u16, String)> {
        self.keys
            .iter()
            .map(|key| (key.key_tag, format!("{:?}", key.algorithm)))
            .collect()
    }

    /// The zone signed: the `DNSKEY`s at the apex plus one `RRSIG` per RRset per key.
    ///
    /// `now` is seconds since the epoch. A failure returns the records **unsigned**, and the caller
    /// logs it: a listener that refuses every query because one signature failed is worse than one
    /// that answers, and an unsigned answer is what a validator reports as unproven rather than as
    /// a broken domain.
    pub fn sign(&self, records: &[Record], now: u64) -> Result<Vec<Record>, String> {
        let Some(origin) = self.origin.as_ref() else {
            return Ok(records.to_vec());
        };

        let mut signed = records.to_vec();
        // The keys are part of the zone: a validator asks for them first, and they are signed like
        // everything else. A zone that left its own key unsigned is a zone nothing can trust.
        for key in &self.keys {
            signed.push(key.dnskey_record(origin));
        }

        // Then the denial chain, built from the records as they stand - an update changes the set of
        // hashes, so a chain computed anywhere but here would be one update behind.
        if let Some(params) = &self.nsec3 {
            signed.push(crate::dns::nsec3::param_record(origin, params, KEY_TTL));
            // `signed: true` - the records about to be signed, so every bitmap names `RRSIG`.
            let chain = crate::dns::nsec3::chain(origin, &signed, params, KEY_TTL, true)
                .map_err(|err| format!("the NSEC3 chain could not be built: {err}"))?;
            signed.extend(chain);
        }

        // Seconds past the wire form's range would be a date in 2106; a clock that far out is a
        // broken host, and a signature that cannot be expressed is better reported than truncated.
        let inception = i64::try_from(now)
            .map_err(|_| format!("the clock reads {now}, past 2106"))?
            - INCEPTION_BACKDATE;
        let inception = OffsetDateTime::from_unix_timestamp(inception)
            .map_err(|err| format!("the inception is not a timestamp: {err}"))?;

        let sets = rrsets(&signed)?;
        let mut rrsigs = Vec::with_capacity(sets.len() * self.keys.len());
        for set in &sets {
            for key in &self.keys {
                let rrsig = hickory_server::proto::dnssec::rdata::RRSIG::from_rrset(
                    set,
                    DNSClass::IN,
                    inception,
                    &key.signer,
                )
                .map_err(|err| {
                    format!(
                        "{} {:?} could not be signed: {err}",
                        set.name(),
                        set.record_type()
                    )
                })?;

                // RFC 4034 §3: the TTL of an `RRSIG` equals the TTL of the RRset it covers. A
                // signature that outlives its records is cached longer than the answer it proves.
                let mut record = Record::from_rdata(
                    set.name().clone(),
                    set.ttl(),
                    RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
                );
                record.dns_class = DNSClass::IN;
                rrsigs.push(record);
            }
        }

        signed.extend(rrsigs);
        Ok(signed)
    }
}

impl Signers {
    /// The `NSEC3`s that deny `qname`, or `None` when the zone publishes no denials.
    ///
    /// `signed` is the zone as `sign` returned it, so the type bitmaps carry `RRSIG` - a bitmap that
    /// does not name a type the owner has is a denial a validator rejects.
    pub fn denial(
        &self,
        signed: &[Record],
        qname: &Name,
        qtype: RecordType,
    ) -> Option<Vec<Record>> {
        let params = self.nsec3.as_ref()?;
        let origin = self.origin.as_ref()?;
        // The chain that is already in the zone, not a copy rebuilt here: those are the records that
        // were signed, so the `RRSIG`s beside them belong to exactly these RRsets. Rebuilding the
        // chain produced records that differed from the signed ones in a way the signature noticed.
        let chain: Vec<Record> = signed
            .iter()
            .filter(|record| record.record_type() == RecordType::NSEC3)
            .cloned()
            .collect();
        let _ = origin;
        let proof = match crate::dns::nsec3::denial(origin, &chain, qname, qtype, params) {
            Ok(proof) => proof?,
            Err(err) => {
                tracing::error!(%err, "dns: a denial could not be built");
                return None;
            }
        };

        // Every `NSEC3` in the proof travels with its `RRSIG`: an unsigned denial is one a
        // validator rejects, and the signature is what makes the answer `NXDOMAIN validated`
        // rather than `SERVFAIL`. Matched by owner and by the type the signature covers.
        let mut with_signatures = Vec::with_capacity(proof.len() * 2);
        for record in proof {
            let owner = record.name.to_ascii();
            let signature = signed.iter().find(|candidate| {
                candidate.name.to_ascii() == owner
                    && matches!(
                        &candidate.data,
                        RData::DNSSEC(DNSSECRData::RRSIG(sig))
                            if sig.input().type_covered == RecordType::NSEC3
                    )
            });
            with_signatures.push(record);
            if let Some(signature) = signature {
                with_signatures.push(signature.clone());
            }
        }
        Some(with_signatures)
    }

    /// Whether this zone publishes `NSEC3` denials.
    pub fn has_denials(&self) -> bool {
        self.nsec3.is_some()
    }

    /// The salt the chain is hashed with, empty when there is none.
    pub fn nsec3_salt(&self) -> Vec<u8> {
        self.nsec3
            .as_ref()
            .map(|params| params.salt.clone())
            .unwrap_or_default()
    }

    /// How many extra iterations the chain uses.
    pub fn nsec3_iterations(&self) -> u16 {
        self.nsec3
            .as_ref()
            .map(|params| params.iterations)
            .unwrap_or(0)
    }
}

/// The zone as RRsets: one per (name, type), which is the unit a signature covers.
///
/// The TTL of the set is the **lowest** of its records. RFC 2181 §5.2 says the records of an RRset
/// must share one TTL and a reader must treat them as if they were the lowest; taking the lowest
/// here means the signature matches what a validator will reconstruct.
fn rrsets(records: &[Record]) -> Result<Vec<RecordSet>, String> {
    /// One group while the zone is being sorted: the owner, its type, the lowest TTL seen, and the
    /// records. A struct rather than a tuple because a tuple of four says nothing at the point of
    /// use, and `clippy` is right to refuse it.
    struct Group {
        name: Name,
        rtype: RecordType,
        ttl: u32,
        records: Vec<Record>,
    }

    let mut grouped: BTreeMap<(String, u16), Group> = BTreeMap::new();
    for record in records {
        // An `RRSIG` is never signed: it is the signature.
        if record.record_type() == RecordType::RRSIG {
            continue;
        }
        let key = (
            record.name.to_ascii().to_ascii_lowercase(),
            u16::from(record.record_type()),
        );
        let entry = grouped.entry(key).or_insert_with(|| Group {
            name: record.name.clone(),
            rtype: record.record_type(),
            ttl: record.ttl,
            records: Vec::new(),
        });
        entry.ttl = entry.ttl.min(record.ttl);
        entry.records.push(record.clone());
    }

    let mut sets = Vec::with_capacity(grouped.len());
    for (_, group) in grouped {
        let mut set = RecordSet::new(group.name, group.rtype, group.ttl);
        set.set_dns_class(DNSClass::IN);
        for record in group.records {
            set.insert(record, 0);
        }
        sets.push(set);
    }
    Ok(sets)
}

/// `ecdsa-p256-sha256`, `13`, `ed25519`.
fn algorithm_from(text: &str) -> Option<Algorithm> {
    match text.trim().to_ascii_lowercase().as_str() {
        "13" | "ecdsa-p256-sha256" | "ecdsap256sha256" => Some(Algorithm::ECDSAP256SHA256),
        "14" | "ecdsa-p384-sha384" | "ecdsap384sha384" => Some(Algorithm::ECDSAP384SHA384),
        "15" | "ed25519" => Some(Algorithm::ED25519),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signatures are made at read time, so there is nothing to re-sign and nothing to expire.
    ///
    /// This is the whole answer to "how is re-signing scheduled": it is not. A signature is made
    /// over the zone as it stands, at the moment it is answered, which means (a) an RFC 2136 update
    /// is covered by the next answer without a hook, and (b) a server that was down for a month has
    /// no stale signature to repair on the way up - the first answer after the start carries a fresh
    /// one. The test pins the property rather than the mechanism: two reads a second apart produce
    /// signatures that are valid now, and none that is already expired.
    #[test]
    fn signatures_are_made_at_read_time_so_none_can_be_stale() {
        let keys = crate::dns::dnssec::Signers::new(
            &DnssecConfig {
                keys: vec![KeyConfig {
                    algorithm: "ecdsa-p256-sha256".to_string(),
                    // A copy that only this process can read: the fixture in the repository is
                    // 644 after a checkout, and the loader refuses that on purpose.
                    file: private_copy("rrl-dnssec-test-p256.der"),
                }],
                signature_days: Some(7),
                nsec3: None,
            },
            "ad.example.com",
        )
        .expect("the test key loads");

        let origin = Name::from_ascii("ad.example.com.").expect("a name");
        let records = vec![Record::from_rdata(
            origin.clone(),
            600,
            RData::A(hickory_server::proto::rr::rdata::A::from(
                std::net::Ipv4Addr::new(10, 0, 2, 5),
            )),
        )];

        // A clock a month ahead: a server that was down that long answers with a signature made now,
        // not with one from before the outage.
        for at in [1_700_000_000u64, 1_700_000_000 + 30 * 24 * 3600] {
            let signed = keys.sign(&records, at).expect("the zone signs");
            let rrsig = signed
                .iter()
                .find_map(|record| match &record.data {
                    RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Some(sig.clone()),
                    _ => None,
                })
                .expect("a signature");
            assert!(
                rrsig.input().sig_inception.get() < at as u32,
                "the inception is before the answer"
            );
            assert!(
                rrsig.input().sig_expiration.get() > at as u32,
                "the expiration is after the answer, whatever the clock read at start"
            );
        }
    }

    /// A key anybody on the host can read is a key anybody can sign with, so the file is refused.
    ///
    /// The check is on the mode, not on the owner: this server may run as one user and be started by
    /// another, and what matters is that the octets are not readable by a third party.
    #[test]
    fn a_world_readable_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory =
            std::env::temp_dir().join(format!("rrl-dnssec-mode-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a temporary directory");
        let path = directory.join("key.der");
        // A copy of the real fixture, so the only thing wrong with it is the mode.
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/keys/rrl-dnssec-test-p256.der"),
        )
        .expect("the fixture");
        std::fs::write(&path, &bytes).expect("written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("mode");

        let config = KeyConfig {
            algorithm: "ecdsa-p256-sha256".to_string(),
            file: path.clone(),
        };
        let error = super::Key::load(&config, &Name::root(), std::time::Duration::from_secs(60))
            .expect_err("0644 is readable by others");
        let text = error.to_string();
        assert!(text.contains("readable by others"), "{text}");
        assert!(text.contains("0600"), "it says what to do: {text}");

        // And `0600` is accepted, so the check is about the mode and not about the path.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
        super::Key::load(&config, &Name::root(), std::time::Duration::from_secs(60))
            .expect("a 0600 key loads");

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// Both formats a tool writes: a DER document, and the same octets between PEM markers.
    ///
    /// `openssl genpkey` writes PEM unless told otherwise, and a secret store hands out DER - so a
    /// loader that took one and not the other is a loader half the tools cannot feed.
    #[test]
    fn a_key_is_read_from_pem_or_der() {
        let der = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/keys/rrl-dnssec-test-p256.der"),
        )
        .expect("the fixture");

        assert_eq!(
            decode_key_bytes(&der).expect("DER reads"),
            der,
            "a DER file is its own octets"
        );

        // Wrapped at 64 characters, which is what every PEM writer does and what base64 in one
        // line would not catch.
        let body = crate::model::encode_binary(&der);
        let wrapped: Vec<&str> = body
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).expect("base64 is text"))
            .collect();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            wrapped.join("\n")
        );
        assert_eq!(
            decode_key_bytes(pem.as_bytes()).expect("PEM reads"),
            der,
            "a PEM file is the same octets"
        );

        // And the refusals say which of the two the file was not.
        let error = decode_key_bytes(b"hello").expect_err("not a key");
        assert!(error.contains("neither PEM nor DER"), "{error}");
        let error = decode_key_bytes(b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n")
            .expect_err("empty block");
        assert!(error.contains("empty"), "{error}");
    }

    /// A copy of a fixture with `0600`, because a git checkout cannot carry a mode.
    fn private_copy(fixture: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = std::env::temp_dir().join(format!("rrl-keys-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a temporary directory");
        let target = directory.join(fixture);
        if !target.exists() {
            let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/keys")
                .join(fixture);
            std::fs::copy(&source, &target).expect("the fixture");
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
                .expect("the mode");
        }
        target
    }

    #[test]
    fn the_three_algorithms_this_build_signs_with_are_named_and_numbered() {
        assert_eq!(algorithm_from("13"), Some(Algorithm::ECDSAP256SHA256));
        assert_eq!(
            algorithm_from("ecdsa-p256-sha256"),
            Some(Algorithm::ECDSAP256SHA256)
        );
        assert_eq!(algorithm_from("14"), Some(Algorithm::ECDSAP384SHA384));
        assert_eq!(algorithm_from("ED25519"), Some(Algorithm::ED25519));

        // Refused, not guessed: RSA and SHA-1 are not offered, and neither is a typo.
        assert_eq!(algorithm_from("8"), None);
        assert_eq!(algorithm_from("rsasha256"), None);
        assert_eq!(algorithm_from("ecdsa-p256"), None);
    }
}
