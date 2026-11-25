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

        let der = std::fs::read(&config.file).map_err(|err| {
            format!(
                "dns.dnssec.keys: {} could not be read: {err}",
                config.file.display()
            )
        })?;
        if der.is_empty() {
            return Err(format!(
                "dns.dnssec.keys: {} is empty",
                config.file.display()
            ));
        }
        let pkcs8 = PrivatePkcs8KeyDer::from(der);

        // One arm per algorithm, because a P-256 key and an Ed25519 key are different types in
        // `ring` and the only thing they share is the trait this box erases.
        let boxed: Box<dyn hickory_server::proto::dnssec::SigningKey> = match algorithm {
            Algorithm::ED25519 => Box::new(
                Ed25519SigningKey::from_pkcs8(&pkcs8)
                    .map_err(|err| format!("{}: {err}", config.file.display()))?,
            ),
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
