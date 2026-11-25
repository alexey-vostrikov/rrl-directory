//! TSIG as this server checks it: RFC 8945, keys from the configuration.
//!
//! # What is here and what is not
//!
//! The MAC is not computed here. `hickory-proto` implements RFC 8945 including the exact buffer a
//! signature covers - the message with the TSIG record replaced by a stub, `arcount` decremented, and
//! for a response the request's MAC prepended - and a second implementation of that layout would be a
//! second opinion about which octets were signed. So this module owns the **policy**: which keys
//! exist, what an unknown key answers, what a wrong MAC answers, and what window of clock skew is
//! tolerated.
//!
//! # Answers, and why they differ
//!
//! RFC 8945 §5.2 draws the line that matters: `BADKEY` and `BADSIG` are answered with a TSIG record
//! that carries the error and **no** MAC (nothing can be signed with a key we do not have, and
//! nothing should be signed with a key that just failed to prove itself), while `BADTIME` is answered
//! **signed** by the same key, because the client needs to trust the server's clock reading to fix
//! its own. `hickory`'s `TSigResponseContext` encodes exactly these three cases, and choosing the
//! right constructor is the whole of this module's job.
//!
//! A request with no TSIG at all is not an error here: queries are answered without a signature for
//! clients that never asked for one, which is every ordinary resolver. Whether an unsigned *update*
//! is acceptable is a policy of the update path (RRL-2.25.8), not of this module.

use std::time::{SystemTime, UNIX_EPOCH};

use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::rdata::tsig::TsigError;
use hickory_server::proto::rr::{TSigResponseContext, TSigner};
use hickory_server::server::Request;

use crate::dns::config::TsigKey;

/// The keys this server accepts, ready to verify and to sign with.
///
/// Wrapped in an `Arc` by its owner: a request handler is shared by every connection, and building a
/// signer per request would copy key material on the hot path for no reason.
#[derive(Default)]
pub struct Keys {
    signers: Vec<TSigner>,
}

/// By name, never by contents.
///
/// `TSigner` holds the key itself and has no `Debug` of its own, which is the right default: a struct
/// that printed it is one whose key reaches a log line the day somebody adds `?keys` to a `tracing`
/// call. This implementation keeps `Keys` usable inside types that derive `Debug` - and says only
/// what may be said.
impl std::fmt::Debug for Keys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Keys")
            .field("names", &self.names())
            .finish()
    }
}

impl Keys {
    /// No keys: unsigned requests are answered unsigned, signed ones are refused as `BADKEY`.
    pub fn none() -> Self {
        Self::default()
    }

    /// The signers for the configured keys, or the reason one of them cannot be used.
    ///
    /// Refused at start rather than at the first update, for the reason every other setting in this
    /// section is: a key that does not load is a client that will be told `BADKEY` hours later, and
    /// the operator who wrote the file is the one who can fix it.
    pub fn new(keys: &[TsigKey]) -> Result<Self, String> {
        let mut signers = Vec::with_capacity(keys.len());
        for key in keys {
            let signer = TSigner::new(
                key.secret.clone(),
                key.algorithm.clone(),
                key.name.clone(),
                key.fudge,
            )
            .map_err(|err| format!("dns.keys '{}': {err}", key.name))?;
            signers.push(signer);
        }
        Ok(Self { signers })
    }

    /// Whether any key is configured at all.
    pub fn is_empty(&self) -> bool {
        self.signers.is_empty()
    }

    /// The keys by name, for a report an operator reads at start.
    pub fn names(&self) -> Vec<String> {
        self.signers
            .iter()
            .map(|signer| signer.signer_name().to_ascii())
            .collect()
    }

    /// `(verdict, context)`: what the request has earned, and how to sign the answer to it.
    ///
    /// The context is what makes the answer signed; `None` means the answer goes out unsigned, which
    /// is right only for a request that carried no signature.
    pub fn authorize(
        &self,
        request: &Request,
        now: u64,
    ) -> (Result<(), ResponseCode>, Option<TSigResponseContext>) {
        let (verdict, context) = self.verified(request, now);
        (verdict.map(|_| ()), context)
    }

    /// The same check, saying **which** key it was.
    ///
    /// `Ok(None)` is a request that carried no signature and did not need one; `Ok(Some(name))` is a
    /// signature that verified under a key this server holds. A policy that distinguishes clients by
    /// key - a zone transfer, first of them - cannot be written against `authorize`, because "did not
    /// sign" and "signed correctly" both come back as `Ok(())` there.
    pub fn verified(
        &self,
        request: &Request,
        now: u64,
    ) -> (
        Result<Option<&hickory_server::proto::rr::Name>, ResponseCode>,
        Option<TSigResponseContext>,
    ) {
        let Some(signature) = request.signature.as_deref() else {
            return (Ok(None), None);
        };
        let id = request.metadata.id;

        // RFC 8945 §5.5: one algorithm per key name, so the name is what a key is looked up by. A
        // second algorithm under one name would make the same key two keys, and which one verified
        // would depend on the request.
        let Some(signer) = self
            .signers
            .iter()
            .find(|signer| signer.signer_name() == &signature.name)
        else {
            tracing::warn!(key = %signature.name, id, "dns: a signature named a key this server does not have");
            return (
                Err(ResponseCode::NotAuth),
                Some(TSigResponseContext::unknown_key(
                    id,
                    now,
                    signature.name.clone(),
                )),
            );
        };

        let Ok((_, _, window)) = signer.verify_message_byte(request.as_slice(), None, true) else {
            tracing::warn!(key = %signature.name, id, "dns: a signature did not verify");
            return (
                Err(ResponseCode::NotAuth),
                Some(TSigResponseContext::bad_signature(id, now, signer.clone())),
            );
        };

        if !window.contains(&now) {
            // Signed, not bare: the client has to be able to trust the time in this answer before it
            // can decide its own clock is wrong.
            tracing::warn!(
                key = %signature.name,
                id,
                skew = ?window,
                now,
                "dns: a signature is outside its time window"
            );
            return (
                Err(ResponseCode::NotAuth),
                Some(TSigResponseContext::new(
                    id,
                    now,
                    signer.clone(),
                    signature.data.mac.clone(),
                    Some(TsigError::BadTime),
                )),
            );
        }

        (
            Ok(Some(signer.signer_name())),
            Some(TSigResponseContext::new(
                id,
                now,
                signer.clone(),
                signature.data.mac.clone(),
                None,
            )),
        )
    }
}

/// Seconds since the epoch, which is what a TSIG signature travels in.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
