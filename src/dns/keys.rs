//! The keys that may change a zone, as entries the directory itself holds.
//!
//! # Why an entry and not a line in the configuration
//!
//! A key in `dns.keys` is invisible to every LDAP client, is not replicated with anything, and
//! cannot be issued without editing a file and restarting the server. An entry is none of those: it
//! is read by the same code that answers a search, it travels wherever the directory travels, and
//! it can be created or deleted at runtime. The REST surface of RRL-13.3 issues exactly this entry.
//!
//! # Why the secret is stored reversibly
//!
//! A password is hashed so that reading the file does not help an attacker sign in. A TSIG key
//! cannot be: the MAC is computed over the message with the key itself, so verification needs the
//! octets back. That is a fact about the protocol, not a choice - and it is why this attribute joins
//! `userPassword` in the ACL rule that keeps it out of a search, rather than being protected by a
//! hash that would silently disable it.
//!
//! # What is deliberately not here
//!
//! Grants. `rrlDnsGrant` is *declared* here because the class cannot be written without it, and
//! interpreted in RRL-13.2 - the module that decides whether an update is allowed. A key whose
//! grants this module parsed would be a second opinion about what the strings mean.

use std::time::SystemTime;

use hickory_server::proto::rr::Name;
use hickory_server::proto::rr::rdata::tsig::TsigAlgorithm;

use crate::dns::config::TsigKey;
use crate::model::Entry;
use crate::schema::Schema;

/// The vocabulary a key is written in, in RFC 4512 form.
///
/// OIDs are under `1.3.6.1.4.1.59999` - a private arc this project uses for everything it defines
/// itself, so no name here can collide with AD's vocabulary or with a published one.
pub const KEYS_EXTENSION: &str = r#"
# --- attributes ----------------------------------------------------------------------------
#
# The algorithm is part of the key's identity in RFC 8945 §5.5: one name, one algorithm. It is a
# string and not an OID so that an operator reading an entry sees `hmac-sha256`, and what it may say
# is decided where the key is resolved rather than by the schema.
attributetype ( 1.3.6.1.4.1.59999.8.1.1 NAME 'rrlDnsKeyAlgorithm'
    EQUALITY caseIgnoreIA5Match
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )

# The shared secret. Octets, not text: the value is a key, and a syntax that said `Directory String`
# would invite an implementation to fold its case.
attributetype ( 1.3.6.1.4.1.59999.8.1.2 NAME 'rrlDnsKeySecret'
    EQUALITY octetStringMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )

# Absent means the key does not expire. A present value in the past is a key that no longer
# verifies - which is what rotation looks like from the client's side.
attributetype ( 1.3.6.1.4.1.59999.8.1.3 NAME 'rrlDnsKeyExpires'
    EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )

# What the key may change. One string per rule, interpreted by RRL-13.2.
attributetype ( 1.3.6.1.4.1.59999.8.1.4 NAME 'rrlDnsGrant'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )

# --- classes -------------------------------------------------------------------------------
#
# Structural: a key is an object in its own right, not an attribute of something else. `cn` is the
# key's name, which is also the name a client writes in `nsupdate -y hmac-sha256:<name>:<secret>`,
# and `description` is inherited from the core schema for the note an operator leaves behind.
objectclass ( 1.3.6.1.4.1.59999.8.2.1 NAME 'rrlDnsKey'
    SUP top STRUCTURAL
    MUST ( cn $ rrlDnsKeyAlgorithm $ rrlDnsKeySecret )
    MAY  ( rrlDnsKeyExpires $ rrlDnsGrant $ description ) )
"#;

/// Publishes the key vocabulary.
///
/// `extend_missing` rather than `extend`: AD's vocabulary is loaded beside this one for a domain
/// controller, and a name defined in both would be a start-up failure over a duplicate that says
/// nothing about the data.
pub fn extend(schema: &mut Schema) -> Result<(), String> {
    schema
        .extend_missing(KEYS_EXTENSION)
        .map_err(|err| err.to_string())
}

/// Where keys live: `cn=keys,<base_dn>`.
///
/// Not under `cn=Configuration` and not in the DNS partition: a key is this server's own credential,
/// and the zones it may change are named in its grants. Putting it beside the configuration would
/// make it follow the configuration's replication instead of the domain's.
pub fn keys_dn(base_dn: &str) -> String {
    format!("cn=keys,{base_dn}")
}

/// Why an entry is not a key this server can use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The entry has no `cn`, so it names nothing a client could sign with.
    NoName { dn: String },
    /// No `rrlDnsKeyAlgorithm`: a key without one cannot be matched against a signature.
    NoAlgorithm { name: String },
    /// The algorithm is not one this build verifies. Named, and with the ones it does.
    Algorithm { name: String, algorithm: String },
    /// The secret is missing or is not base64.
    Secret { name: String, detail: String },
    /// `rrlDnsKeyExpires` is not a time this server can read.
    Expiry { name: String, value: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoName { dn } => write!(
                formatter,
                "{dn} carries no 'cn', so the key it describes has no name to sign with"
            ),
            Self::NoAlgorithm { name } => write!(
                formatter,
                "the key '{name}' carries no 'rrlDnsKeyAlgorithm': a key whose algorithm is \
                 unknown cannot verify anything"
            ),
            Self::Algorithm { name, algorithm } => write!(
                formatter,
                "the key '{name}' names algorithm '{algorithm}', which this server cannot verify: \
                 use hmac-sha256, hmac-sha384 or hmac-sha512"
            ),
            Self::Secret { name, detail } => {
                write!(formatter, "the key '{name}' has no usable secret: {detail}")
            }
            Self::Expiry { name, value } => write!(
                formatter,
                "the key '{name}' has rrlDnsKeyExpires '{value}', which is not a generalised time"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// A key read out of an entry: what a signature is checked against, and when it stops being one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    /// The key itself, in the shape `dns.keys` resolves to - the two paths agree by construction.
    pub key: TsigKey,
    /// Absent means no expiry.
    pub expires: Option<SystemTime>,
}

impl Key {
    /// Whether the key may verify a signature at `now`.
    pub fn live_at(&self, now: SystemTime) -> bool {
        self.expires.is_none_or(|expires| now < expires)
    }

    /// Reads a key out of an entry, or says what is wrong with it.
    ///
    /// Every failure is named rather than skipped: a key that silently does not load is a client
    /// told `BADKEY` with nothing in the log that connects it to the entry an operator wrote.
    pub fn read(entry: &Entry) -> Result<Self, Error> {
        let attributes = entry.attributes();
        let name = attributes
            .get("cn")
            .and_then(|attribute| attribute.values.first())
            .map(|value| value.trim().to_string())
            .ok_or_else(|| Error::NoName {
                dn: entry.dn().to_string(),
            })?;

        let algorithm_text = attributes
            .get("rrlDnsKeyAlgorithm")
            .and_then(|attribute| attribute.values.first())
            .map(|value| value.trim().to_ascii_lowercase())
            .ok_or_else(|| Error::NoAlgorithm { name: name.clone() })?;
        let algorithm = match algorithm_text.as_str() {
            "hmac-sha256" => TsigAlgorithm::HmacSha256,
            "hmac-sha384" => TsigAlgorithm::HmacSha384,
            "hmac-sha512" => TsigAlgorithm::HmacSha512,
            other => {
                return Err(Error::Algorithm {
                    name,
                    algorithm: other.to_string(),
                });
            }
        };

        let secret_text = attributes
            .get("rrlDnsKeySecret")
            .and_then(|attribute| attribute.values.first())
            .ok_or_else(|| Error::Secret {
                name: name.clone(),
                detail: "rrlDnsKeySecret is absent".to_string(),
            })?;
        let secret = crate::model::decode_binary(secret_text).ok_or_else(|| Error::Secret {
            name: name.clone(),
            detail: format!("'{secret_text}' is not base64"),
        })?;
        if secret.is_empty() {
            return Err(Error::Secret {
                name: name.clone(),
                detail: "the secret decodes to nothing".to_string(),
            });
        }

        let expires = match attributes
            .get("rrlDnsKeyExpires")
            .and_then(|attribute| attribute.values.first())
        {
            None => None,
            Some(value) => Some(
                crate::operational::parse_generalized_time(value.trim()).ok_or_else(|| {
                    Error::Expiry {
                        name: name.clone(),
                        value: value.clone(),
                    }
                })?,
            ),
        };

        // The name a client signs with is the `cn` as a DNS name, because that is where TSIG carries
        // it: `nsupdate -y hmac-sha256:app-acme:...` sends `app-acme.` and the server compares it
        // against the key's name label by label, not as text.
        let signer = Name::from_ascii(&name)
            .map(|mut name| {
                name.set_fqdn(true);
                name
            })
            .map_err(|err| Error::Secret {
                name: name.clone(),
                detail: format!("the name is not a DNS name TSIG can carry: {err}"),
            })?;

        Ok(Self {
            key: TsigKey {
                name: signer,
                secret,
                algorithm,
                // RFC 8945 §10: 300 unless the entry says otherwise. A key entry has no field for
                // this yet, and inventing a per-key fudge before anything asks for one would be a
                // setting nobody can test.
                fudge: 300,
            },
            expires,
        })
    }
}

/// The keys the directory holds under [`keys_dn`], and what is wrong with the ones it cannot use.
///
/// Called by [`crate::dns::serve::InDirectory::keys`] on **every** signature check, not once at
/// start: a key issued through the REST surface of RRL-13.3 has to work without a restart, and a key
/// deleted there has to stop working without one. A domain has a handful of keys and the read is one
/// subtree over them, which is the same trade the zone itself makes on every query.
///
/// An entry that does not describe a usable key is **reported and skipped**, not fatal: refusing to
/// serve a whole zone because somebody wrote a broken key entry would turn an operator's typo into
/// an outage. The name it reports is the DN, which is what the operator can act on.
pub fn load(directory: &crate::directory::Directory, base_dn: &str) -> (Vec<TsigKey>, Vec<String>) {
    let mut keys = Vec::new();
    let mut broken = Vec::new();
    let now = SystemTime::now();

    for (_, entry) in
        directory.records_in_scope(&keys_dn(base_dn), crate::directory::Scope::OneLevel)
    {
        // A container has no `rrlDnsKey`, and it is not a broken key - it is not a key at all.
        let is_key = entry
            .attributes()
            .get(crate::model::ATTR_OBJECT_CLASS)
            .is_some_and(|classes| {
                classes
                    .values
                    .iter()
                    .any(|class| class.eq_ignore_ascii_case("rrlDnsKey"))
            });
        if !is_key {
            continue;
        }

        match Key::read(entry.as_ref()) {
            Ok(key) if key.live_at(now) => keys.push(key.key),
            Ok(key) => broken.push(format!(
                "{} is expired and is not accepted",
                key.key.name.to_ascii()
            )),
            Err(err) => broken.push(format!("{}: {err}", entry.dn())),
        }
    }

    (keys, broken)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, Attributes};

    const BASE: &str = "dc=ad,dc=example,dc=com";

    fn with_keys() -> Schema {
        let mut schema = Schema::core();
        extend(&mut schema).expect("the key vocabulary parses");
        schema
    }

    fn entry(name: &str, extra: Vec<(&str, Vec<&str>)>) -> Entry {
        let mut attributes = Attributes::new().push(Attribute::new(
            crate::model::ATTR_OBJECT_CLASS,
            vec!["top".to_string(), "rrlDnsKey".to_string()],
        ));
        attributes = attributes.push(Attribute::single("cn", name));
        for (attribute, values) in extra {
            attributes = attributes.push(Attribute::new(
                attribute,
                values.into_iter().map(str::to_string).collect(),
            ));
        }
        Entry::new(format!("cn={name},{}", keys_dn(BASE)), attributes)
    }

    fn complete(name: &str) -> Entry {
        entry(
            name,
            vec![
                ("rrlDnsKeyAlgorithm", vec!["hmac-sha256"]),
                ("rrlDnsKeySecret", vec!["c2VjcmV0MTIzNDU2Nzg5MA=="]),
                (
                    "rrlDnsGrant",
                    vec!["zone=ad.example.com;name=_acme-challenge;types=TXT;ops=add,delete"],
                ),
                ("description", vec!["the acme client on the edge host"]),
            ],
        )
    }

    /// The entry this module describes has to pass the schema this server enforces - the same
    /// mistake a zone made, where the class it was written in was not in the loaded vocabulary.
    #[test]
    fn a_key_entry_validates_and_reads_back() {
        let entry = complete("app-acme");
        if let Err(violations) = with_keys().check(&entry) {
            panic!("a key entry must validate: {violations:?}");
        }

        let key = Key::read(&entry).expect("a complete entry is a key");
        assert_eq!(key.key.name.to_ascii(), "app-acme.");
        assert_eq!(key.key.secret, b"secret1234567890");
        assert_eq!(key.key.algorithm, TsigAlgorithm::HmacSha256);
        assert!(key.expires.is_none(), "no expiry is an eternal key");
    }

    /// A key with no algorithm cannot be matched against a signature, and the complaint names it.
    #[test]
    fn an_entry_without_an_algorithm_names_the_key() {
        let entry = entry(
            "nameless",
            vec![("rrlDnsKeySecret", vec!["c2VjcmV0MTIzNDU2Nzg5MA=="])],
        );
        // The schema refuses it first, which is the point of `MUST`: a key written by a client
        // without an algorithm never reaches the store. The reader still has to answer for a store
        // written before the class existed.
        assert!(with_keys().check(&entry).is_err());
        let error = Key::read(&entry).expect_err("no algorithm, no key");
        assert!(error.to_string().contains("rrlDnsKeyAlgorithm"), "{error}");
        assert!(error.to_string().contains("nameless"), "{error}");
    }

    #[test]
    fn an_algorithm_this_build_cannot_verify_is_named_with_the_ones_it_can() {
        let entry = entry(
            "old",
            vec![
                ("rrlDnsKeyAlgorithm", vec!["hmac-md5"]),
                ("rrlDnsKeySecret", vec!["c2VjcmV0MTIzNDU2Nzg5MA=="]),
            ],
        );
        let error = Key::read(&entry).expect_err("hmac-md5 is not verifiable");
        let text = error.to_string();
        assert!(text.contains("hmac-md5"), "{text}");
        assert!(
            text.contains("hmac-sha256"),
            "it says what to use instead: {text}"
        );
    }

    #[test]
    fn a_secret_that_is_not_base64_is_refused_rather_than_guessed() {
        let entry = entry(
            "broken",
            vec![
                ("rrlDnsKeyAlgorithm", vec!["hmac-sha256"]),
                ("rrlDnsKeySecret", vec!["not base64 at all!"]),
            ],
        );
        let error = Key::read(&entry).expect_err("a key is octets");
        assert!(error.to_string().contains("base64"), "{error}");
    }

    /// Expiry is a fact about the key, and the check is a comparison rather than a scheduler: a key
    /// that expired while the server was running must stop verifying on the next request.
    #[test]
    fn an_expired_key_is_no_longer_live() {
        let entry = entry(
            "rotated",
            vec![
                ("rrlDnsKeyAlgorithm", vec!["hmac-sha256"]),
                ("rrlDnsKeySecret", vec!["c2VjcmV0MTIzNDU2Nzg5MA=="]),
                ("rrlDnsKeyExpires", vec!["20260101000000Z"]),
            ],
        );
        let key = Key::read(&entry).expect("a dated key reads");
        let expires = key.expires.expect("it has a date");
        assert!(!key.live_at(expires), "at the instant of expiry it is done");
        assert!(key.live_at(expires - std::time::Duration::from_secs(1)));
    }

    #[test]
    fn a_date_that_is_not_a_time_is_refused_with_its_value() {
        let entry = entry(
            "vague",
            vec![
                ("rrlDnsKeyAlgorithm", vec!["hmac-sha256"]),
                ("rrlDnsKeySecret", vec!["c2VjcmV0MTIzNDU2Nzg5MA=="]),
                ("rrlDnsKeyExpires", vec!["next tuesday"]),
            ],
        );
        let error = Key::read(&entry).expect_err("next tuesday is not a time");
        assert!(error.to_string().contains("next tuesday"), "{error}");
    }

    /// Keys live where a client can list them: one container, named once.
    #[test]
    fn keys_live_under_one_container() {
        assert_eq!(keys_dn(BASE), "cn=keys,dc=ad,dc=example,dc=com");
    }

    /// A directory holding one good key, one broken one and one that expired yesterday: the good one
    /// is served, the other two are reported by the DN an operator can go and fix.
    ///
    /// This is the read a signature is checked against, so it is also where "a key issued five
    /// minutes ago works" and "a rotated-out key stops working" are decided - neither needs a
    /// restart, which is the whole reason keys are entries.
    #[test]
    fn the_directory_s_own_keys_are_read_and_the_broken_ones_reported() {
        let container = Entry::new(
            keys_dn(BASE),
            Attributes::new()
                .push(Attribute::new(
                    crate::model::ATTR_OBJECT_CLASS,
                    vec!["top".to_string(), "container".to_string()],
                ))
                .push(Attribute::single("cn", "keys")),
        );
        let good = {
            let mut entry = complete("app-acme");
            // Refresh the DN so it hangs under the container this test built.
            entry = Entry::new(
                format!("cn=app-acme,{}", keys_dn(BASE)),
                entry.attributes().clone(),
            );
            entry
        };
        let broken = Entry::new(
            format!("cn=no-algorithm,{}", keys_dn(BASE)),
            Attributes::new()
                .push(Attribute::new(
                    crate::model::ATTR_OBJECT_CLASS,
                    vec!["top".to_string(), "rrlDnsKey".to_string()],
                ))
                .push(Attribute::single("cn", "no-algorithm"))
                .push(Attribute::single(
                    "rrlDnsKeySecret",
                    "c2VjcmV0MTIzNDU2Nzg5MA==",
                )),
        );
        let expired = {
            let entry = entry(
                "rotated",
                vec![
                    ("rrlDnsKeyAlgorithm", vec!["hmac-sha256"]),
                    ("rrlDnsKeySecret", vec!["c2VjcmV0MTIzNDU2Nzg5MA=="]),
                    ("rrlDnsKeyExpires", vec!["20200101000000Z"]),
                ],
            );
            Entry::new(
                format!("cn=rotated,{}", keys_dn(BASE)),
                entry.attributes().clone(),
            )
        };

        let directory = crate::directory::Directory::from_entries(
            BASE,
            "users",
            "groups",
            vec![container, good, broken, expired],
        );

        let (keys, broken) = load(&directory, BASE);
        assert_eq!(keys.len(), 1, "only the usable key is served: {broken:?}");
        assert_eq!(keys[0].name.to_ascii(), "app-acme.");
        assert_eq!(broken.len(), 2, "the other two are reported: {broken:?}");
        assert!(
            broken.iter().any(|reason| reason.contains("no-algorithm")),
            "the broken entry is named by its DN: {broken:?}"
        );
        assert!(
            broken
                .iter()
                .any(|reason| reason.contains("expired") && reason.contains("rotated")),
            "the expired key is named as expired: {broken:?}"
        );
    }
}
