//! Schema that makes this directory answer to clients expecting an Active Directory.
//!
//! Kerberos is not only a bind mechanism. A client that authenticates by ticket is usually a
//! client from an AD world - `sssd`, a Windows host, a Samba tool - and such a client does not ask
//! "who is uid=alice". It asks for `userPrincipalName`, `sAMAccountName`, `userAccountControl`,
//! `objectGUID`, `servicePrincipalName`. Against a schema that has never heard of them, every one
//! of those questions fails with `undefinedAttributeType`, and the answer looks like a broken
//! directory rather than a missing definition.
//!
//! So the extension is tied to Kerberos mode: a server that accepts tickets is a server claiming
//! to stand in for a domain controller, and it should publish the vocabulary of one. A server
//! without a keytab stays exactly as it was - it is somebody's LDAP directory, not an impostor
//! domain controller, and adding `userAccountControl` to it would invite clients to rely on
//! something nothing maintains.
//!
//! # Where the definitions come from
//!
//! Not from here. [`crate::ad_vocabulary`] derives AD's attribute and class definitions from the
//! files Microsoft publishes (`schema/ad/attributes.ldf`, `schema/ad/classes.ldf`), so the OIDs,
//! syntaxes and allowed attributes are AD's own and cannot drift from the source. This module used
//! to carry a hand-written transcription of them, and checking it against those files found eight
//! attribute OIDs that disagreed with AD's - `objectGUID` and `objectSid` holding each other's
//! number among them - with no test able to see it, because the tests were written against the
//! transcription.
//!
//! What is left here is what AD does **not** have: Samba's `sambaNTPassword`, the attribute the
//! realm keeps an account's NT hash in, and the additions this server makes to AD's classes so that
//! the KDC can read the keys it derives from an ordinary entry.
//!
//! What this is **not**: an implementation of AD semantics. There is no USN tracking and no
//! `msDS-*` replication metadata. The definitions exist so that questions can be asked and answered;
//! the answers come from ordinary LDAP entries, and where a value has to be synthesised this crate
//! says where - [`crate::ad_derived`] for the three AD writes into every object it creates.
use crate::schema::Schema;

/// The one attribute AD does not have and this server does.
///
/// `sambaNTPassword` is Samba's spelling of an account's NT hash, and `rrl-kdc` writes it on the
/// entry a principal lives in. Everything else this server publishes is AD's own, and AD's
/// vocabulary is no longer written here: [`crate::ad_vocabulary`] derives it from the files
/// Microsoft publishes, so there is nothing to drift from the source.
pub const OUR_EXTENSION: &str = r#"
attributetype ( 1.3.6.1.4.1.7165.2.1.25 NAME 'sambaNTPassword'
    DESC 'MD4 hash of the unicode password'
    EQUALITY caseIgnoreIA5Match
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{32} SINGLE-VALUE )
"#;

/// The bits of `userAccountControl` this server acts on.
///
/// Not the whole flag word: AD defines a couple of dozen bits and most of them describe password
/// policy, which a directory that never sees a password has no business deciding. These three are
/// the ones that answer "may this account authenticate at all", and that question is ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserAccountControl(u32);

impl UserAccountControl {
    /// The account is disabled.
    pub const ACCOUNTDISABLE: u32 = 0x0002;
    /// The account is locked out by policy.
    pub const LOCKOUT: u32 = 0x0010;
    /// The account is a machine account created with a broken password and never used.
    pub const PASSWD_NOTREQD: u32 = 0x0020;

    /// Reads the attribute's value.
    ///
    /// `None` for anything that is not a number, and the caller must decide: a flag word this
    /// server cannot read is not permission to authenticate, nor is it proof of a problem.
    pub fn parse(text: &str) -> Option<Self> {
        text.trim().parse::<u32>().ok().map(Self)
    }

    pub fn bits(self) -> u32 {
        self.0
    }

    pub fn is_disabled(self) -> bool {
        self.0 & Self::ACCOUNTDISABLE != 0
    }

    pub fn is_locked_out(self) -> bool {
        self.0 & Self::LOCKOUT != 0
    }

    /// Whether this account may complete a bind.
    ///
    /// Deliberately not "everything except disabled": a flag word with only the bits this server
    /// does not understand set is an ordinary enabled account, and refusing it would break exactly
    /// the accounts the extension exists to serve.
    pub fn may_authenticate(self) -> bool {
        !self.is_disabled() && !self.is_locked_out()
    }

    /// The reason a bind was refused, in words an operator can act on.
    pub fn refusal(self) -> Option<&'static str> {
        if self.is_disabled() {
            return Some(
                "the account is disabled (userAccountControl ACCOUNTDISABLE): a ticket proves who \
                 the client is, but a disabled account may not use one",
            );
        }
        if self.is_locked_out() {
            return Some(
                "the account is locked out (userAccountControl LOCKOUT): unlock it before it may \
                 authenticate again",
            );
        }
        None
    }
}

/// What this server adds to AD's account classes, and why each one is there.
///
/// AD keeps a password's NT hash and its Kerberos keys in `unicodePwd` and
/// `supplementalCredentials`; `sambaNTPassword` is Samba's spelling of the hash and `krb5Key` is
/// Heimdal's, and `rrl-kdc` writes both. `userPassword` is what a simple bind is checked against.
///
/// `augment` adds them to AD's own `user` and `computer` without restating AD's `MAY` list.
const ADDITIONS: [&str; 8] = [
    "userPassword",
    "sambaNTPassword",
    "supplementalCredentials",
    "msDS-KeyVersionNumber",
    "krb5Key",
    "krb5KeyVersionNumber",
    "krb5PrincipalName",
    "krb5PrincipalRealm",
];

/// The schema with the AD definitions added.
///
/// Returns the schema unchanged when it cannot parse the extension, and says so: a directory that
/// silently runs without half its published vocabulary is worse than one that starts with none,
/// and the definitions above are constants that a test parses on every run.
pub fn extend(schema: &mut Schema) -> Result<(), String> {
    // AD's own definitions, `replace`d so that AD's reading of a name wins over the core one: a
    // domain controller's `info` is AD's `info`, not this server's.
    schema
        .replace(&crate::ad_vocabulary::vocabulary())
        .map_err(|err| err.to_string())?;
    schema
        .extend(OUR_EXTENSION)
        .map_err(|err| err.to_string())?;

    // The keys this server derives live on the account, and AD's `user` does not permit two of
    // them. `augment` says that without restating AD's own `MAY` list - which is the transcription
    // this module just stopped carrying. `userPassword` is the password a simple bind is checked
    // against; `sambaNTPassword` is the NT hash a Netlogon channel and an NTLM logon are proved
    // with.
    for class in ["user", "computer"] {
        schema
            .augment(class, &[], &ADDITIONS)
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entry as the write path stores it, AD's synthesised attributes included.
    ///
    /// Every entry AD creates carries `objectCategory`, `instanceType` and `nTSecurityDescriptor`
    /// because its `top` class requires them, and this server now writes them at the same moment.
    /// A test that built a bare entry would be testing a shape that never reaches the store.
    fn entry(dn: &str, attributes: crate::model::Attributes) -> crate::model::Entry {
        const BASE: &str = "dc=ad,dc=example,dc=com";
        crate::model::Entry::new(
            dn.to_string(),
            crate::ad_derived::synthesised(dn, &attributes, BASE),
        )
    }

    fn with_ad() -> Schema {
        let mut schema = Schema::core();
        extend(&mut schema).expect("the AD extension parses");
        schema
    }

    #[test]
    fn the_extension_parses_and_publishes_the_attributes_ad_clients_ask_for() {
        // The whole point: a client asking for these must not get `undefinedAttributeType`.
        let schema = with_ad();

        for name in [
            "userprincipalname",
            "samaccountname",
            "useraccountcontrol",
            "objectguid",
            "objectsid",
            "serviceprincipalname",
            "primarygroupid",
            "grouptype",
            "accountexpires",
            "pwdlastset",
            "dnshostname",
            "msds-supportedencryptiontypes",
            "unicodepwd",
            "sambantpassword",
        ] {
            assert!(
                schema.attribute(name).is_some(),
                "{name} must be defined, or a client asking for it gets a refusal"
            );
        }
    }

    #[test]
    fn the_extension_publishes_the_ad_object_classes() {
        let schema = with_ad();

        for name in ["user", "group", "computer"] {
            assert!(schema.class(name).is_some(), "{name} must be defined");
        }
    }

    #[test]
    fn an_entry_shaped_like_an_ad_user_validates() {
        // A dump from a real directory is the test that matters: if `user` here refused what `user`
        // means there, the extension would be a vocabulary nobody can speak.
        let schema = with_ad();
        let entry = entry(
            "cn=Alice,ou=users,dc=example,dc=com",
            crate::model::Attributes::new()
                .push(crate::model::Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "person".to_string(), "user".to_string()],
                ))
                .push(crate::model::Attribute::single("cn", "Alice"))
                .push(crate::model::Attribute::single("sn", "Kerberos"))
                .push(crate::model::Attribute::single(
                    "userPrincipalName",
                    "alice@EXAMPLE.COM",
                ))
                .push(crate::model::Attribute::single("sAMAccountName", "alice"))
                // AD's `securityPrincipal` class makes a SID mandatory on every account, and the
                // write path allocates one for an entry that arrives without it.
                .push(crate::model::Attribute::single("objectSid", "AQUAAAAAAAUVAAAA").binary())
                .push(crate::model::Attribute::single("userAccountControl", "512")),
        );

        if let Err(violations) = schema.check(&entry) {
            panic!("an AD-shaped user must validate: {violations:?}");
        }
    }

    /// The entry a realm bootstrap writes: Heimdal's principal classes, the Samba attribute the
    /// NT hash goes into, and no `user` class at all.
    ///
    /// This is the shape that made seven `kdc_daemon` tests fail at once when `rrl-kdc` started
    /// writing `sambaNTPassword`: the attribute was defined by neither vocabulary, and the
    /// violation named the attribute rather than the class that should have permitted it. The
    /// bootstrap's entry is a principal, so it is `krb5Principal`'s `MAY` list that has to carry
    /// the name - not `user`'s, which nothing in that path adds.
    /// The zone this server writes itself has to pass its own schema check: a directory in `strict`
    /// mode that refused its own provisioning would be a server that cannot start with `dns:`
    /// enabled, and the complaint would name `dnsNode` as an unknown class.
    #[test]
    fn an_entry_shaped_like_a_dns_zone_and_its_nodes_validates() {
        let schema = with_ad();
        let zone = entry(
            "dc=ad.example.com,cn=RRLDNS,dc=DomainDnsZones,dc=ad,dc=example,dc=com",
            crate::model::Attributes::new()
                .push(crate::model::Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "dnsZone".to_string()],
                ))
                .push(crate::model::Attribute::single("dc", "ad.example.com"))
                .push(
                    crate::model::Attribute::new("dNSProperty", vec!["AAECAw==".to_string()])
                        .binary(),
                ),
        );
        if let Err(violations) = schema.check(&zone) {
            panic!("a zone object must validate: {violations:?}");
        }

        let node = entry(
            "dc=_ldap._tcp,dc=ad.example.com,cn=RRLDNS,dc=DomainDnsZones,dc=ad,dc=example,dc=com",
            crate::model::Attributes::new()
                .push(crate::model::Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "dnsNode".to_string()],
                ))
                .push(crate::model::Attribute::single("dc", "_ldap._tcp"))
                .push(
                    crate::model::Attribute::new("dnsRecord", vec!["AAECAw==".to_string()])
                        .binary(),
                ),
        );
        if let Err(violations) = schema.check(&node) {
            panic!("a zone node must validate: {violations:?}");
        }
    }

    #[test]
    fn an_entry_shaped_like_a_realm_principal_carrying_an_nt_hash_validates() {
        #[allow(unused_mut)]
        let mut schema = with_ad();
        #[cfg(feature = "kdc")]
        crate::kerberos::schema::extend(&mut schema).expect("the realm vocabulary parses");
        #[cfg(not(feature = "kdc"))]
        return;

        let entry = entry(
            "krb5PrincipalName=alice@EXAMPLE.COM,krb5RealmName=EXAMPLE.COM,dc=example,dc=com",
            crate::model::Attributes::new()
                .push(crate::model::Attribute::new(
                    "objectClass",
                    vec![
                        "top".to_string(),
                        "krb5Principal".to_string(),
                        "krb5KDCEntry".to_string(),
                    ],
                ))
                .push(crate::model::Attribute::single(
                    "krb5PrincipalName",
                    "alice@EXAMPLE.COM",
                ))
                .push(crate::model::Attribute::single(
                    "krb5PrincipalRealm",
                    "EXAMPLE.COM",
                ))
                .push(crate::model::Attribute::single("krb5KeyVersionNumber", "1"))
                .push(crate::model::Attribute::single("krb5KDCFlags", "12"))
                // The value Samba writes: MD4 of the UTF-16LE password, as thirty-two upper-case
                // hexadecimal digits. The exact digest does not matter to the schema, the shape does.
                .push(crate::model::Attribute::single(
                    "sambaNTPassword",
                    "8846F7EAEE8FB117AD06BDD830B7586C",
                )),
        );

        if let Err(violations) = schema.check(&entry) {
            let reported: Vec<_> = violations.iter().map(|v| format!("{v:?}")).collect();
            panic!("a principal carrying an NT hash must validate: {reported:?}");
        }
    }

    #[test]
    fn an_entry_shaped_like_a_computer_that_joined_validates() {
        // Exactly what `net ads join` writes, attribute by attribute: the four SPNs it derives from
        // its own name, the host name a member reads back to find itself, the account flags, and the
        // enctypes. If any of these is missing from the schema, the member's single `add` is refused
        // as a whole and the failure reads as a schema complaint rather than as a missing attribute
        // - which is the state this test was written to end.
        // Both vocabularies, as a server that is a domain controller loads them: the AD one
        // publishes the classes, the realm one defines the key attributes they now permit.
        let schema = {
            #[allow(unused_mut)]
            let mut schema = with_ad();
            #[cfg(feature = "kdc")]
            crate::kerberos::schema::extend(&mut schema).expect("the realm vocabulary parses");
            schema
        };
        #[allow(unused_mut)]
        let mut attributes = crate::model::Attributes::new()
            .push(crate::model::Attribute::new(
                "objectClass",
                vec![
                    "top".to_string(),
                    "person".to_string(),
                    "organizationalPerson".to_string(),
                    "user".to_string(),
                    "computer".to_string(),
                ],
            ))
            .push(crate::model::Attribute::single("cn", "samba"))
            // No `sn`: `net ads join` does not send one for a computer, and AD's `person`
            // does not require it (MS-ADSC: `systemMustContain: cn`).
            .push(crate::model::Attribute::single("sAMAccountName", "samba$"))
            .push(crate::model::Attribute::single(
                "dNSHostName",
                "samba.ad.example.com",
            ))
            .push(crate::model::Attribute::new(
                "servicePrincipalName",
                vec![
                    "HOST/samba".to_string(),
                    "HOST/samba.ad.example.com".to_string(),
                    "RestrictedKrbHost/samba".to_string(),
                    "RestrictedKrbHost/samba.ad.example.com".to_string(),
                ],
            ))
            .push(crate::model::Attribute::single(
                "userAccountControl",
                "4128",
            ))
            .push(crate::model::Attribute::single(
                "msDS-SupportedEncryptionTypes",
                "24",
            ))
            // A machine account is a security principal, and AD's schema requires a SID on it.
            .push(crate::model::Attribute::single("objectSid", "AQUAAAAAAAUVAAAA").binary());

        // The keys this server derives from `unicodePwd` in the same change. Without them the
        // account exists and the KDC answers `S_PRINCIPAL_UNKNOWN` to every request; with them and
        // no schema allowance, strict validation refuses the whole `add`.
        //
        // Behind the same feature as the vocabulary that defines them: `krb5Key` is Heimdal's
        // spelling and comes from the realm schema, so a build without `kdc` has neither the
        // attributes nor their definitions - and asserting them there failed the gate on a build
        // that cannot write them anyway.
        #[cfg(feature = "kdc")]
        {
            attributes = attributes
                .push(crate::model::Attribute::single("krb5Key", "\u{01}"))
                .push(crate::model::Attribute::single("krb5KeyVersionNumber", "1"))
                .push(crate::model::Attribute::single(
                    "msDS-KeyVersionNumber",
                    "1",
                ));
        }

        let entry = entry("cn=samba,cn=computers,dc=ad,dc=example,dc=com", attributes);

        if let Err(violations) = schema.check(&entry) {
            panic!("a computer account as a member writes it must validate: {violations:?}");
        }
    }

    #[test]
    fn an_attribute_the_class_does_not_allow_is_still_caught() {
        // The extension must not turn strict checking into "anything goes": a class list that
        // allowed everything would pass the test above for the wrong reason.
        let schema = with_ad();
        let entry = entry(
            "cn=Bob,ou=users,dc=example,dc=com",
            crate::model::Attributes::new()
                .push(crate::model::Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "person".to_string(), "user".to_string()],
                ))
                .push(crate::model::Attribute::single("cn", "Bob"))
                .push(crate::model::Attribute::single("sn", "Person"))
                .push(crate::model::Attribute::single("shadowLastChange", "19000")),
        );

        assert!(
            schema.check(&entry).is_err(),
            "an attribute outside the class list is a violation, extension or not"
        );
    }

    #[test]
    fn the_extension_is_not_part_of_the_core_schema() {
        // A server without a keytab must not publish AD vocabulary: it is not claiming to be a
        // domain controller, and a client that found these would rely on flags nothing maintains.
        let core = Schema::core();
        assert!(core.attribute("userprincipalname").is_none());
        assert!(core.class("user").is_none());
    }

    #[test]
    fn the_flag_word_decides_who_may_authenticate() {
        // 512 = NORMAL_ACCOUNT, the value a healthy AD user carries.
        assert!(
            UserAccountControl::parse("512")
                .expect("parsed")
                .may_authenticate()
        );
        // 514 = NORMAL_ACCOUNT | ACCOUNTDISABLE.
        assert!(
            !UserAccountControl::parse("514")
                .expect("parsed")
                .may_authenticate()
        );
        // 528 = NORMAL_ACCOUNT | LOCKOUT.
        assert!(
            !UserAccountControl::parse("528")
                .expect("parsed")
                .may_authenticate()
        );
        // Bits this server does not interpret alone leave the account usable.
        assert!(
            UserAccountControl::parse("66048")
                .expect("parsed")
                .may_authenticate(),
            "DONT_EXPIRE_PASSWORD is not a reason to refuse a ticket"
        );
    }

    #[test]
    fn a_flag_word_that_is_not_a_number_is_not_a_refusal() {
        // The caller decides what to do with `None`; this function must not guess that a value it
        // cannot read means "disabled", which would lock out an account over a typo.
        assert_eq!(UserAccountControl::parse("enabled"), None);
        assert_eq!(UserAccountControl::parse(""), None);
        assert_eq!(UserAccountControl::parse("-512"), None);
    }

    #[test]
    fn the_refusal_names_the_flag_that_caused_it() {
        let disabled = UserAccountControl::parse("514").expect("parsed");
        assert!(
            disabled
                .refusal()
                .is_some_and(|why| why.contains("disabled")),
            "{:?}",
            disabled.refusal()
        );

        let locked = UserAccountControl::parse("528").expect("parsed");
        assert!(
            locked.refusal().is_some_and(|why| why.contains("locked")),
            "{:?}",
            locked.refusal()
        );

        assert_eq!(
            UserAccountControl::parse("512").expect("parsed").refusal(),
            None
        );
    }

    /// The other half: an entry that is still wrong is still refused, or the override would be a
    /// licence to drop every constraint on the class it touched.
    #[test]
    fn a_person_without_cn_is_still_refused() {
        let schema = with_ad();
        let entry = entry(
            "o=someone,dc=ad,dc=example,dc=com",
            crate::model::Attributes::new()
                .push(crate::model::Attribute::single("objectClass", "person"))
                .push(crate::model::Attribute::single("sn", "someone")),
        );
        assert!(
            schema.check(&entry).is_err(),
            "`cn` is what AD requires of a person"
        );
    }
}
