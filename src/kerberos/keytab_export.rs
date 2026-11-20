//! This controller's own keys, as a keytab.
//!
//! SMB's SESSION_SETUP accepts Kerberos only when the server holds the key a client's service ticket
//! was sealed with. Without one there is one single path left - NTLM - and that path is exactly the
//! one a Windows member refuses for anything but the first join: measured, the guest joined far
//! enough to create its account and then could not prove a secure channel, because everything after
//! the account exists is expected to be a ticket.
//!
//! # Where the keys come from
//!
//! From this domain, not from a file somebody generated elsewhere. A controller is a member of its own
//! domain: it has a machine account, that account has keys, and the realm answers for the service
//! names the account publishes. So the export is a read of the directory - and on a domain that has
//! never run it, a single write that gives the controller its account, exactly as a member's join
//! gives one to the member.
//!
//! # Why the same key under several names
//!
//! A client asks for `cifs/dc1.ad.example.com@AD.EXAMPLE.COM`, and the KDC answers with a ticket
//! sealed in the key of the account that publishes that name. The acceptor is handed the ticket and
//! nothing else - no hint of which keytab entry to use - so the keytab carries the same key material
//! under every name the controller is reached by: the account's own principal, `HOST/`, `CIFS/`,
//! `LDAP/` and `RestrictedKrbHost/`, each in the DNS form and the NetBIOS form. That is what Samba's
//! own DC keytab holds, and for the same reason: a keytab that named only one of them answers a
//! ticket for the others with `KRB_AP_ERR_MODIFIED`, which reads as a wrong password.

use std::path::{Path, PathBuf};

use rrl_kdc::crypto::OwnCipher;
use rrl_kdc::hdb::HdbEntry;
use rrl_kdc::hdb::ldap::from_attributes;
use rrl_kdc::name::Principal;

use crate::backend::{Backend, EntryChange};
use crate::model::{Attribute, Attributes, Entry};

use super::bootstrap::{ENCTYPES, attributes_of};

/// `UF_SERVER_TRUST_ACCOUNT | UF_WORKSTATION_TRUST_ACCOUNT`: the flags of a domain controller's own
/// machine account, which is a member of the domain it serves.
const DC_ACCOUNT_CONTROL: u32 = 0x3000;
/// `DOMAIN_GROUP_RID_CONTROLLERS`: the group a controller's account belongs to.
const DOMAIN_CONTROLLERS_RID: u32 = 516;

/// The flags a controller's account needs, and the reason each one is here.
///
/// `SERVER` is what lets the TGS seal a ticket for a name this account publishes - without it every
/// `cifs/…` request is answered `KDC_ERR_S_PRINCIPAL_UNKNOWN` for an account whose keys are right
/// there. The client side is what a machine does with its own keytab: `kinit -k`, and the
/// `netr_ServerAuthenticate3` that follows a join.
const REQUIRED_FLAGS: u32 = rrl_kdc::hdb::flags::SERVER
    | rrl_kdc::hdb::flags::CLIENT
    | rrl_kdc::hdb::flags::FORWARDABLE
    | rrl_kdc::hdb::flags::PROXIABLE
    | rrl_kdc::hdb::flags::RENEWABLE
    | rrl_kdc::hdb::flags::REQUIRE_PREAUTH;

/// The flags a controller's account must **not** have.
///
/// `initial` (Heimdal's `hdb` flag) means "a ticket for this service must come from an AS-REQ", and
/// its purpose is `kadmin/changepw`: a password that any stolen TGT could rotate is a password an
/// attacker rotates to lock the owner out. On a machine account it means the opposite of what it
/// looks like - every `cifs/…` request is refused with `KDC_ERR_POLICY`, "requires an initial
/// ticket", for an account that is not `kadmin` at all. It arrived here by copying `user`'s flags,
/// and it is cleared rather than merely not added.
const FORBIDDEN_FLAGS: u32 = rrl_kdc::hdb::flags::INITIAL;

/// What an export wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exported {
    /// The keytab, as it was written.
    pub path: PathBuf,
    /// The account the keys belong to.
    pub dn: String,
    /// Whether this run had to create that account.
    pub created: bool,
    /// The principal names the keytab holds, in the order it holds them.
    pub principals: Vec<String>,
}

/// Writes `path` a keytab for this controller, creating its account when the domain has none.
///
/// `dns_host` is the name clients reach this server by - the one the root DSE publishes - and
/// `dns_domain` the domain's, so the two forms of every service name agree with what a client found
/// through DNS.
pub async fn export(
    backend: &Backend,
    realm: &str,
    base_dn: &str,
    netbios: &str,
    dns_host: &str,
    dns_domain: &str,
    path: &Path,
) -> Result<Exported, String> {
    let account = format!("{}$", netbios.to_uppercase());
    let principal = Principal::parse(&format!("{account}@{realm}"))
        .map_err(|err| format!("'{account}@{realm}' is not a principal: {err}"))?;
    // Where AD files a controller's own account: an organizational unit of its own, not the
    // container the members it serves are created in.
    let dn = format!(
        "cn={},{},{base_dn}",
        netbios,
        crate::provision::DOMAIN_CONTROLLERS_OU
    );

    let loaded = backend
        .load()
        .await
        .map_err(|err| format!("reading the directory: {err}"))?;
    let directory = loaded.into_directory(base_dn, "users", "groups");
    let existing = match directory.find(&dn).cloned() {
        Some(entry) => Some(entry),
        // An account this server wrote before it filed controllers where AD files them lives in
        // `cn=computers`. Found by its `sAMAccountName`, read through `record` because the snapshot's
        // entries are skeletons - and carried over to the canonical DN below rather than left
        // behind: a second account for the same controller carries a second SID, and the SIDs already
        // handed out name the first.
        None => {
            let mut found = None;
            for identity in directory.all() {
                let Some(record) = directory.record(identity.dn()) else {
                    continue;
                };
                let named = record
                    .attributes()
                    .get("sAMAccountName")
                    .and_then(|attribute| attribute.values.first())
                    .is_some_and(|value| value.eq_ignore_ascii_case(&account));
                if named {
                    found = Some(record.into_owned());
                    break;
                }
            }
            found
        }
    };
    // The SID the account already carries, which travels with it: a write rebuilds the entry from the
    // keytab, and a SID issued above is not the only case - an account that already has one and is
    // written again, because it moved to the DN AD files controllers at or because its shape had to
    // be repaired, keeps the value it has. Measured the hard way: the write rebuilt the entry without
    // the SID the old one carried, and the move left a controller account no ACL could name.
    let existing_sid = existing
        .as_ref()
        .and_then(|entry| entry.attributes().get("objectSid"))
        .and_then(|attribute| attribute.values.first())
        .filter(|value| !value.is_empty())
        .cloned();
    // The DN the account is stored at now, when that is not the canonical one.
    let moved_from = existing
        .as_ref()
        .map(|entry| entry.dn().to_string())
        .filter(|have| !have.eq_ignore_ascii_case(&dn));

    // Whether the account already carries a SID decides whether one has to be issued: `take` moves
    // the domain's counter, and a counter moved for an account that had one would skip a number for
    // no reason.
    let has_sid = existing.as_ref().is_some_and(|entry| {
        entry
            .attributes()
            .get("objectSid")
            .is_some_and(|attribute| !attribute.values.is_empty())
    });
    // Whether the stored account is shaped like one at all: a store written by an earlier build kept
    // the realm's `krb5Principal` classes and never gained `computer`, and the write below is
    // otherwise skipped for it on every start, so the wrong shape would stay forever. Measured: the
    // schema reported `sAMAccountName`, `objectSid`, `dNSHostName` and `primaryGroupID` as "not
    // allowed by any object class" for the controller's own account on every reload.
    // Both classes, and neither is optional: `computer` is what makes the entry a machine account,
    // and `krb5KDCEntry` is what allows the realm's own attributes (`krb5KDCFlags` among them) to sit
    // on it. An entry with one and not the other is one this command has to repair, which is why it
    // is part of the shape rather than a separate condition.
    let shaped_like_an_account = existing.as_ref().is_some_and(|entry| {
        let Some(classes) = entry.attributes().get("objectClass") else {
            return false;
        };
        let has = |wanted: &str| {
            classes
                .values
                .iter()
                .any(|value| <str>::eq_ignore_ascii_case(value, wanted))
        };
        has("computer") && has("krb5KDCEntry")
    });
    let (mut entry, mut created) = match existing {
        Some(entry) => (read_back(&entry, &principal)?, false),
        None => (create(&principal)?, true),
    };

    // Every name a client may ask for, all sealed in the one key. Short forms included: a client
    // that reached the controller by its NetBIOS name asks for `cifs/dc1` and the ticket is sealed in
    // the same key.
    //
    // **Lower case**, because RFC 4120 §6.2 makes a principal's components case-sensitive: a client
    // asks for `cifs/dc1.ad.example.com` and the acceptor looks the key up under exactly that name,
    // so a keytab holding `CIFS/…` answers "service principal not found" for a ticket the KDC has
    // just issued. Measured twice - once with the service in upper case and once with the host name.
    // The account's own principal keeps the case the directory stores it in, because that is the name
    // its tickets carry.
    let short = netbios.to_lowercase();
    let host = dns_host.to_lowercase();
    let names = [
        account.clone(),
        format!("host/{host}"),
        format!("host/{short}"),
        format!("cifs/{host}"),
        format!("cifs/{short}"),
        format!("ldap/{host}"),
        format!("ldap/{short}"),
        format!("restrictedkrbhost/{host}"),
        format!("restrictedkrbhost/{short}"),
    ];

    let mut keytab = krb5::Keytab::new();
    let mut written = Vec::new();
    for name in &names {
        let mut any = false;
        for key in &entry.keys {
            // The enctype lives inside the key, because a key without one is not a key: this is the
            // number a keytab records and the acceptor looks the key up by.
            let Some(enctype) = krb5::EncType::from_i32(key.key.enctype() as i32) else {
                continue;
            };
            keytab.add(krb5::ServiceKey::new(
                name.clone(),
                realm,
                key.kvno,
                enctype,
                key.key.bytes().to_vec(),
            ));
            any = true;
        }
        if any {
            written.push(format!("{name}@{realm}"));
        }
    }
    if written.is_empty() {
        return Err(format!(
            "'{dn}' holds no key this acceptor can use, so a keytab written from it would be empty"
        ));
    }

    keytab
        .save(path)
        .map_err(|err| format!("writing '{}': {err}", path.display()))?;
    // The file is the password of this controller: readable by the process that serves, and by
    // nobody else.
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, mode)
            .map_err(|err| format!("making '{}' private: {err}", path.display()))?;
    }

    // Written when it is new, and repaired when an existing account is missing a flag it needs: an
    // account created by an earlier version of this command has keys and no `server` flag, and a
    // realm that keeps it that way refuses every service ticket for a name it publishes.
    let missing = entry.flags & REQUIRED_FLAGS != REQUIRED_FLAGS;
    let forbidden = entry.flags & FORBIDDEN_FLAGS != 0;
    if missing || forbidden {
        tracing::info!(
            dn = %dn,
            before = format_args!("{:#010x}", entry.flags),
            after = format_args!(
                "{:#010x}",
                (entry.flags | REQUIRED_FLAGS) & !FORBIDDEN_FLAGS
            ),
            "keytab: the account's flags are missing a half, and are repaired"
        );
        entry.flags = (entry.flags | REQUIRED_FLAGS) & !FORBIDDEN_FLAGS;
        created = true;
    }
    // The account's SID, which is what a PAC is built from: a machine account without one is an
    // account every ticket for it says nothing about, and an ACL naming it can never match.
    let mut sid_attribute = existing_sid;
    if !has_sid {
        // `take` records the new position before returning, and a number skipped by a crash is a
        // number nobody can tell from one never used.
        let mut entropy = [0u8; 16];
        getrandom::fill(&mut entropy)
            .map_err(|err| format!("no randomness for the domain's identity: {err}"))?;
        let issuer = crate::sid::domain::Issuer::open(backend, entropy)
            .map_err(|err| format!("the domain has no SID to issue one from: {err}"))?;
        let sid = issuer
            .take()
            .map_err(|err| format!("the domain could not issue a SID: {err}"))?;
        use base64::Engine as _;
        sid_attribute = Some(base64::engine::general_purpose::STANDARD.encode(sid.to_bytes()));
    }

    // `has_sid` is false equally for a new account and for one that lost its SID, and both need the
    // write. An account that already had one is written only when something else about it changed.
    if created || !has_sid || !shaped_like_an_account || moved_from.is_some() {
        let mut entry = entry_of(&entry, dn.clone(), dns_host, dns_domain);
        if let Some(encoded) = sid_attribute {
            entry = crate::model::Entry::new(
                entry.dn().to_string(),
                entry
                    .attributes()
                    .clone()
                    // Binary: the value is base64 in the store and a SID on the wire.
                    .push(crate::model::Attribute::single("objectSid", &encoded).binary()),
            );
        }
        if std::env::var_os("RRL_KEYTAB_DIAG").is_some() {
            eprintln!(
                "keytab: writing {dn}: created={created} shaped={shaped_like_an_account} classes={:?}",
                entry
                    .attributes()
                    .get("objectClass")
                    .map(|attribute| attribute.values.clone())
                    .unwrap_or_default()
            );
        }
        let mut changes = vec![EntryChange::Upsert { entry }];
        // The old DN goes in the same change: a store that kept both would have two accounts for one
        // controller, and the second is one no SID ever named.
        if let Some(old) = &moved_from {
            // A controller's account is a user-shaped object, which is the kind the store needs to
            // know to find it in the collection it lives in.
            changes.push(EntryChange::Delete {
                dn: old.clone(),
                kind: Some(crate::backend::ObjectKind::User),
            });
        }
        backend
            .apply(&changes)
            .await
            .map_err(|err| format!("writing '{dn}': {err}"))?;
    }

    Ok(Exported {
        path: path.to_path_buf(),
        dn,
        created,
        principals: written,
    })
}

/// The account as the directory already holds it, or why it cannot be exported.
fn read_back(entry: &Entry, principal: &Principal) -> Result<HdbEntry, String> {
    let mut attributes = crate::kerberos::realm::to_realm_attributes(entry.attributes());
    // An account created by something else may carry the name in `sAMAccountName` alone; the mapping
    // needs a principal, and the account's own is what the ticket will be sealed for.
    if !attributes.has(rrl_kdc::hdb::ldap::attrs::PRINCIPAL_NAME) {
        attributes.add(
            rrl_kdc::hdb::ldap::attrs::PRINCIPAL_NAME,
            principal.to_string(),
        );
    }
    from_attributes(&attributes)
        .map_err(|err| format!("'{}' does not read back as a principal: {err}", entry.dn()))
}

/// The account a domain that has never run this command does not have yet.
///
/// `HdbEntry::user` and a password nobody keeps: the keys are what a keytab needs, and a password
/// that exists only inside this function is a password that cannot leak. The password is random
/// rather than fixed for exactly that reason - two domains exporting their first keytab must not
/// share a key.
fn create(principal: &Principal) -> Result<HdbEntry, String> {
    let mut password = [0u8; 32];
    getrandom::fill(&mut password).map_err(|err| format!("no randomness for the key: {err}"))?;
    // Hexadecimal, so that the value is text: the derivation takes octets, and octets that are also a
    // printable string are what a `ktutil addent` would have produced had an operator made this file.
    let password = password
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let cipher = OwnCipher;
    // A controller's account is both halves at once: it logs on like a machine (`kinit -k` from its
    // own keytab) and is the service a client asks a ticket for (`cifs/…`). `user` gives the client
    // flags and `service` the server one, so the two are combined here rather than picking one -
    // measured: with `user` alone the TGS refuses every service ticket with
    // `KDC_ERR_S_PRINCIPAL_UNKNOWN`, "may not be issued a ticket", for an account whose keys are
    // right there in the entry.
    let mut entry = HdbEntry::service(principal.clone());
    entry.flags = (entry.flags | REQUIRED_FLAGS) & !FORBIDDEN_FLAGS;
    entry.kvno = 1;
    for enctype in ENCTYPES {
        entry
            .add_password_key(&cipher, enctype, password.as_bytes(), 1)
            .map_err(|err| format!("a key for {enctype:?}: {err}"))?;
    }
    Ok(entry)
}

/// The account as the directory stores it, with the names a member publishes.
fn entry_of(account: &HdbEntry, dn: String, dns_host: &str, dns_domain: &str) -> Entry {
    let name = account.principal.name();
    let short = name.trim_end_matches('$').to_string();
    let domain = dns_domain.to_ascii_lowercase();
    let host = dns_host.to_ascii_lowercase();
    let short_lower = short.to_lowercase();

    let mut spns = Vec::new();
    for service in ["HOST", "CIFS", "LDAP", "RestrictedKrbHost"] {
        spns.push(format!("{service}/{host}"));
        spns.push(format!("{service}/{short_lower}"));
        // The DNS form the client found through DNS, when it is not the name already above.
        if !domain.is_empty() && !host.ends_with(&domain) {
            spns.push(format!("{service}/{short_lower}.{domain}"));
        }
    }
    spns.sort_unstable();
    spns.dedup();

    let attributes: Attributes = attributes_of(account)
        // `replace`, not `push`: the realm's own vocabulary has already put `top` and the two
        // `krb5*` classes here, and `push` appends a second `objectClass` beside them. Readers take
        // the first match, so the entry kept its `krb5Principal` shape and lost the `computer` one -
        // measured, the schema then reported `sAMAccountName`, `objectSid`, `dNSHostName` and
        // `primaryGroupID` as "not allowed by any object class" for the controller's own account.
        .replace(Attribute::new(
            "objectClass",
            vec![
                "top".to_string(),
                "person".to_string(),
                "organizationalPerson".to_string(),
                "user".to_string(),
                "computer".to_string(),
                // Auxiliary, and it has to be here: `krb5KDCEntry` is the class that allows
                // `krb5KDCFlags` and the rest of the realm's attributes on an account that is also a
                // machine. `krb5Principal` is not - it is *structural*, and two structural classes
                // from different trees is an entry the schema refuses.
                "krb5KDCEntry".to_string(),
            ],
        ))
        .push(Attribute::single("cn", &short))
        .push(Attribute::single("sAMAccountName", &name))
        .push(Attribute::single(
            "userAccountControl",
            &DC_ACCOUNT_CONTROL.to_string(),
        ))
        .push(Attribute::single(
            "primaryGroupID",
            &DOMAIN_CONTROLLERS_RID.to_string(),
        ))
        // The service names, which are what makes this account the one the realm answers for when a
        // client asks for a ticket to `cifs/…`. Without them the account has keys and nothing to use
        // them for: the TGS answers `KDC_ERR_S_PRINCIPAL_UNKNOWN`, which a client reports as an
        // unknown service rather than as a missing name.
        .push(Attribute::new("servicePrincipalName", spns))
        .push(Attribute::single("dNSHostName", dns_host));
    Entry::new(dn, attributes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The service names a machine account publishes, derived the way this module derives them.
    #[test]
    fn a_controller_publishes_the_names_a_client_asks_for() {
        let principal = Principal::parse("DC1$@AD.EXAMPLE.COM").expect("a principal");
        let entry = create(&principal).expect("keys");
        let account = entry_of(
            &entry,
            "cn=DC1,cn=computers,dc=ad,dc=example,dc=com".to_string(),
            "dc1.ad.example.com",
            "ad.example.com",
        );
        let spns = account
            .attributes()
            .get("servicePrincipalName")
            .expect("the names are published")
            .values
            .clone();

        for wanted in [
            "CIFS/dc1.ad.example.com",
            "CIFS/dc1",
            "HOST/dc1.ad.example.com",
            "LDAP/dc1.ad.example.com",
            "RestrictedKrbHost/dc1",
        ] {
            assert!(
                spns.iter().any(|spn| spn == wanted),
                "'{wanted}' is missing from {spns:?}"
            );
        }
        assert_eq!(
            spns.len(),
            spns.iter().collect::<std::collections::BTreeSet<_>>().len(),
            "and no name is published twice"
        );
    }

    /// The keys a keytab is written from are all four the acceptor can use, and under one kvno.
    #[test]
    fn the_account_has_a_key_for_every_enctype_the_acceptor_reads() {
        let principal = Principal::parse("DC1$@AD.EXAMPLE.COM").expect("a principal");
        let entry = create(&principal).expect("keys");
        assert_eq!(entry.keys.len(), ENCTYPES.len());
        for etype in ENCTYPES {
            assert!(
                entry.keys.iter().any(|key| key.key.enctype() == etype),
                "{etype:?} has no key"
            );
            assert!(
                krb5::EncType::from_i32(etype as i32).is_some(),
                "{etype:?} would be dropped from the keytab"
            );
        }
    }
}
