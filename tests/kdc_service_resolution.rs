//! A service ticket for a machine account, asked for in any case.
//!
//! Measured on the AD-join stand: `kvno host/dc1` was answered and `kvno HOST/dc1` was
//! `SVC_UNAVAILABLE`, for one account that publishes both spellings. The cause was two entries per
//! account - the account itself with `servicePrincipalName` and no keys, and a second `krb5Principal`
//! entry written from the controller's keytab, with keys and the name in whatever case the keytab
//! carried. Which one answered depended on the case of the question, and the one that answered with
//! keys was not the account a client authenticates as.
//!
//! AD keeps one entry: the account holds the keys and the `servicePrincipalName` list, and a ticket
//! for any of those names is sealed in the account's key. That is the model here, and the tests below
//! hold the three halves of it - resolution in either case, the account's key being the one used, and
//! a service with no keys still being refused.
#![cfg(feature = "kdc")]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rrl_kdc::crypto::{Enctype, OwnCipher};
use rrl_kdc::hdb::ldap::dn_for;
use rrl_kdc::name::Principal;

use rrl_kdc::hdb::ldap::Directory as _;

use rrl_directory::backend::{Backend, EntryChange};
use rrl_directory::kerberos::{KerberosConfig, Settings, bootstrap, serve};
use rrl_directory::model::{Attribute, Entry};
use rrl_directory::reload::Source;

const REALM: &str = "EXAMPLE.COM";
const BASE_DN: &str = "dc=example,dc=com";
const PASSWORD: &str = "correct horse battery staple";
/// The account a machine joins as, and the two names it publishes.
const ACCOUNT: &str = "DC1$";
const SPNS: [&str; 2] = ["HOST/dc1.ad.example.com", "LDAP/dc1.ad.example.com"];

/// A source over a fresh redb store.
async fn source(dir: &std::path::Path) -> Arc<Source> {
    let store = dir.join("directory.redb");
    let text = format!(
        "base_dn: {BASE_DN}\n\
         backend: redb\n\
         backends:\n  redb:\n    path: {}\n\
         indexes:\n  default: [pres, eq, sub]\n\
         kerberos:\n  enabled: true\n",
        store.display()
    );
    let config =
        rrl_directory::config::resolve(rrl_directory::config::Args::default(), Some(&text), |_| {
            None
        })
        .expect("config");
    let backend = Backend::from_config("redb", config.backends.get("redb")).expect("backend");
    let (source, _) = Source::load(&config, backend).await.expect("source");
    source
}

/// The machine account, written the way the directory writes one: keys for `DC1$@REALM` and the
/// service names it publishes, in one entry.
async fn with_machine_account(source: &Arc<Source>) {
    let principal = Principal::parse(&format!("{ACCOUNT}@{REALM}")).expect("a principal");
    let mut hdb = rrl_kdc::hdb::HdbEntry::user(principal.clone());
    // SERVER: a ticket may be issued *for* this principal, not only to it. A machine account is
    // both - it logs in and it serves - which is what the flag says.
    hdb.flags = rrl_kdc::hdb::flags::SERVER | rrl_kdc::hdb::flags::FORWARDABLE;
    for enctype in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        hdb.add_password_key(&OwnCipher, enctype, PASSWORD.as_bytes(), 1)
            .expect("a key");
    }

    // The classes AD publishes for a machine, in the order `net ads join` writes them. `computer`
    // and not `user` alone: `sAMAccountName` and `dNSHostName` are allowed by AD's `computer`, and a
    // strict server refuses an entry that claims the attributes without the class.
    // `replace` and not `push`: the realm's own attributes carry `objectClass: krb5Principal`, and a
    // second attribute of the same name is kept beside it rather than merged - the first one wins on
    // lookup, so the classes AD publishes were never seen and the write was refused for attributes
    // its `computer` allows. Measured: "attribute 'samaccountname' is not allowed by any object
    // class", for an entry that named the class.
    let mut attributes = bootstrap::attributes_of(&hdb);
    // Only the classes AD publishes: `krb5Principal` is structural and refuses to coexist with
    // `computer`. The realm's own attributes that the account does not keep - `krb5KDCFlags` above
    // all - are dropped, and the flags are then read from `userAccountControl` the way a real
    // account's are: a principal that publishes a service name is a server, which is what a ticket
    // for `HOST/...` needs.
    attributes = attributes.replace(Attribute::new(
        "objectClass",
        vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
            "user".to_string(),
            "computer".to_string(),
        ],
    ));
    for absent in ["krb5KDCFlags", "krb5EncryptionType"] {
        attributes = attributes.without(absent);
    }
    attributes = attributes.replace(Attribute::single("userAccountControl", "4096"));
    attributes = attributes.replace(Attribute::single("cn", "DC1"));
    attributes = attributes.replace(Attribute::single("sAMAccountName", ACCOUNT));
    attributes = attributes.replace(Attribute::single("dNSHostName", "dc1.ad.example.com"));
    // One attribute with every name, not one attribute per name: `push` appends, and a reader takes
    // the first attribute of that description - so two `servicePrincipalName` attributes made the
    // account publish only the first, and a ticket for the second answered `S_PRINCIPAL_UNKNOWN`.
    // Measured here, before this line was written.
    attributes = attributes.replace(Attribute::new(
        "servicePrincipalName",
        SPNS.iter()
            .map(|spn| (*spn).to_string())
            .collect::<Vec<_>>(),
    ));
    // A machine account is a security principal, and AD's `computer` requires a SID of one.
    attributes = attributes.replace(Attribute::single("objectSid", "AQUAAAAAAAUVAAAA").binary());

    let dn = format!("cn=DC1,cn=computers,{BASE_DN}");
    source
        .apply(&[EntryChange::Upsert {
            entry: Entry::new(dn, attributes),
        }])
        .await
        .unwrap_or_else(|err| panic!("the machine account is written: {err}"));
}

fn settings(realm: &str) -> Settings {
    let config = KerberosConfig {
        enabled: true,
        realm: Some(realm.to_string()),
        port: Some(0),
        master_key_file: None,
    };
    Settings::resolve(&config, BASE_DN, IpAddr::V4(Ipv4Addr::LOCALHOST)).expect("settings")
}

fn master_file(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("master");
    std::fs::write(&path, "the realm master password\n").expect("write");
    path
}

/// Starts the KDC over `source` and returns its address.
async fn start(
    source: &Arc<Source>,
    dir: &std::path::Path,
) -> (std::net::SocketAddr, tokio::sync::watch::Sender<bool>) {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let running = serve::start(
        &settings(REALM),
        Arc::clone(source),
        BASE_DN.to_string(),
        Some(&master_file(dir)),
        None,
        shutdown_rx,
    )
    .await
    .expect("the KDC starts");
    (running.bind, shutdown_tx)
}

/// A ticket for any name the account publishes, asked for in either case.
///
/// The names are compared as AD compares them - `servicePrincipalName` has a case-insensitive
/// matching rule, and a Windows service asks for `HOST/host` in upper case while the account holds
/// whatever the join wrote. A KDC that answers only the spelling in the directory is one that works
/// for the tools written against this implementation and fails for the clients it exists to serve.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_machine_account_answers_for_its_names_in_either_case() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(dir.path()).await;
    with_machine_account(&source).await;
    let (bind, shutdown) = start(&source, dir.path()).await;

    let client = krb5::KdcClient::new(REALM, [bind.to_string().as_str()]);
    let account = krb5::Principal::parse(&format!("{ACCOUNT}@{REALM}")).expect("a principal");
    let tgt = client
        .login_with_password(&account, PASSWORD)
        .expect("the account logs in with its own password");

    for spn in SPNS {
        for spelling in [spn.to_string(), spn.to_uppercase(), spn.to_lowercase()] {
            let wanted = krb5::Principal::parse(&format!("{spelling}@{REALM}"))
                .unwrap_or_else(|err| panic!("'{spelling}' is a principal: {err}"));
            let ticket = client
                .service_ticket(&tgt, &wanted)
                .unwrap_or_else(|err| panic!("a ticket for '{spelling}' has to be issued: {err}"));
            // The ticket names the *requested* service, so the client's acceptor looks it up by the
            // name it asked for - that is RFC 4120 §7.5.1 and not a detail of this server.
            assert_eq!(
                ticket.server.components, wanted.components,
                "'{spelling}' comes back under the name it was asked for"
            );
        }
    }

    let _ = shutdown.send(true);
}

/// The account's key, and not a second entry's: a client that proves the machine password opens the
/// ticket a service gets.
///
/// This is the half a resolution test cannot see. If the KDC inked the ticket in a key from the
/// controller's keytab, a client asking for `HOST/dc1` would still get an answer and only the
/// acceptor would fail - with `KRB_AP_ERR_MODIFIED`, which reads as a protocol fault rather than as
/// two keys for one account.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_ticket_is_sealed_in_the_accounts_own_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(dir.path()).await;
    with_machine_account(&source).await;
    let (bind, shutdown) = start(&source, dir.path()).await;

    let client = krb5::KdcClient::new(REALM, [bind.to_string().as_str()]);
    let account = krb5::Principal::parse(&format!("{ACCOUNT}@{REALM}")).expect("a principal");
    let tgt = client
        .login_with_password(&account, PASSWORD)
        .expect("a login");

    let wanted = krb5::Principal::parse(&format!("HOST/dc1.ad.example.com@{REALM}")).expect("a p");
    client
        .service_ticket(&tgt, &wanted)
        .expect("a ticket for the service name");

    // Which key sealed it is the question, and it is answerable one step back: the KDC seals a ticket
    // in whatever `fetch_for_service` returned, so the keys resolution hands over *are* the keys the
    // ticket is encrypted with. Asking the realm directly is not a proxy for the property, it is the
    // property.
    let realm =
        rrl_directory::kerberos::realm::RealmView::new(REALM, BASE_DN, source.directory().await);
    let published = realm
        .get_by_spn(SPNS[0])
        .expect("the name resolves")
        .expect("the account publishes it");

    // The account's own `krb5Key` values, exactly as the directory stores them.
    let snapshot = source.directory().await;
    let account_entry = snapshot
        .find(&format!("cn=DC1,cn=computers,{BASE_DN}"))
        .expect("the account is there");
    let stored: Vec<Vec<u8>> = account_entry
        .attributes()
        .get("krb5Key")
        .map(|attribute| {
            attribute
                .values
                .iter()
                .map(|value| {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD
                        .decode(value)
                        .expect("a key is base64")
                })
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !stored.is_empty(),
        "the account has keys, or nothing could be signed"
    );

    let delivered = published.get(rrl_kdc::hdb::ldap::attrs::KEY);
    let delivered: Vec<Vec<u8>> = delivered.to_vec();
    assert!(
        !delivered.is_empty(),
        "the name resolves to keys, or the ticket would have been refused"
    );
    for value in &delivered {
        assert!(
            stored.iter().any(|key| key == value),
            "the key the KDC seals a ticket in has to be the account's, not another entry's"
        );
    }

    let _ = shutdown.send(true);
}

/// A name nothing publishes is still refused - the negative that keeps the two above honest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_no_account_publishes_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(dir.path()).await;
    with_machine_account(&source).await;
    let (bind, shutdown) = start(&source, dir.path()).await;

    let client = krb5::KdcClient::new(REALM, [bind.to_string().as_str()]);
    let account = krb5::Principal::parse(&format!("{ACCOUNT}@{REALM}")).expect("a principal");
    let tgt = client
        .login_with_password(&account, PASSWORD)
        .expect("a login");

    let absent = krb5::Principal::parse(&format!("NOPRINTER/dc1.ad.example.com@{REALM}"))
        .expect("a principal");
    assert!(
        client.service_ticket(&tgt, &absent).is_err(),
        "a service the account never published must not be issued"
    );

    let _ = shutdown.send(true);
}

/// A second entry left over from before is shadowed, not obeyed.
///
/// Directories that this server has already run against hold one `krb5Principal` entry per keytab
/// line, each with the keytab's own key. Nothing deletes them - an entry is somebody's data - so
/// resolution has to prefer the account, or the leftover answers a service ticket with a key the
/// account never had and the acceptor refuses a ticket the KDC considers valid.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_leftover_principal_entry_does_not_win() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(dir.path()).await;
    with_machine_account(&source).await;

    // The leftover: the name as a principal, with a key nothing else holds.
    let stale = Principal::parse(&format!("{}@{REALM}", SPNS[0])).expect("a principal");
    let mut hdb = rrl_kdc::hdb::HdbEntry::service(stale.clone());
    hdb.add_key(
        rrl_kdc::crypto::Key::new(Enctype::Aes256Sha1, vec![0x77; 32]).expect("a key"),
        9,
        None,
    );
    let stale_dn = dn_for(&stale, BASE_DN);
    source
        .apply(&[EntryChange::Upsert {
            entry: Entry::new(stale_dn.clone(), bootstrap::attributes_of(&hdb)),
        }])
        .await
        .unwrap_or_else(|err| panic!("the leftover is written: {err}"));

    let realm =
        rrl_directory::kerberos::realm::RealmView::new(REALM, BASE_DN, source.directory().await);
    let published = realm
        .get(&stale)
        .expect("the name resolves")
        .expect("something answers for it");

    // The account's keys, not the leftover's: the leftover's one key is 0x77 repeated, and it must
    // not be among what resolution delivers.
    let leftover_key = {
        let mut entry = rrl_kdc::hdb::HdbEntry::service(stale.clone());
        entry.add_key(
            rrl_kdc::crypto::Key::new(Enctype::Aes256Sha1, vec![0x77; 32]).expect("a key"),
            9,
            None,
        );
        bootstrap::attributes_of(&entry)
            .get("krb5Key")
            .and_then(|attribute| attribute.values.first().cloned())
            .expect("the leftover has a key")
    };
    let delivered: Vec<String> = published
        .get(rrl_kdc::hdb::ldap::attrs::KEY)
        .iter()
        .map(|value| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(value)
        })
        .collect();
    assert!(!delivered.is_empty(), "the account publishes keys");
    assert!(
        !delivered.contains(&leftover_key),
        "a ticket must not be sealed in the leftover entry's key"
    );
}

/// A keytab's keys land on the account that publishes the name, not on a second entry.
///
/// This is the provisioning half, and it is where the defect came from: `ensure_keytab_principals`
/// wrote one `krb5Principal` entry per name in the keytab, so an account that publishes
/// `HOST/dc1.ad.example.com` and a keytab entry of the same name were two entries, one with the
/// password and one with the keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_keytab_s_keys_go_to_the_account_that_publishes_the_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = source(dir.path()).await;
    // The account as the join leaves it: an SPN and no keys yet.
    let dn = format!("cn=DC1,cn=computers,{BASE_DN}");
    let attributes = rrl_directory::model::Attributes::new()
        .push(Attribute::new(
            "objectClass",
            vec![
                "top".to_string(),
                "person".to_string(),
                "organizationalPerson".to_string(),
                "user".to_string(),
                "computer".to_string(),
            ],
        ))
        .push(Attribute::single("cn", "DC1"))
        .push(Attribute::single("sAMAccountName", ACCOUNT))
        .push(Attribute::single("dNSHostName", "dc1.ad.example.com"))
        .push(Attribute::single("servicePrincipalName", SPNS[0]))
        .push(Attribute::single("objectSid", "AQUAAAAAAAUVAAAA").binary());
    source
        .apply(&[EntryChange::Upsert {
            entry: Entry::new(dn.clone(), attributes),
        }])
        .await
        .unwrap_or_else(|err| panic!("the account: {err}"));

    let keytab = dir.path().join("account.keytab");
    let mut tab = krb5::Keytab::new();
    tab.add(krb5::ServiceKey::new(
        SPNS[0],
        REALM,
        1,
        krb5::EncType::AES256CtsHmacSha196,
        vec![0x11; 32],
    ));
    tab.save(&keytab).expect("keytab");

    let written = bootstrap::ensure_keytab_principals(&source, REALM, BASE_DN, &keytab)
        .await
        .expect("the keytab is read");

    // The account got the keys ...
    let snapshot = source.directory().await;
    let stored = snapshot.find(&dn).expect("the account is still there");
    assert!(
        stored.attributes().get("krb5Key").is_some(),
        "the keys belong on the account that publishes the name"
    );

    // ... and no second entry was made for the name.
    let duplicate = dn_for(
        &Principal::parse(&format!("{}@{REALM}", SPNS[0])).expect("a principal"),
        BASE_DN,
    );
    assert!(
        source.directory().await.find(&duplicate).is_none(),
        "a second entry for a name an account publishes is what made the case matter: {written:?}"
    );
}
