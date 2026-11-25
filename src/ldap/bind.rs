//! Bind operation: simple authentication against user entries.

use rasn_ldap::{AuthenticationChoice, BindRequest, MessageId, ResultCode};

use super::responses::bind_response;
use super::session::{Identity, Session};
use crate::acl::Requester;
use crate::directory::Directory;
use crate::dn;
use crate::model::Entry;
use crate::password::verify;
use crate::security::Security;

/// Result of a bind: the response, and an entry to store when the password hash
/// needs upgrading.
///
/// The upgrade is kept separate from the response because the two are not one decision:
/// by the time the new hash exists the bind has already succeeded, so failing to store
/// it must not turn a correct `success` into an error.
pub struct Outcome {
    pub message: rasn_ldap::LdapMessage,
    pub upgrade: Option<crate::model::Entry>,
}

/// Handles a bind request and updates the session identity.
///
/// Kept as the simple entry point for callers that do not care about the hash upgrade;
/// the dispatcher uses [`handle_bind_outcome`].
pub fn handle_bind(
    session: &mut Session,
    directory: &Directory,
    message_id: MessageId,
    request: &BindRequest,
    security: &Security,
) -> rasn_ldap::LdapMessage {
    handle_bind_outcome(session, directory, message_id, request, security).message
}

/// Handles a bind request, and reports an entry to store when the stored hash is not in
/// the configured scheme.
///
/// The identity is cleared first: per RFC 4513 a failed bind leaves the
/// connection anonymous, and gorestldap kept the previous ACL in that case.
pub fn handle_bind_outcome(
    session: &mut Session,
    directory: &Directory,
    message_id: MessageId,
    request: &BindRequest,
    security: &Security,
) -> Outcome {
    let mut upgrade = None;
    let message = authenticate(
        session,
        directory,
        message_id,
        request,
        security,
        &mut upgrade,
    );

    Outcome { message, upgrade }
}

/// Does the work and reports the upgrade through `upgrade`.
///
/// The out-parameter keeps every refusal a single `return` of a response, which is what
/// makes the failure paths below readable; a returned tuple would need wrapping at each
/// one of them.
fn authenticate(
    session: &mut Session,
    directory: &Directory,
    message_id: MessageId,
    request: &BindRequest,
    security: &Security,
    upgrade: &mut Option<crate::model::Entry>,
) -> rasn_ldap::LdapMessage {
    // Before the reset: a SASL bind is several requests, and the exchange between them lives on
    // the session. Clearing it here - which is what a simple bind must do - made every round look
    // like the first one, and a live client got "the first token must carry the ticket" on its
    // second message.
    if super::sasl_bind::is_gssapi(request) {
        return super::sasl_bind::handle_gssapi(session, directory, message_id, request, security);
    }

    // A bind that names NTLMSSP outright - Samba's `GSS-NTLMSSP` or the bare spelling. Before the
    // refusal below, because "not offered" is now a decision rather than a fact: it is offered when
    // the configuration says so, and the acceptor's own answer is the one that knows.
    #[cfg(feature = "smb")]
    if let Some(token) = super::sasl_bind::ntlm_token(request) {
        return super::sasl_bind::handle_ntlm(session, directory, message_id, token, security);
    }

    // The Sicily bind, before the version check because it is a *version 2* bind: Microsoft's LDAP
    // client sends the name `NTLM` and an NTLMSSP message where a password would go, and it does so
    // before the machine has any ticket. Measured on the AD-join stand: an `Add-Computer` from a
    // stock Windows Server 2022 opens 389 and sends exactly this, and a server that answered
    // `protocolError: only version 3` left the join at `0x37`.
    //
    // Returned before `session.reset()`: like any multi-round bind, the challenge outstanding on
    // this connection is what the second message is checked against.
    if let Some((round, token)) = Sicily::of(request) {
        let token = token.to_vec();
        return sicily_round(session, directory, message_id, round, &token, security);
    }

    session.reset();

    if request.version != 3 {
        return bind_response(
            message_id,
            ResultCode::ProtocolError,
            &format!("only LDAP version 3 is supported, got {}", request.version),
        );
    }

    let password = match &request.authentication {
        AuthenticationChoice::Simple(password) => {
            String::from_utf8_lossy(password.as_ref()).into_owned()
        }
        // A SASL mechanism this server does not answer is refused by name: a client that gets
        // "not supported" and no mechanism in the message has nothing to fall back to, and the
        // operator cannot tell whether the server is misconfigured or the client is asking for
        // something the deployment never offered.
        AuthenticationChoice::Sasl(credentials) => {
            let mechanism = credentials.mechanism.0.to_string();
            tracing::warn!(
                mechanism = %mechanism,
                offered = ?crate::ldap::sasl_bind::MECHANISMS,
                "bind: a SASL mechanism this server does not answer"
            );
            // NTLM is named apart from the rest because it is not a mechanism this server forgot:
            // it is one it decides not to offer. Checking a password here would be a second
            // implementation beside the one in the SMB session and the one in this directory's own
            // simple bind, and two checks of one password are two chances to disagree. A Samba
            // member reaches Kerberos with `-k` or with a ticket in `KRB5CCNAME`.
            // NTLM is named apart from the rest: reaching this arm means this build has no
            // acceptor for it at all, and the sentence says how to get there rather than leaving a
            // client to guess.
            let message = if is_ntlm(&mechanism) {
                format!(
                    "SASL mechanism {mechanism} is not offered by this build: this server accepts \
                     Kerberos ({}), and NTLM only where the acceptor is compiled in and \
                     `sasl.allow_ntlm` is set. A Samba member joins with `net ads join -k` and a \
                     ticket from `kinit`.",
                    crate::ldap::sasl_bind::MECHANISMS.join(", ")
                )
            } else {
                format!(
                    "SASL mechanism {mechanism} is not supported; this server offers {}",
                    crate::ldap::sasl_bind::MECHANISMS.join(", ")
                )
            };
            return bind_response(message_id, ResultCode::AuthMethodNotSupported, &message);
        }
        other => {
            return bind_response(
                message_id,
                ResultCode::AuthMethodNotSupported,
                &format!("authentication method {other:?} is not supported"),
            );
        }
    };

    /// Whether a mechanism name is one of NTLM's.
    ///
    /// Samba's client uses two spellings depending on which plugin answered: `NTLMSSP` for the bare
    /// mechanism and `GSS-NTLMSSP` for the SPNEGO-wrapped one. Both mean the same thing here, and the
    /// answer to both is the same sentence.
    fn is_ntlm(mechanism: &str) -> bool {
        ["NTLMSSP", "GSS-NTLMSSP"]
            .iter()
            .any(|known| known.eq_ignore_ascii_case(mechanism))
    }

    let bind_dn = dn::normalize(&request.name.0);

    // Anonymous bind: empty name and empty password.
    if bind_dn.is_empty() && password.is_empty() {
        return bind_response(message_id, ResultCode::Success, "");
    }

    if bind_dn.is_empty() {
        return bind_response(
            message_id,
            ResultCode::UnwillingToPerform,
            "unauthenticated bind (empty name with a password) is not allowed",
        );
    }

    // A password sent in the clear is refused before the entry is looked up, so
    // the answer does not reveal whether the account exists.
    if !session.is_encrypted() && !security.allow_unencrypted_bind {
        return bind_response(
            message_id,
            ResultCode::StrongerAuthRequired,
            "simple bind requires transport encryption (LDAPS or StartTLS)",
        );
    }

    if !dn::is_valid(&bind_dn) {
        return bind_response(
            message_id,
            ResultCode::InvalidDnSyntax,
            &format!("wrong dn '{bind_dn}'"),
        );
    }

    // `record`, not `find`: a skeleton snapshot holds the identity and not the values, and this
    // path needs `userPassword`. Same answer, one keyed read when the snapshot was built that way.
    let fetched = directory.record(&bind_dn);
    let entry = match fetched.as_deref() {
        Some(entry) => entry,
        None => {
            return bind_response(
                message_id,
                ResultCode::NoSuchObject,
                &format!("dn '{bind_dn}' not found"),
            );
        }
    };

    // An account is an entry the directory names one: `sAMAccountName`. The rule used to be "under
    // the users organizational unit", which excluded every machine account - they live in the
    // computers container - and a member's own bind as SYSTEM is one of them.
    let named = entry
        .attributes()
        .get("sAMAccountName")
        .and_then(|attribute| attribute.values.first())
        .is_some();
    let carries_password = entry
        .attributes()
        .get("userPassword")
        .and_then(|attribute| attribute.values.first())
        .is_some();
    // The users organizational unit keeps answering `InvalidCredentials` for an entry that holds no
    // password: that entry is an account by position and the client's mistake is the password. Any
    // other entry binds only if it is one the directory names or one that carries a password.
    let under_users =
        bind_dn.ends_with(&format!(",{}", directory.ou_dn(directory.users_ou_name())));
    if !under_users && !named && !carries_password {
        return bind_response(
            message_id,
            ResultCode::NoSuchObject,
            &format!("dn '{bind_dn}' not found"),
        );
    }

    let stored_hash = entry
        .attributes()
        .get("userPassword")
        .and_then(|attribute| attribute.values.first())
        .filter(|hash| !hash.is_empty())
        .cloned();

    let is_admin = entry.is_admin();
    let rights = security.acl.rights(
        &Requester::new(&bind_dn, is_admin),
        directory,
        &bind_dn,
        None,
    );
    if !rights.auth {
        return bind_response(
            message_id,
            ResultCode::InsufficientAccessRights,
            "access rules do not allow this entry to bind",
        );
    }

    // No text password: a machine account, whose password exists only as the keys derived from it -
    // a join writes `unicodePwd` and that write leaves keys and an NT hash behind and nothing to
    // compare text against. Verified by deriving again from the salt the entry carries; measured, a
    // member's LDAP bind as SYSTEM answered `49: Invalid Credentials` for a password both sides
    // agreed on, and the step that needed it then reported the domain unreachable.
    let Some(stored_hash) = stored_hash else {
        #[cfg(feature = "kdc")]
        {
            let realm = security
                .gssapi
                .as_ref()
                .and_then(|gssapi| gssapi.realms().next());
            // An entry with no keys was never given a password: the answer is about the account, not
            // about the password, and the two read differently to whoever is looking at a log.
            if entry
                .attributes()
                .internal(rrl_kdc::hdb::ldap::attrs::KEY)
                .is_none()
                || realm.is_none()
            {
                return bind_response(
                    message_id,
                    ResultCode::InvalidCredentials,
                    "user has no password set",
                );
            }
            let derived = realm.is_some_and(|realm| {
                crate::kerberos::unicode_pwd::verify_password(entry.attributes(), &password, realm)
            });
            return if derived {
                session.set_identity(Identity::new(&bind_dn, is_admin));
                bind_response(message_id, ResultCode::Success, "")
            } else {
                bind_response(message_id, ResultCode::InvalidCredentials, "wrong password")
            };
        }
        #[cfg(not(feature = "kdc"))]
        return bind_response(
            message_id,
            ResultCode::InvalidCredentials,
            "user has no password set",
        );
    };

    match verify(&password, &stored_hash, &security.passwords) {
        Ok(true) => {
            session.set_identity(Identity::new(&bind_dn, is_admin));

            // The password is in hand for the only time: if the stored hash is not in
            // the configured scheme, write the new one now. `needs_rehash` returns
            // false when the operator turned the upgrade off.
            // `can_upgrade_password_hashes` is false when the backend cannot store a whole
            // entry: attempting it anyway refused the write on every single bind and printed a
            // line about it each time, which is noise rather than news.
            if security.can_upgrade_password_hashes && security.passwords.needs_rehash(&stored_hash)
            {
                match crate::password::store::hash(&password, security.passwords.store_scheme()) {
                    Ok(upgraded) => {
                        *upgrade = Some(replace_password(entry, &upgraded));
                    }
                    Err(err) => {
                        // A hash the server cannot compute is a configuration problem,
                        // not a reason to refuse a bind that already succeeded.
                        eprintln!(
                            "{}",
                            crate::i18n::t(
                                "error.password_upgrade",
                                &[("dn", &bind_dn), ("detail", &err.to_string())]
                            )
                        );
                    }
                }
            }

            bind_response(message_id, ResultCode::Success, "")
        }
        Ok(false) => bind_response(message_id, ResultCode::InvalidCredentials, "wrong password"),
        Err(err) => bind_response(
            message_id,
            ResultCode::InvalidCredentials,
            &format!("wrong password for dn '{bind_dn}': {err}"),
        ),
    }
}

/// The entry with `userPassword` replaced, keeping the flags the attribute had.
fn replace_password(entry: &Entry, hash: &str) -> Entry {
    let mut attribute = crate::model::Attribute::single("userPassword", hash);
    if let Some(existing) = entry.attributes().get("userPassword") {
        attribute.flags = existing.flags;
    }

    Entry::new(entry.dn(), entry.attributes().clone().replace(attribute))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Group, User};
    use crate::password::{StoreScheme, hash as hash_password};

    /// Policy for these tests: they exercise authentication, not transport, and
    /// `handle_bind` has no socket to encrypt. The unencrypted bind is switched on
    /// here and nowhere else in the suite, which is the point of the setting.
    fn security() -> Security {
        Security {
            allow_unencrypted_bind: true,
            allow_ntlm: false,
            ..Security::default()
        }
    }

    fn hash(value: &str) -> String {
        hash_password(value, StoreScheme::Argon2id).expect("hash")
    }

    const BASE: &str = "dc=example,dc=com";
    const ADMIN_DN: &str = "cn=admin,ou=users,dc=example,dc=com";
    const ALICE_DN: &str = "cn=alice,ou=users,dc=example,dc=com";

    fn directory() -> Directory {
        let admin = User {
            ldap_admin: true,
            cn: "admin".to_string(),
            uid: Some("admin".to_string()),
            user_password: Some(hash("admin-secret")),
            ..User::default()
        };
        let alice = User {
            cn: "alice".to_string(),
            uid: Some("alice".to_string()),
            user_password: Some(hash("alice-secret")),
            ..User::default()
        };
        let passwordless = User {
            cn: "nopassword".to_string(),
            ..User::default()
        };
        let group = Group {
            cn: "group_a".to_string(),
            ..Group::default()
        };

        Directory::new(
            BASE,
            "users",
            "groups",
            vec![admin, alice, passwordless],
            vec![group],
        )
    }

    fn request(version: u8, name: &str, password: &[u8]) -> BindRequest {
        BindRequest::new(
            version,
            rasn_ldap::LdapDn::from(name),
            AuthenticationChoice::Simple(rasn::types::OctetString::from_slice(password)),
        )
    }

    fn code(message: &rasn_ldap::LdapMessage) -> ResultCode {
        match &message.protocol_op {
            rasn_ldap::ProtocolOp::BindResponse(response) => response.result_code,
            other => panic!("unexpected response: {other:?}"),
        }
    }

    fn diagnostic(message: &rasn_ldap::LdapMessage) -> String {
        match &message.protocol_op {
            rasn_ldap::ProtocolOp::BindResponse(response) => response.diagnostic_message.0.clone(),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn valid_credentials_bind_the_admin() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            1,
            &request(3, ADMIN_DN, b"admin-secret"),
            &security(),
        );

        assert_eq!(code(&response), ResultCode::Success);
        assert_eq!(diagnostic(&response), "");
        let identity = session.identity().expect("identity");
        assert_eq!(identity.dn, ADMIN_DN);
        assert!(identity.admin);
    }

    #[test]
    fn regular_user_binds_without_admin_rights() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            2,
            &request(3, ALICE_DN, b"alice-secret"),
            &security(),
        );

        assert_eq!(code(&response), ResultCode::Success);
        let identity = session.identity().expect("identity");
        assert_eq!(identity.dn, ALICE_DN);
        assert!(!identity.admin);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            3,
            &request(3, ADMIN_DN, b"not-the-password"),
            &security(),
        );

        assert_eq!(code(&response), ResultCode::InvalidCredentials);
        assert_eq!(diagnostic(&response), "wrong password");
        assert!(session.identity().is_none());
    }

    #[test]
    fn unknown_entry_is_reported_as_missing_object() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            4,
            &request(3, "cn=nobody,ou=users,dc=example,dc=com", b"x"),
            &security(),
        );

        assert_eq!(code(&response), ResultCode::NoSuchObject);
        assert_eq!(
            diagnostic(&response),
            "dn 'cn=nobody,ou=users,dc=example,dc=com' not found"
        );
    }

    #[test]
    fn binding_as_a_group_or_the_domain_is_rejected() {
        let directory = directory();
        let mut session = Session::new();

        let group = handle_bind(
            &mut session,
            &directory,
            5,
            &request(3, "cn=group_a,ou=groups,dc=example,dc=com", b"x"),
            &security(),
        );
        let domain = handle_bind(
            &mut session,
            &directory,
            6,
            &request(3, BASE, b"x"),
            &security(),
        );

        assert_eq!(code(&group), ResultCode::NoSuchObject);
        assert_eq!(code(&domain), ResultCode::NoSuchObject);
    }

    #[test]
    fn unsupported_attribute_in_dn_is_rejected() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            7,
            &request(3, "mail=admin@example.com,dc=example,dc=com", b"x"),
            &security(),
        );

        assert_eq!(code(&response), ResultCode::InvalidDnSyntax);
    }

    #[test]
    fn a_sasl_bind_without_a_keytab_says_why() {
        // GSSAPI is implemented, but a server with no keytab cannot accept a ticket, and the
        // answer has to say that rather than the old "method not supported": an operator reading
        // it needs to know the difference between "never implemented" and "not configured here".
        let directory = directory();
        let mut session = Session::new();
        let sasl = BindRequest::new(
            3,
            rasn_ldap::LdapDn::from(ADMIN_DN),
            AuthenticationChoice::Sasl(rasn_ldap::SaslCredentials::new(
                rasn_ldap::LdapString::from("GSSAPI"),
                None,
            )),
        );

        let response = handle_bind(&mut session, &directory, 8, &sasl, &security());

        assert_eq!(code(&response), ResultCode::AuthMethodNotSupported);
        assert!(
            diagnostic(&response).contains("keytab"),
            "{}",
            diagnostic(&response)
        );
    }

    /// `sasl.allow_ntlm`: NTLM is answered only once the configuration says so, and the refusal
    /// names the setting.
    ///
    /// The default is off because NTLM proves a client with a password hash and nothing else - no
    /// ticket, no channel binding - and a server that answers it without being asked accepts a
    /// weaker proof than it advertises. A joining Windows machine always takes this path, and a
    /// member falls back to it whenever the KDC is unreachable, so which answer it gets is the
    /// operator's decision and has to be a visible one.
    /// A NEGOTIATE_MESSAGE, forty octets as MS-NLMP 2.2.1.1 lays it out.
    ///
    /// Only what the acceptor reads: the signature, the type, empty name fields, the flags. The
    /// challenge it produces from this is not what this file checks - that the mechanism is
    /// reachable is - so the fixture is the smallest message the parser accepts.
    #[cfg(feature = "kdc")]
    fn negotiate() -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(b"NTLMSSP\0");
        message.extend_from_slice(&1u32.to_le_bytes());
        message.extend_from_slice(&[0u8; 16]);
        message.extend_from_slice(&0x0008_8207u32.to_le_bytes());
        message.extend_from_slice(&[0u8; 8]);
        message
    }

    #[cfg(all(feature = "kdc", feature = "smb"))]
    // NTLM's keys come from the realm, and the acceptor that answers NTLMSSP lives in the SMB
    // crate: with `kdc` alone the mechanism is refused as not offered, which is what these three
    // tests asserted against and failed. Measured: `cargo test --features kdc --lib` had four
    // failures, and the shipped CI never saw them because it builds `--all-features`.: without `kdc` this build cannot answer an NTLMSSP token,
    // and the test asserts what it does answer. Gated, not skipped inside — a `return` on one
    // branch is unreachable code there, and the CI lints this crate with no features on.
    #[test]
    fn ntlm_is_off_until_the_configuration_turns_it_on() {
        let directory = directory();

        for name in ["GSS-NTLMSSP", "NTLMSSP", "ntlmssp"] {
            let mut session = Session::new();
            let sasl = BindRequest::new(
                3,
                rasn_ldap::LdapDn::from(ADMIN_DN),
                AuthenticationChoice::Sasl(rasn_ldap::SaslCredentials::new(
                    rasn_ldap::LdapString::from(name),
                    None,
                )),
            );

            let response = handle_bind(&mut session, &directory, 10, &sasl, &security());
            let message = diagnostic(&response);

            assert_eq!(
                code(&response),
                ResultCode::AuthMethodNotSupported,
                "{name}: a mechanism the server was not told to answer"
            );
            assert!(
                message.contains("sasl.allow_ntlm"),
                "{name}: the refusal says which setting decides it: {message}"
            );
        }

        // And with the gate open the same bind reaches the acceptor, which answers the first round
        // with a challenge - not with a refusal. That the challenge is the right one is
        // `ntlm_bind`'s question; that the mechanism is reachable at all is this one.
        let mut session = Session::new();
        let sasl = BindRequest::new(
            3,
            rasn_ldap::LdapDn::from(ADMIN_DN),
            AuthenticationChoice::Sasl(rasn_ldap::SaslCredentials::new(
                rasn_ldap::LdapString::from("NTLMSSP"),
                Some(rasn::types::OctetString::from(negotiate())),
            )),
        );
        let allowed = Security {
            allow_ntlm: true,
            ..security()
        };
        let response = handle_bind(&mut session, &directory, 11, &sasl, &allowed);
        let rasn_ldap::ProtocolOp::BindResponse(body) = &response.protocol_op else {
            panic!("expected a bind response");
        };
        assert_ne!(
            body.result_code,
            ResultCode::AuthMethodNotSupported,
            "allowed means answered: {:?}",
            body.diagnostic_message
        );
    }

    #[test]
    fn an_unknown_sasl_mechanism_is_refused_by_name() {
        let directory = directory();
        let mut session = Session::new();
        let sasl = BindRequest::new(
            3,
            rasn_ldap::LdapDn::from(ADMIN_DN),
            AuthenticationChoice::Sasl(rasn_ldap::SaslCredentials::new(
                rasn_ldap::LdapString::from("EXTERNAL"),
                None,
            )),
        );

        let response = handle_bind(&mut session, &directory, 9, &sasl, &security());

        assert_eq!(code(&response), ResultCode::AuthMethodNotSupported);
        assert!(diagnostic(&response).contains("EXTERNAL"));
    }

    #[test]
    fn version_two_is_rejected() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            9,
            &request(2, ADMIN_DN, b"admin-secret"),
            &security(),
        );

        assert_eq!(code(&response), ResultCode::ProtocolError);
        assert_eq!(
            diagnostic(&response),
            "only LDAP version 3 is supported, got 2"
        );
    }

    #[test]
    fn anonymous_bind_succeeds_without_an_identity() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            10,
            &request(3, "", b""),
            &security(),
        );

        assert_eq!(code(&response), ResultCode::Success);
        assert!(session.identity().is_none());
    }

    #[test]
    fn unauthenticated_bind_is_refused() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            11,
            &request(3, "", b"secret"),
            &security(),
        );

        assert_eq!(code(&response), ResultCode::UnwillingToPerform);
        assert_eq!(
            diagnostic(&response),
            "unauthenticated bind (empty name with a password) is not allowed"
        );
    }

    #[test]
    fn user_without_password_cannot_bind() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            12,
            &request(3, "cn=nopassword,ou=users,dc=example,dc=com", b"x"),
            &security(),
        );

        assert_eq!(code(&response), ResultCode::InvalidCredentials);
        assert_eq!(diagnostic(&response), "user has no password set");
    }

    #[test]
    fn failed_bind_drops_the_previous_identity() {
        let directory = directory();
        let mut session = Session::new();
        handle_bind(
            &mut session,
            &directory,
            13,
            &request(3, ADMIN_DN, b"admin-secret"),
            &security(),
        );
        assert!(session.identity().is_some());

        handle_bind(
            &mut session,
            &directory,
            14,
            &request(3, ADMIN_DN, b"wrong"),
            &security(),
        );

        assert!(session.identity().is_none());
    }

    #[test]
    fn bind_by_uid_rdn_also_works() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            15,
            &request(3, "uid=alice,ou=users,dc=example,dc=com", b"alice-secret"),
            &security(),
        );

        assert_eq!(code(&response), ResultCode::Success);
        assert_eq!(
            session.identity().expect("identity").dn,
            "uid=alice,ou=users,dc=example,dc=com"
        );
    }

    #[test]
    fn plaintext_simple_bind_is_refused_when_configured() {
        let directory = directory();
        let mut session = Session::new();
        let security = Security {
            allow_unencrypted_bind: false,
            allow_ntlm: false,
            ..Security::default()
        };

        let response = handle_bind(
            &mut session,
            &directory,
            20,
            &request(3, ADMIN_DN, b"admin-secret"),
            &security,
        );

        assert_eq!(code(&response), ResultCode::StrongerAuthRequired);
        assert_eq!(
            diagnostic(&response),
            "simple bind requires transport encryption (LDAPS or StartTLS)"
        );
        assert!(session.identity().is_none());
    }

    #[test]
    fn encrypted_simple_bind_is_allowed_when_plaintext_is_refused() {
        let directory = directory();
        let mut session = Session::new();
        session.set_encrypted(true);
        let security = Security {
            allow_unencrypted_bind: false,
            allow_ntlm: false,
            ..Security::default()
        };

        let response = handle_bind(
            &mut session,
            &directory,
            21,
            &request(3, ADMIN_DN, b"admin-secret"),
            &security,
        );

        assert_eq!(code(&response), ResultCode::Success);
        assert!(session.identity().is_some());
    }

    #[test]
    fn anonymous_bind_over_plaintext_is_still_allowed() {
        let directory = directory();
        let mut session = Session::new();
        let security = Security {
            allow_unencrypted_bind: false,
            allow_ntlm: false,
            ..Security::default()
        };

        let response = handle_bind(
            &mut session,
            &directory,
            22,
            &request(3, "", b""),
            &security,
        );

        assert_eq!(code(&response), ResultCode::Success);
    }

    #[test]
    fn access_rules_can_refuse_bind_on_an_entry() {
        use crate::acl::{Acl, Rights, Rule, Subject};

        let directory = directory();
        let mut session = Session::new();
        let security = Security {
            acl: Acl::new(vec![Rule {
                subject: Subject::Users,
                base: None,
                attributes: vec![],
                rights: Rights {
                    read: true,
                    ..Rights::none()
                },
            }]),
            allow_unencrypted_bind: true,
            allow_ntlm: false,
            ..Security::default()
        };

        let response = handle_bind(
            &mut session,
            &directory,
            23,
            &request(3, ADMIN_DN, b"admin-secret"),
            &security,
        );

        assert_eq!(code(&response), ResultCode::InsufficientAccessRights);
        assert_eq!(
            diagnostic(&response),
            "access rules do not allow this entry to bind"
        );
    }

    #[test]
    fn bind_dn_case_and_spaces_are_normalized() {
        let directory = directory();
        let mut session = Session::new();

        let response = handle_bind(
            &mut session,
            &directory,
            16,
            &request(3, "CN=Admin, OU=Users, DC=Example, DC=Com", b"admin-secret"),
            &security(),
        );

        assert_eq!(code(&response), ResultCode::Success);
        assert_eq!(session.identity().expect("identity").dn, ADMIN_DN);
    }
}

/// What a Sicily bind asks for, if it is one.
///
/// Microsoft's extension to `AuthenticationChoice`: three context tags RFC 4511 leaves out, used for
/// the legacy NTLM bind a Windows machine sends before it has a ticket (`MS-ADTS`; the shape `ldap3`
/// and `impacket` both speak). The tag names the round, and with no argument the tag alone is the
/// whole message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sicily {
    /// `[9]`: which packages the server offers, answered with their names in `matchedDN`.
    PackageDiscovery,
    /// `[10]`: the client's NTLM NEGOTIATE, answered with the challenge in `matchedDN`.
    Negotiate,
    /// `[11]`: the client's NTLM AUTHENTICATE, answered with `success` or a refusal.
    Response,
}

impl Sicily {
    /// The round this request is, and the token it carried.
    fn of(request: &BindRequest) -> Option<(Self, &[u8])> {
        match &request.authentication {
            AuthenticationChoice::SicilyPackageDiscovery(token) => {
                Some((Self::PackageDiscovery, token.as_ref()))
            }
            AuthenticationChoice::SicilyNegotiate(token) => Some((Self::Negotiate, token.as_ref())),
            AuthenticationChoice::SicilyResponse(token) => Some((Self::Response, token.as_ref())),
            _ => None,
        }
    }
}

/// One round of the Sicily NTLM bind.
///
/// # Where the answer's token goes
///
/// Not in `serverSaslCreds`, which is where a SASL mechanism's half belongs: the Sicily exchange
/// puts the challenge in **`matchedDN`** and reports `success` for the negotiate round, which is
/// what every client of this dialect reads (`ldap3`'s `sicily_bind_response_to_dict` takes
/// `server_creds` from `matchedDN`, and `impacket` does the same). Answering in the SASL field with
/// `saslBindInProgress` is answered by silence: measured on the AD-join stand, the client sent its
/// NEGOTIATE, read a `serverSaslCreds` it was not looking at, and stopped - the join then reported
/// `ERROR_INVALID_LEVEL`, which names neither LDAP nor the bind.
fn sicily_round(
    session: &mut Session,
    directory: &Directory,
    message_id: MessageId,
    round: Sicily,
    token: &[u8],
    security: &Security,
) -> rasn_ldap::LdapMessage {
    // The packages this server can speak. One, and named the way a client compares it: `ldap3`
    // splits the value on `;`, and every Windows dialect spells the package this server checks.
    const PACKAGES: &str = "NTLM";

    // The operator's decision, and answered the same way here as on the SASL path. It comes before
    // the package discovery round on purpose: advertising `NTLM` and then refusing the first token
    // is two answers to one question, and the client reports only the first.
    if !security.allow_ntlm {
        session.reset();
        return bind_response(
            message_id,
            ResultCode::AuthMethodNotSupported,
            "NTLMSSP is not enabled on this server: it proves a client with a password hash and no \
             ticket, so it is off unless the configuration turns it on (sasl.allow_ntlm: true)",
        );
    }

    if round == Sicily::PackageDiscovery {
        return super::responses::bind_response_with_matched_dn(
            message_id,
            ResultCode::Success,
            PACKAGES.as_bytes(),
            "",
        );
    }

    #[cfg(feature = "smb")]
    {
        match super::ntlm_bind::step(session, directory, token, security) {
            Ok(step) => {
                tracing::debug!(
                    round = ?round,
                    code = ?step.code,
                    token = token.len(),
                    "ntlm: sicily round"
                );
                if let Some(identity) = step.identity.clone() {
                    session.set_identity(identity);
                    session.clear_sasl();
                }
                // The layer is installed before the answer is written, because the answer is the
                // first thing it protects: a client that negotiated `SIGN | SEAL` reads a
                // `BindResponse` in the clear as a bind that failed, and reports `53 Unwilling To
                // Perform` from its own security package while this server has answered `success`.
                if let Some((flags, key)) = step.ntlm {
                    session.install_ntlm_layer(flags, &key);
                }
                // Both rounds answer `success`: this dialect reports the outcome of the *bind*, and
                // the state of the NTLM conversation is carried by the token in `matchedDN`.
                match &step.credentials {
                    Some(credentials) => super::responses::bind_response_with_matched_dn(
                        message_id,
                        ResultCode::Success,
                        credentials,
                        &step.diagnostic,
                    ),
                    None => bind_response(message_id, ResultCode::Success, &step.diagnostic),
                }
            }
            Err(err) => {
                // RFC 4513: a failed bind leaves the connection anonymous, and a half-finished NTLM
                // exchange must not be resumable into an authenticated one.
                session.reset();
                bind_response(message_id, ResultCode::InvalidCredentials, &err.to_string())
            }
        }
    }
    #[cfg(not(feature = "smb"))]
    {
        let _ = (session, directory, token, security, round);
        bind_response(
            message_id,
            ResultCode::AuthMethodNotSupported,
            "this server was built without the SMB acceptor, so it cannot check an NTLM token: \
             a Windows machine joins it only with a Kerberos ticket",
        )
    }
}
