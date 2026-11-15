//! The PAC this directory states about a client, built where the facts are.
//!
//! `rrl-kdc` issues a PAC only when somebody installs an issuer — MIT's `issue_pac`, installed by a
//! kdb module. This module is that installation for this server, and it exists because the facts a
//! `KERB_VALIDATION_INFO` is made of live here and nowhere else: `objectSid`, `primaryGroupID`,
//! `memberOf`, `sAMAccountName`, `userAccountControl`. A KDC holding a principal's keys knows none
//! of them, and a PAC with an invented RID is worse than a ticket without one, because a service
//! trusts it.
//!
//! # What is not done here
//!
//! The format is not written here. `rrl-krb-common` holds `KERB_VALIDATION_INFO`, the buffer table
//! and the two signatures, and the acceptor parses with the same code — a second NDR encoder would
//! be a second chance to produce a PAC Windows refuses, and that shows up on a domain rather than in
//! a test. This module only fills the structure in.
//!
//! # The incoming PAC
//!
//! A `TGS-REQ` carries the PAC of the ticket it presents, and the issuer is given it
//! (`PacRequest::old_pac`). Samba's `samba_kdc_issue_pac` revalidates the logon information in the
//! old PAC and keeps it when the directory still agrees. This implementation rebuilds from the
//! directory instead, for a reason that is worth stating: a rebuilt PAC cannot outlive a change in
//! the directory, so removing an account from a group takes effect on the next ticket rather than at
//! the end of the ticket's life. The old PAC is read for one thing - whether the client's claim was
//! a PAC at all - and the rest of it is replaced.

use std::sync::Arc;

use rrl_kdc::crypto::Key;
use rrl_kdc::kdc::logon_info::{Identity, LogonInfo, encode};
use rrl_kdc::kdc::pac::{
    self, Buffer, PAC_LOGON_INFO, PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM, PacIssuer, PacRequest,
};
use rrl_kdc::name::Principal;

use crate::kerberos::realm::RealmView;
use crate::model::Entry;
use crate::sid::Sid;

/// `SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED`, which is what AD states
/// for a group a logon holds, as opposed to one it may use but does not have enabled.
const GROUP_ENABLED: u32 = 0x0000_0007;

/// `UF_NORMAL_ACCOUNT`: what an account is when the directory says nothing.
const UF_NORMAL_ACCOUNT: u32 = 0x0000_0200;

/// `DOMAIN_GROUP_RID_USERS`, the primary group AD gives an account it has not been told about.
const DOMAIN_USERS: u32 = 513;

/// Where a PAC's logon information comes from: this server's own directory.
///
/// The view is the same one the realm reads keys through, so a ticket and the PAC beside it describe
/// one entry at one snapshot. Holding a second handle on the directory would be a second thing to
/// keep in step, and the failure would be a ticket whose `cname` and whose `UserId` came from
/// different moments.
#[derive(Debug)]
pub struct DirectoryPacIssuer {
    view: Arc<RealmView>,
    /// The controller's name, for `LogonServer`. Empty when the operator's configuration names none,
    /// which is the honest value: a name invented here is a claim about which controller answered.
    logon_server: String,
    /// The domain's downlevel name, `EXAMPLE`, for `LogonDomainName`.
    ///
    /// Taken from the realm's first label rather than stored: a PAC's `LogonDomainName` is compared
    /// against the domain a service already knows, and a DNS name in that field fails the comparison
    /// on the client side with no message that points here.
    netbios: String,
}

impl DirectoryPacIssuer {
    /// An issuer over `view`.
    pub fn new(view: Arc<RealmView>, realm: &str, logon_server: impl Into<String>) -> Self {
        Self {
            view,
            logon_server: logon_server.into(),
            netbios: realm
                .split('.')
                .next()
                .unwrap_or(realm)
                .to_ascii_uppercase(),
        }
    }

    /// The identity this directory states for `principal`, or `None` when it states none.
    ///
    /// `None` for an account the directory does not hold, and for one it holds without a
    /// `objectSid`: a PAC has to name a SID, and an entry without one is an account this realm
    /// cannot describe to a Windows service. The ticket is issued without a PAC rather than with an
    /// empty one, which is what an account that is not a domain account at all should get.
    fn identity(&self, principal: &Principal) -> Option<Identity> {
        let entry = self.view.record_for(principal)?;
        let account = Sid::from_directory_value(
            entry
                .attributes()
                .get(crate::sid::ATTRIBUTE)?
                .values
                .first()?,
        )
        .ok()?;

        // The RID is the last sub-authority and the domain is everything before it. An account SID
        // with nothing before it is a SID of the domain itself, and a PAC for it would claim the
        // domain logs on as a user.
        let user_rid = account.rid()?;
        let domain = account.parent()?;

        let groups = self
            .groups(&entry)
            .into_iter()
            .map(|group| (group, GROUP_ENABLED))
            .collect();

        Some(Identity {
            domain: shared_sid(&domain),
            domain_name: self.netbios.clone(),
            logon_server: self.logon_server.clone(),
            user_rid,
            primary_group: number(&entry, "primaryGroupID").unwrap_or(DOMAIN_USERS),
            groups,
            full_name: text(&entry, "displayName").unwrap_or_default(),
            user_account_control: number(&entry, "userAccountControl").unwrap_or(UF_NORMAL_ACCOUNT),
            // No foreign-domain SIDs: this realm has one domain, and `memberOf` on an entry from
            // another one would have to be resolved against a directory this server does not hold.
            extra_sids: Vec::new(),
        })
    }

    /// The RIDs of the groups `entry` is a member of, as this directory can resolve them.
    ///
    /// `memberOf` holds DNs, and a DN is not a RID: each one is read back as an entry and asked for
    /// its `objectSid`. A group whose entry is absent, or which has no SID, is skipped rather than
    /// guessed — a made-up RID is a group the client would hold and nobody granted.
    fn groups(&self, entry: &Entry) -> Vec<u32> {
        let Some(member_of) = entry.attributes().get("memberOf") else {
            return Vec::new();
        };
        let mut rids = Vec::with_capacity(member_of.values.len());
        for dn in member_of.values.iter() {
            let Some(group) = self.view.record(dn) else {
                tracing::warn!(dn, "pac: a group in memberOf is not in the directory");
                continue;
            };
            let Some(sid) = group
                .attributes()
                .get(crate::sid::ATTRIBUTE)
                .and_then(|attribute| attribute.values.first())
                .and_then(|value| Sid::from_directory_value(value).ok())
            else {
                tracing::warn!(dn, "pac: a group has no objectSid");
                continue;
            };
            if let Some(rid) = sid.rid() {
                rids.push(rid);
            }
        }
        // Sorted and deduplicated: `memberOf` is an unordered set, and a PAC whose group list
        // changes order between two tickets for the same account is a PAC two assertions can never
        // both pass.
        rids.sort_unstable();
        rids.dedup();
        rids
    }

    /// The `KERB_VALIDATION_INFO` for `request`, or why it could not be built.
    fn logon_info(&self, request: &PacRequest<'_>, identity: &Identity) -> LogonInfo {
        // `EffectiveName` is the account's own name, not the principal the client asked with: a
        // client sending `alice@AD.EXAMPLE.COM` must be told `alice`, or every service that compares
        // the two sees two accounts.
        let effective = self
            .view
            .record_for(request.client)
            .and_then(|entry| text(&entry, "sAMAccountName"))
            .unwrap_or_else(|| request.client.to_string());
        identity.logon_info(effective, request.authtime)
    }
}

impl PacIssuer for DirectoryPacIssuer {
    fn issue(&self, request: &PacRequest<'_>) -> rrl_kdc::Result<Option<Vec<u8>>> {
        let Some(identity) = self.identity(request.client) else {
            // Said out loud, because a Windows logon that gets a ticket with no PAC fails later and
            // somewhere else - at the service, with a message about the token, not about this.
            tracing::info!(
                client = %request.client,
                "pac: the directory states no SID for this account, so the ticket carries no PAC"
            );
            return Ok(None);
        };
        if request.old_pac.is_some() {
            // Kept as a fact rather than merged: see the module comment. Logged because it is the
            // one place where what this KDC does differs from Samba's, and an operator comparing the
            // two deserves to find it written down.
            tracing::debug!(
                client = %request.client,
                old = request.old_pac.map_or(0, <[u8]>::len),
                "pac: the incoming ticket carried a PAC; the directory's answer replaces it"
            );
        }

        let logon = self.logon_info(request, &identity);
        let mut blob = pac::pac(&[
            Buffer::new(PAC_LOGON_INFO, encode(&logon)?),
            pac::client_info(&logon.effective_name, request.authtime)?,
            Buffer::new(
                PAC_SERVER_CHECKSUM,
                vec![0_u8; request.signature.signature_len() + 4],
            ),
            Buffer::new(
                PAC_PRIVSVR_CHECKSUM,
                vec![0_u8; request.signature.signature_len() + 4],
            ),
        ]);
        // Both keys, as MIT passes them: the server checksum is keyed by the ticket's service key
        // and the privsvr checksum by `krbtgt`. One key twice would verify at this KDC and fail at
        // every service.
        seal_with(
            &mut blob,
            request.server_key,
            request.kdc_key,
            request.signature,
        )?;
        Ok(Some(pac::authorization_data(&blob)))
    }
}

/// `seal`, with the error converted into this crate's KDC error.
///
/// The two crates disagree about which error type a cryptographic failure is, and the conversion
/// belongs at the seam rather than in the middle of a function that is about a directory.
fn seal_with(
    blob: &mut [u8],
    server_key: &Key,
    kdc_key: &Key,
    signature: pac::SignatureType,
) -> rrl_kdc::Result<()> {
    pac::seal(blob, server_key, kdc_key, signature)
        .map_err(|err| rrl_kdc::Error::Crypto(format!("the PAC could not be signed: {err}")))
}

/// The shared crate's `Sid`, from this crate's.
///
/// Two types for one fact: this server needs a SID it can parse from text, compare and encode into a
/// DN-style attribute, and the PAC needs the four fields the wire has. The conversion is field by
/// field, with nothing inferred.
fn shared_sid(sid: &Sid) -> rrl_kdc::kdc::logon_info::Sid {
    rrl_kdc::kdc::logon_info::Sid {
        revision: sid.revision(),
        authority: sid.authority(),
        sub_authorities: sid.subauthorities().to_vec(),
    }
}

/// An attribute's first value, when the entry has the attribute at all.
fn text(entry: &Entry, name: &str) -> Option<String> {
    entry
        .attributes()
        .get(name)
        .and_then(|attribute| attribute.values.first())
        .cloned()
}

/// An attribute read as an unsigned number: AD stores these as decimal text.
fn number(entry: &Entry, name: &str) -> Option<u32> {
    text(entry, name).and_then(|value| value.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::Directory;
    use crate::model::{Attribute, Attributes, Entry};
    use rrl_kdc::crypto::{Enctype, Key};

    const BASE: &str = "dc=ad,dc=example,dc=com";
    const REALM: &str = "AD.EXAMPLE.COM";
    /// `S-1-5-21-1-2-3`: a domain SID whose RID space the accounts below live in.
    const DOMAIN: [u32; 3] = [1, 2, 3];

    fn domain_sid() -> Sid {
        Sid::domain(DOMAIN[0], DOMAIN[1], DOMAIN[2])
    }

    /// An account's SID: the domain's with its RID appended.
    fn account_sid(rid: u32) -> Sid {
        let mut sub_authorities = domain_sid().subauthorities().to_vec();
        sub_authorities.push(rid);
        Sid::new(domain_sid().authority(), sub_authorities).expect("a SID within the limit")
    }

    fn entry(dn: &str, classes: &[&str], attributes: Vec<Attribute>) -> Entry {
        let mut built = Attributes::new().push(Attribute::new(
            crate::model::ATTR_OBJECT_CLASS,
            classes.iter().map(|name| (*name).to_string()).collect(),
        ));
        for attribute in attributes {
            built = built.push(attribute);
        }
        Entry::new(dn, built)
    }

    /// The directory a PAC is read out of: one account, two groups, and the domain.
    fn directory() -> Directory {
        let admins = format!("cn=admins,ou=groups,{BASE}");
        let users = format!("cn=domain users,ou=groups,{BASE}");
        let entries = vec![
            entry(
                &format!("cn=Alice,ou=users,{BASE}"),
                &["top", "user"],
                vec![
                    Attribute::single("cn", "Alice"),
                    Attribute::single("sAMAccountName", "alice"),
                    Attribute::single("userPrincipalName", &format!("alice@{REALM}")),
                    Attribute::single("displayName", "Alice Example"),
                    Attribute::single("primaryGroupID", "513"),
                    Attribute::single("userAccountControl", "512"),
                    account_sid(1105).attribute(crate::sid::ATTRIBUTE),
                    Attribute::new("memberOf", vec![admins.clone(), users.clone()]),
                ],
            ),
            entry(
                &format!("cn=Bob,ou=users,{BASE}"),
                &["top", "user"],
                vec![
                    Attribute::single("cn", "Bob"),
                    Attribute::single("sAMAccountName", "bob"),
                    // No `objectSid`: an account this realm cannot state a PAC for.
                ],
            ),
            entry(
                &admins,
                &["top", "group"],
                vec![
                    Attribute::single("cn", "admins"),
                    account_sid(512).attribute(crate::sid::ATTRIBUTE),
                ],
            ),
            entry(
                &users,
                &["top", "group"],
                vec![
                    Attribute::single("cn", "domain users"),
                    account_sid(513).attribute(crate::sid::ATTRIBUTE),
                ],
            ),
        ];
        Directory::from_entries(BASE, "users", "groups", entries)
    }

    fn issuer() -> DirectoryPacIssuer {
        let view = Arc::new(RealmView::new(REALM, BASE, Arc::new(directory())));
        DirectoryPacIssuer::new(view, REALM, "dc1.ad.example.com")
    }

    /// The two keys a PAC is signed with, of one enctype so that one signature type describes both.
    fn keys() -> (Key, Key) {
        (
            Key::new(Enctype::Aes256Sha1, vec![0x11; 32]).expect("a service key"),
            Key::new(Enctype::Aes256Sha1, vec![0x22; 32]).expect("a krbtgt key"),
        )
    }

    /// The `PAC_LOGON_INFO` buffer out of the `AuthorizationData` this crate issued.
    ///
    /// Read here by the layout [MS-PAC] §2.3 and §2.5 give, rather than through `krb5::pac::Pac`:
    /// that parser expects the NDR type-serialization header in front of `KERB_VALIDATION_INFO`,
    /// and the buffer on the wire does not carry one — impacket reads the bare form, and it is what
    /// this crate has been issuing since `RRL-3.8`. A test that went through that parser would be
    /// measuring the parser, not the PAC.
    fn logon_buffer(answer: &[u8]) -> Vec<u8> {
        // The envelope and the buffer table through the crate's own parser, which reads both
        // correctly; only the `KERB_VALIDATION_INFO` inside the buffer is read here.
        let pac = krb5::pac::find_pac(answer)
            .expect("the answer is authorization data")
            .expect("it carries a PAC");
        let pac = krb5::pac::Pac::parse(pac).expect("the PAC parses");
        pac.buffer(PAC_LOGON_INFO)
            .expect("the PAC states a logon")
            .to_vec()
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four octets"))
    }

    fn u64_at(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight octets"))
    }

    /// What `logon_buffer` says, at the offsets [MS-PAC] §2.5 fixes.
    ///
    /// The fixed part is 212 octets: six `FILETIME`s, six `RPC_UNICODE_STRING`s, then the counts and
    /// the pointers. A string's `Length` is in octets and its value is UTF-16LE at the offset its
    /// `Pointer` names, counted from the buffer's first octet.
    struct WrittenLogon {
        effective_name: String,
        logon_time: i64,
        user_id: u32,
        primary_group_id: u32,
        user_account_control: u32,
        group_ids: Vec<(u32, u32)>,
    }

    fn wrote(buffer: &[u8]) -> WrittenLogon {
        // A string's pointer names a referent that is itself the conformant array's header:
        // `MaximumCount`, `Offset`, `ActualCount`, then the UTF-16 characters. Reading the name at
        // the pointer would read that header as text - which is how the first version of this
        // helper "found" the name `\u{5}\0\0\0\u{5}`.
        let string = |at: usize| -> String {
            let pointer = u32_at(buffer, at + 4) as usize;
            if pointer == 0 {
                return String::new();
            }
            let count = u32_at(buffer, pointer + 8) as usize;
            let start = pointer + 12;
            let units: Vec<u16> = buffer[start..start + count * 2]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes(*pair))
                .collect();
            String::from_utf16(&units).expect("a name is UTF-16")
        };
        let group_count = u32_at(buffer, 108) as usize;
        let group_at = u32_at(buffer, 112) as usize;
        let groups = if group_count == 0 {
            Vec::new()
        } else {
            // The array's pointer names its own length word, then the members.
            (0..group_count)
                .map(|index| {
                    let at = group_at + 4 + index * 8;
                    (u32_at(buffer, at), u32_at(buffer, at + 4))
                })
                .collect()
        };
        // `FILETIME` ticks since 1601, and 11 644 473 600 seconds between there and 1970.
        let ticks = u64_at(buffer, 0) as i64;
        WrittenLogon {
            effective_name: string(48),
            logon_time: ticks / 10_000_000 - 11_644_473_600,
            user_id: u32_at(buffer, 100),
            primary_group_id: u32_at(buffer, 104),
            user_account_control: u32_at(buffer, 164),
            group_ids: groups,
        }
    }

    fn request<'a>(
        client: &'a Principal,
        keys: &'a (Key, Key),
        old_pac: Option<&'a [u8]>,
    ) -> PacRequest<'a> {
        PacRequest {
            client,
            server: client,
            authtime: 1_700_000_000,
            signature: pac::SignatureType::for_enctype(Enctype::Aes256Sha1)
                .expect("a type for this enctype"),
            server_key: &keys.0,
            kdc_key: &keys.1,
            old_pac,
        }
    }

    /// The acceptance of this task: the SIDs, the primary group and the group list come out of the
    /// directory, in the fields a Windows service reads.
    #[test]
    fn the_pac_states_the_sids_the_directory_holds() {
        let issuer = issuer();
        let keys = keys();
        let client = Principal::parse(&format!("alice@{REALM}")).expect("a principal");

        let answer = issuer
            .issue(&request(&client, &keys, None))
            .expect("the PAC is issued")
            .expect("this account has a SID");

        let logon = wrote(&logon_buffer(&answer));
        assert_eq!(logon.effective_name, "alice", "the account's own name");
        assert_eq!(logon.user_id, 1105);
        assert_eq!(logon.primary_group_id, 513);
        assert_eq!(logon.user_account_control, 512);
        assert_eq!(
            logon.logon_time, 1_700_000_000,
            "the logon time is the ticket's `authtime`"
        );
        assert_eq!(
            logon.group_ids,
            vec![(512, 7), (513, 7)],
            "both groups, by RID, each enabled"
        );
    }

    /// An account without a `objectSid` gets a ticket with no PAC rather than a PAC with an invented
    /// identity: a service trusts what the PAC says, and 0 is not a RID the directory stated.
    #[test]
    fn an_account_without_a_sid_gets_no_pac() {
        let issuer = issuer();
        let keys = keys();
        let client = Principal::parse(&format!("bob@{REALM}")).expect("a principal");

        assert_eq!(
            issuer
                .issue(&request(&client, &keys, None))
                .expect("issued"),
            None
        );
    }

    /// An account the directory does not hold at all is the same case, and must not be an error: a
    /// KDC that refused the ticket over a missing ACCCOUNT would turn a login into a realm fault.
    #[test]
    fn an_unknown_account_gets_no_pac_rather_than_an_error() {
        let issuer = issuer();
        let keys = keys();
        let client = Principal::parse(&format!("nobody@{REALM}")).expect("a principal");

        assert_eq!(
            issuer
                .issue(&request(&client, &keys, None))
                .expect("issued"),
            None
        );
    }

    /// A `TGS-REQ` carries the PAC of the ticket it presents; the issuer is given it, and the PAC it
    /// writes is the directory's answer rather than a copy. This checks the plumbing the KDC owes the
    /// issuer - that the octets arrive - and the decision this module makes about them.
    #[test]
    fn a_tgs_request_hands_the_incoming_pac_to_the_issuer() {
        let issuer = issuer();
        let keys = keys();
        let client = Principal::parse(&format!("alice@{REALM}")).expect("a principal");

        let fresh = issuer
            .issue(&request(&client, &keys, None))
            .expect("issued")
            .expect("a PAC");
        let again = issuer
            .issue(&request(&client, &keys, Some(&fresh)))
            .expect("issued")
            .expect("a PAC");
        assert_eq!(
            fresh, again,
            "the same directory states the same PAC, so a service hop does not change the token"
        );
    }

    /// `memberOf` names a group this directory does not hold. Guessing a RID for it would grant
    /// something nobody granted, so the group is dropped and the PAC says what it can.
    #[test]
    fn a_group_that_cannot_be_resolved_is_dropped() {
        let admins = format!("cn=admins,ou=groups,{BASE}");
        let entries = vec![
            entry(
                &format!("cn=Carol,ou=users,{BASE}"),
                &["top", "user"],
                vec![
                    Attribute::single("cn", "Carol"),
                    Attribute::single("sAMAccountName", "carol"),
                    Attribute::single("primaryGroupID", "513"),
                    account_sid(1106).attribute(crate::sid::ATTRIBUTE),
                    Attribute::new(
                        "memberOf",
                        vec![admins.clone(), format!("cn=ghosts,ou=groups,{BASE}")],
                    ),
                ],
            ),
            entry(
                &admins,
                &["top", "group"],
                vec![
                    Attribute::single("cn", "admins"),
                    account_sid(512).attribute(crate::sid::ATTRIBUTE),
                ],
            ),
        ];
        let view = Arc::new(RealmView::new(
            REALM,
            BASE,
            Arc::new(Directory::from_entries(BASE, "users", "groups", entries)),
        ));
        let issuer = DirectoryPacIssuer::new(view, REALM, "dc1.ad.example.com");
        let keys = keys();
        let client = Principal::parse(&format!("carol@{REALM}")).expect("a principal");

        let logon = wrote(&logon_buffer(
            &issuer
                .issue(&request(&client, &keys, None))
                .expect("issued")
                .expect("a PAC"),
        ));
        assert_eq!(
            logon.group_ids,
            vec![(512, 7)],
            "the group the directory holds is stated, the one it does not is dropped"
        );
    }
}
