//! Creating a machine account, as `samr_CreateUser2` asks for one.
//!
//! `Add-Computer` creates the computer object over RPC and not over LDAP, and it does it **before**
//! it has a ticket - the domain it is joining has not issued it one - so the call arrives on a pipe
//! authenticated by NTLM, naming a machine the directory does not hold yet. A server that refuses it
//! leaves the join at `0x32` with every earlier answer already correct: DNS, LDAP, the NTLM bind, the
//! domain SID, `samr_EnumerateDomains`, `samr_OpenDomain`, `samr_LookupDomain`.
//!
//! The object this writes is the one AD would: `top, person, organizationalPerson, user, computer`
//! under `CN=Computers`, its SID taken from the domain's allocator - not derived from the name, which
//! would hand two machines the same rights - and the flags of a workstation trust account.

use std::sync::Arc;

// The trait only exists when the SMB layer is built: a realm without port 445 has no `samr` to answer.
#[cfg(feature = "smb")]
use smb_server::MachineAccounts;

/// `UF_WORKSTATION_TRUST_ACCOUNT`: an account that belongs to a machine and may join a domain.
const WORKSTATION_TRUST_ACCOUNT: u32 = 0x1000;
/// `DOMAIN_GROUP_RID_COMPUTERS`, the group a joined machine belongs to by default.
const DOMAIN_COMPUTERS_RID: u32 = 515;

/// The directory, as `samr` creates accounts in it.
pub struct DirectoryAccounts {
    /// The source that persists a change and publishes it to readers.
    source: Arc<crate::reload::Source>,
    /// The domain's identity and the counter its RIDs come from.
    issuer: Arc<crate::sid::domain::Issuer>,
    /// The naming context: the computers container sits under it.
    base_dn: String,
    /// The domain's DNS name, for the `dNSHostName` a member reads back to find itself.
    dns_domain: Option<String>,
}

impl std::fmt::Debug for DirectoryAccounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryAccounts").finish_non_exhaustive()
    }
}

impl DirectoryAccounts {
    pub fn new(
        source: Arc<crate::reload::Source>,
        issuer: Arc<crate::sid::domain::Issuer>,
        base_dn: String,
        dns_domain: Option<String>,
    ) -> Self {
        Self {
            source,
            issuer,
            base_dn,
            dns_domain,
        }
    }

    /// The account's short name: the wire carries `DOCKERW-1$`, the directory names the object
    /// `cn=DOCKERW-1`.
    fn short_name(account: &str) -> &str {
        account.strip_suffix('$').unwrap_or(account)
    }

    /// A SID as the directory stores it: the wire's bytes, in base64.
    fn encode_sid(sid: &crate::sid::Sid) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(sid.to_bytes())
    }
}

#[cfg(feature = "smb")]
#[async_trait::async_trait]
impl MachineAccounts for DirectoryAccounts {
    async fn create_machine(&self, account: &str) -> Option<u32> {
        if account.is_empty() {
            tracing::warn!("samr: a machine account with no name");
            return None;
        }
        let short = Self::short_name(account);
        let dn = format!("cn={},{},{}", short, "cn=computers", self.base_dn);

        // An account that already exists is not created twice: the second object would carry a
        // second SID, and a member that joined with the first would have rights under neither.
        if let Some(existing) = self.existing(account).await {
            tracing::info!(
                account,
                dn = existing.dn(),
                "samr: the machine account already exists, and its SID is handed back"
            );
            return crate::sid::Sid::from_bytes(&{
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(
                        existing
                            .attributes()
                            .get("objectSid")?
                            .values
                            .first()?
                            .trim(),
                    )
                    .ok()?
            })
            .ok()
            .and_then(|sid| rid_of(&sid));
        }

        // The SID is taken from the domain's own counter, and the counter moves before the entry is
        // written: a crash in between skips a number, which nobody can tell from one never used.
        let sid = match self.issuer.take() {
            Ok(sid) => sid,
            Err(err) => {
                tracing::warn!(account, %err, "samr: the domain could not issue a RID");
                return None;
            }
        };
        let Some(rid) = rid_of(&sid) else {
            tracing::warn!(account, "samr: the issued SID has no RID in it");
            return None;
        };

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
            .push(crate::model::Attribute::single("cn", short))
            .push(crate::model::Attribute::single("sAMAccountName", account))
            .push(crate::model::Attribute::single(
                "userAccountControl",
                &WORKSTATION_TRUST_ACCOUNT.to_string(),
            ))
            .push(crate::model::Attribute::single(
                "primaryGroupID",
                &DOMAIN_COMPUTERS_RID.to_string(),
            ))
            // Marked binary: `objectSid`'s syntax is a SID, so its value leaves as octets. Without
            // the flag the store's base64 text goes on the wire and a client that parses it as a
            // SID fails - measured, a Windows join's `ConvertSidToStringSid` on the account it had
            // just created.
            .push(crate::model::Attribute::single("objectSid", &Self::encode_sid(&sid)).binary());

        if let Some(domain) = self.dns_domain.as_deref() {
            // The four names `net ads join` derives from a machine's own name. A member searches for
            // `dNSHostName` to find itself, and the KDC needs the SPNs to answer a service ticket
            // for it: an account without them exists, and nothing can be requested for it.
            attributes = attributes
                .push(crate::model::Attribute::single(
                    "dNSHostName",
                    &format!("{short}.{domain}"),
                ))
                .push(crate::model::Attribute::new(
                    "servicePrincipalName",
                    vec![
                        format!("HOST/{short}"),
                        format!("HOST/{short}.{domain}"),
                        format!("RestrictedKrbHost/{short}"),
                        format!("RestrictedKrbHost/{short}.{domain}"),
                    ],
                ));
        }

        let entry = crate::model::Entry::new(&dn, attributes);
        match self
            .source
            .apply(&[crate::backend::EntryChange::Upsert { entry }])
            .await
        {
            Ok(_) => {
                tracing::info!(account, dn, rid, "samr: machine account created");
                Some(rid)
            }
            Err(err) => {
                tracing::warn!(account, dn, %err, "samr: the store refused the account");
                None
            }
        }
    }

    /// The flags the directory holds for `account`, which `samr_QueryInformationUser` reports back.
    ///
    /// Read from the entry and not remembered in this type: the flags are the directory's, and a
    /// join acts on the answer - it enables an account it finds disabled - so a value invented here
    /// would be a disagreement with the directory that nothing would ever correct.
    async fn machine_control(&self, account: &str) -> Option<u32> {
        let entry = self.existing(account).await?;
        entry
            .attributes()
            .get("userAccountControl")?
            .values
            .first()?
            .trim()
            .parse()
            .ok()
    }

    /// Removes the machine account `account` from the directory.
    ///
    /// The counterpart of `create_machine`, called by `samr_DeleteUser` when a join undoes the
    /// account it made. Only an account with a machine's own SID is removed: a delete that took any
    /// entry by name would let a client remove a person by mistyping a handle.
    async fn delete_machine(&self, account: &str) -> bool {
        let Some(entry) = self.existing(account).await else {
            tracing::info!(account, "samr: DeleteUser for an account that is not there");
            return false;
        };
        let dn = entry.dn().to_string();
        // `computer` or `user` with a machine SID: what `create_machine` writes, and what a join
        // made over LDAP writes too. Anything else that happens to carry the name is left alone.
        let machine = entry
            .attributes()
            .get(crate::model::ATTR_OBJECT_CLASS)
            .is_some_and(|classes| {
                classes.values.iter().any(|class| {
                    ["computer", "user"]
                        .iter()
                        .any(|known| class.eq_ignore_ascii_case(known))
                })
            })
            && entry.attributes().get("objectSid").is_some();
        if !machine {
            tracing::warn!(
                account,
                dn,
                "samr: DeleteUser for an entry that is not a machine account"
            );
            return false;
        }

        match self
            .source
            .apply(&[crate::backend::EntryChange::delete(dn.clone(), None)])
            .await
        {
            Ok(_) => {
                tracing::info!(account, dn, "samr: machine account removed");
                true
            }
            Err(err) => {
                tracing::warn!(account, dn, %err, "samr: the machine account could not be removed");
                false
            }
        }
    }

    async fn account_of_rid(&self, rid: u32) -> Option<String> {
        let directory = self.source.directory().await;
        // Matched on the SID rather than on the DN: a machine account may sit in any container, and
        // its RID is the only thing the wire named. Read through `record`, not through the snapshot:
        // `all()` holds skeletons for everything that existed when this process started, so a scan
        // over it sees no `objectSid` at all and answers "no such user" for an account that is there.
        let mut found = None;
        for identity in directory.all() {
            let Some(record) = directory.record(identity.dn()) else {
                continue;
            };
            let entry_rid = record
                .attributes()
                .get("objectSid")
                .and_then(|attribute| attribute.values.first())
                .and_then(|value| {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD
                        .decode(value.trim())
                        .ok()
                })
                .and_then(|bytes| crate::sid::Sid::from_bytes(&bytes).ok())
                .and_then(|sid| rid_of(&sid));
            if entry_rid == Some(rid) {
                found = Some(record.into_owned());
                break;
            }
        }
        let found = found?;
        let name = found
            .attributes()
            .get("sAMAccountName")?
            .values
            .first()?
            .clone();
        tracing::debug!(rid, account = %name, dn = found.dn(), "samr: a RID resolved to an account");
        Some(name)
    }
}

impl DirectoryAccounts {
    /// The entry an account with this name already holds, if any.
    async fn existing(&self, account: &str) -> Option<crate::model::Entry> {
        let directory = self.source.directory().await;
        // Through `record`, for the reason `account_of_rid` records: the snapshot's entries are
        // skeletons, and a machine account that existed when this process started is one of them.
        for identity in directory.all() {
            let Some(record) = directory.record(identity.dn()) else {
                continue;
            };
            let named = record
                .attributes()
                .get("sAMAccountName")
                .is_some_and(|attribute| {
                    attribute
                        .values
                        .iter()
                        .any(|value| value.eq_ignore_ascii_case(account))
                });
            if named {
                return Some(record.into_owned());
            }
        }
        None
    }
}

/// The RID of a SID: its last sub-authority.
fn rid_of(sid: &crate::sid::Sid) -> Option<u32> {
    let bytes = sid.to_bytes();
    let count = *bytes.get(1)? as usize;
    if count == 0 {
        return None;
    }
    let end = 8 + count * 4;
    bytes
        .get(end - 4..end)
        .and_then(|last| <[u8; 4]>::try_from(last).ok())
        .map(u32::from_le_bytes)
}
