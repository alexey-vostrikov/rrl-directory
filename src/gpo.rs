//! The group policy objects a domain has before anybody creates one.
//!
//! A GPO is two halves that must agree: a `groupPolicyContainer` in the directory, which is the
//! half a client reads first, and a template of files under `Policies\{GUID}` on the policy share,
//! which is the half it reads second. This module writes the first; the share is the other task.
//!
//! # Why the two default policies and not an empty container
//!
//! Every domain made by Windows or by Samba has exactly two before an administrator does anything:
//!
//! ```text
//! {31B2F340-016D-11D2-945F-00C04FB984F9}  Default Domain Policy
//! {6AC1786C-016F-11D2-945F-00C04FB984F9}  Default Domain Controllers Policy
//! ```
//!
//! and `gpresult`, `GPMC` and `Get-GPO` all expect to find them. A domain without them is one where
//! `gpresult /r` answers nothing and an administrator concludes the controller is unmanaged rather
//! than that the policies were never made. The GUIDs are not chosen here: they are the pair MS-GPOD
//! and Samba's `provision` both use, so a client that has seen any other domain recognises these.
//!
//! # The version starts at zero, and that is a fact the client checks
//!
//! `versionNumber` in the directory and `Version=` in the template's `GPT.INI` have to be the same
//! number, and a client applies a policy only when they agree. Zero is what a policy with no
//! settings has, and it is what Samba writes (`create_gpo_struct` writes `Version=0`). The two are
//! set here and in the template by the same constant, so they cannot drift.
//!
//! # What this deliberately does not do
//!
//! No policy *content*: `Machine` and `User` hold nothing, which is a valid policy - a client reads
//! it, finds no settings and applies none. No `gPCUserExtensionNames`: that attribute lists the
//! client-side extensions whose settings the template carries, and listing an extension for an empty
//! template is a claim that there is something to run.
//!
//! And nothing here is replicated: this server has one directory, so a second copy of a policy is a
//! second answer to the same question rather than a backup.

use crate::backend::EntryChange;
use crate::model::{Attribute, Entry};

/// The DNS name of the domain these policies belong to.
///
/// `Settings::resolve` refuses a naming context it cannot spell, and every caller of [`ensure`]
/// has one that resolved - so `None` here is a naming context with no `dc=` components, which is a
/// configuration this server does not start with.
/// The domain a naming context names, for the callers that are not this module.
///
/// One spelling of one rule: the share's first folder, the policies' `gPCFileSysPath` and the zone
/// this server answers for all say the same domain, and a second derivation is a second chance to
/// disagree.
pub fn domain_of_dn(base_dn: &str) -> Option<String> {
    dns_domain(base_dn)
}

fn dns_domain(base_dn: &str) -> Option<String> {
    #[cfg(feature = "dns")]
    {
        crate::dns::config::domain_of_base(base_dn)
    }
    #[cfg(not(feature = "dns"))]
    {
        // Without the `dns` feature the spelling lives here: the same rule, ten lines, rather than
        // a feature the policy half would otherwise depend on for one string.
        let mut labels = Vec::new();
        for rdn in base_dn.split(',') {
            let (kind, value) = rdn.split_once('=')?;
            if !kind.trim().eq_ignore_ascii_case("dc") {
                break;
            }
            labels.push(value.trim().to_ascii_lowercase());
        }
        (labels.len() >= 2).then(|| labels.join("."))
    }
}

/// The policy every domain gets, whose settings a client applies when it finds none of its own.
///
/// The value lives in [`crate::sysvol::profiles`], beside the templates that name the same GUID in
/// their paths: one constant, re-exported, rather than two that can disagree.
pub use crate::sysvol::profiles::DEFAULT_DOMAIN_POLICY;

/// The policy that applies to domain controllers themselves.
pub use crate::sysvol::profiles::DEFAULT_CONTROLLERS_POLICY;

/// What `displayName` says, in the two spellings Windows and Samba use.
pub const DEFAULT_DOMAIN_POLICY_NAME: &str = "Default Domain Policy";
pub const DEFAULT_CONTROLLERS_POLICY_NAME: &str = "Default Domain Controllers Policy";

/// The version of every policy this module writes, in the directory and in `GPT.INI` both.
///
/// Zero: a policy whose template carries no settings. It is not a placeholder to be raised later -
/// a client compares the two numbers and skips a policy whose halves disagree, so a value here that
/// the template does not carry would make the policy invisible without an error anywhere.
pub const VERSION: u32 = 0;

/// `CN=System,<base_dn>`, the container AD keeps the directory's own machinery in.
pub fn system_dn(base_dn: &str) -> String {
    format!("cn=System,{base_dn}")
}

/// `CN=Policies,CN=System,<base_dn>`, where every `groupPolicyContainer` lives.
pub fn policies_dn(base_dn: &str) -> String {
    format!("cn=Policies,{}", system_dn(base_dn))
}

/// The DN of one policy.
pub fn policy_dn(base_dn: &str, guid: &str) -> String {
    format!("cn={guid},{}", policies_dn(base_dn))
}

/// The share path a client fetches the template from, as AD spells it.
///
/// `\\<server>\SYSVOL\<domain>\Policies\<GUID>`, which is four components and not two. Each was
/// missing here once, and the result was a path no client could follow:
///
/// - `SYSVOL` is the share. Without it the client opens the share `Policies`, which no server has;
/// - `<domain>` repeats under the share, because one `SYSVOL` serves the whole forest: `Policies`
///   alone would be ambiguous between two domains on one controller;
/// - `<server>` and not the domain name. A domain path - `\\ad.example.com\SYSVOL\...` - is a **DFS
///   namespace** in AD: the client asks for a referral over `FSCTL_DFS_GET_REFERRALS` and is sent to
///   a controller. This server does not answer that (`STATUS_FS_DRIVER_REQUIRED`), so a domain path
///   would name something that does not resolve. The server's own name is a real share, and it is
///   what the deployment can actually serve today; the domain path returns when DFS does.
///
/// Lower-cased throughout: a share name is matched without case by SMB and by this server, and one
/// spelling is what makes two policies' paths comparable.
pub fn file_sys_path(server: &str, dns_domain: &str, guid: &str) -> String {
    format!(
        r"\\{}\SYSVOL\{}\Policies\{guid}",
        server.to_ascii_lowercase(),
        dns_domain.to_ascii_lowercase()
    )
}

/// The entries that make a domain's policy container - the ones that are missing, in write order.
///
/// Parent first: a directory refuses a child whose parent is absent, and the order of a `Vec` is the
/// only thing that says which is which.
pub fn entries(base_dn: &str, server: &str, dns_domain: &str) -> Vec<Entry> {
    let container = |dn: String, cn: &str| {
        Entry::new(
            dn,
            crate::model::Attributes::new()
                .push(Attribute::new(
                    "objectClass",
                    vec!["top".to_string(), "container".to_string()],
                ))
                .push(Attribute::single("cn", cn)),
        )
    };

    let policy = |guid: &str, name: &str| {
        Entry::new(
            policy_dn(base_dn, guid),
            crate::model::Attributes::new()
                // `container` beside `groupPolicyContainer`: the latter is a subclass of it, and a
                // client that asks for `(objectClass=container)` - which `GPMC` does when it lists
                // the tree - finds the policy only if the superclass is named.
                .push(Attribute::new(
                    "objectClass",
                    vec![
                        "top".to_string(),
                        "container".to_string(),
                        "groupPolicyContainer".to_string(),
                    ],
                ))
                .push(Attribute::single("cn", guid))
                .push(Attribute::single("displayName", name))
                .push(Attribute::single(
                    "gPCFileSysPath",
                    file_sys_path(server, dns_domain, guid).as_str(),
                ))
                // 2 is the version of the Group Policy Editor that made the object, and the only
                // value a policy with no extensions to name has.
                .push(Attribute::single("gPCFunctionalityVersion", "2"))
                .push(Attribute::single(
                    "versionNumber",
                    VERSION.to_string().as_str(),
                ))
                // Zero: the policy is enabled and its settings apply. The two bits `flags` carries
                // are "user settings disabled" and "computer settings disabled", and an empty policy
                // disables neither.
                .push(Attribute::single("flags", "0")),
        )
    };

    vec![
        container(system_dn(base_dn), "System"),
        container(policies_dn(base_dn), "Policies"),
        policy(DEFAULT_DOMAIN_POLICY, DEFAULT_DOMAIN_POLICY_NAME),
        policy(DEFAULT_CONTROLLERS_POLICY, DEFAULT_CONTROLLERS_POLICY_NAME),
    ]
}

/// What the last start did, so a caller can say it once instead of on every restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Both policies were already there; nothing was written.
    AlreadyThere,
    /// The entries in the list were written.
    Created(Vec<String>),
}

/// The name a policy's template path is built from, or why there is none.
///
/// Refused rather than defaulted: the name goes into `gPCFileSysPath`, and a path built from an empty
/// host is `\\\SYSVOL\...` - a policy a client can list and never open, which reads as a broken share
/// rather than as a missing setting.
pub fn checked_server(server: &str) -> Result<&str, String> {
    let trimmed = server.trim();
    if trimmed.is_empty() {
        return Err(
            "a policy names the server its template lives on, and none is configured: set \
             `cldap.dns_host` (or `smb.dns_domain` with `smb.netbios_name`) so that \
             `gPCFileSysPath` is a path a client can follow"
                .to_string(),
        );
    }
    Ok(trimmed)
}

/// Writes the two default policies if the directory has no policy container.
///
/// All or nothing on the container: a directory with `CN=Policies` and one policy is a half-made
/// state somebody has to recognise, and it is reachable only by a write that failed halfway - which
/// the backend makes atomic, so it is not a state this can leave behind.
pub async fn ensure(
    source: &crate::reload::Source,
    base_dn: &str,
    server: &str,
) -> Result<Outcome, String> {
    if source
        .directory()
        .await
        .find(&policies_dn(base_dn))
        .is_some()
    {
        return Ok(Outcome::AlreadyThere);
    }

    let domain = dns_domain(base_dn).ok_or_else(|| {
        format!("the policies belong to a domain and '{base_dn}' has no dc= components to name one")
    })?;
    let server = checked_server(server)?;
    let entries = entries(base_dn, server, &domain);
    let written = entries.iter().map(|entry| entry.dn().to_string()).collect();
    let changes: Vec<EntryChange> = entries
        .into_iter()
        .map(|entry| EntryChange::Upsert { entry })
        .collect();
    source
        .apply(&changes)
        .await
        .map_err(|err| format!("writing the domain's default policies: {err}"))?;
    Ok(Outcome::Created(written))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "dc=ad,dc=example,dc=com";
    const DOMAIN: &str = "ad.example.com";

    fn schema() -> crate::schema::Schema {
        let mut schema = crate::schema::Schema::core();
        crate::ad_schema::extend(&mut schema).expect("the AD vocabulary parses");
        schema
    }

    /// Both policies validate against the schema this server publishes, or a client finds nothing.
    ///
    /// The check is the same one a write makes, and it is the only way to know that the class and
    /// its five attributes are really in the published vocabulary rather than in a file nobody
    /// parsed: `groupPolicyContainer` comes from the AD dump, so this is a test of the dump and of
    /// the parser rather than of a definition written here.
    #[test]
    fn the_default_policies_are_entries_this_schema_accepts() {
        let schema = schema();
        for entry in entries(BASE, "dc1.ad.example.com", DOMAIN) {
            if let Err(violations) = schema.check(&entry) {
                panic!("{} does not validate: {violations:?}", entry.dn());
            }
        }
    }

    /// The two names every domain has, in the spelling AD's tools print.
    #[test]
    fn the_two_default_policies_are_the_ones_windows_makes() {
        let policies = entries(BASE, "dc1.ad.example.com", DOMAIN);
        let names: Vec<&str> = policies
            .iter()
            .filter_map(|entry| {
                entry
                    .attributes()
                    .get("displayName")
                    .and_then(|attribute| attribute.values.first().map(String::as_str))
            })
            .collect();
        assert_eq!(
            names,
            vec![DEFAULT_DOMAIN_POLICY_NAME, DEFAULT_CONTROLLERS_POLICY_NAME],
            "the names `gpresult` looks for"
        );
        assert!(
            policies
                .iter()
                .any(|entry| entry.dn().contains(DEFAULT_DOMAIN_POLICY)),
            "the domain policy GUID is Samba's and MS-GPOD's, not one of ours"
        );
    }

    /// The path is spelled out in full, character for character.
    ///
    /// The version of this test before it checked `starts_with(r"\\ad.example.com\")` and
    /// `ends_with(r"Policies\{GUID}")`, which are both true of a path that is missing `SYSVOL` and
    /// the domain that repeats under it - and a client cannot follow that path at all. A test of the
    /// two ends of a string says nothing about its middle, so this one states the whole thing.
    #[test]
    fn the_path_is_the_one_a_client_can_follow() {
        assert_eq!(
            file_sys_path("dc1.ad.example.com", DOMAIN, DEFAULT_DOMAIN_POLICY),
            r"\\dc1.ad.example.com\SYSVOL\ad.example.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "share, domain under the share, then Policies"
        );
        // A path built from the domain name is a DFS namespace, which this server does not answer:
        // `FSCTL_DFS_GET_REFERRALS` returns STATUS_FS_DRIVER_REQUIRED. Named here so that the reason
        // the server's name is used is in the test and not only in a commit message.
        assert!(
            !file_sys_path("dc1.ad.example.com", DOMAIN, DEFAULT_DOMAIN_POLICY)
                .starts_with(r"\\ad.example.com\SYSVOL"),
            "the domain would need DFS, and this server does not serve one"
        );
    }

    /// The version and the path name one GUID, and the path carries the server it lives on.
    #[test]
    fn the_version_is_zero_and_the_path_names_the_same_guid() {
        for entry in entries(BASE, "dc1.ad.example.com", DOMAIN) {
            let Some(version) = entry
                .attributes()
                .get("versionNumber")
                .and_then(|attribute| attribute.values.first())
            else {
                continue;
            };
            assert_eq!(version, "0", "an empty template carries Version=0");
            let path = entry
                .attributes()
                .get("gPCFileSysPath")
                .and_then(|attribute| attribute.values.first())
                .expect("a policy names its template");
            let guid = entry
                .attributes()
                .get("cn")
                .and_then(|attribute| attribute.values.first())
                .expect("a policy is named by its GUID");
            assert_eq!(
                path,
                &file_sys_path("dc1.ad.example.com", DOMAIN, guid),
                "the path is built by the one function that knows its shape"
            );
            assert!(
                path.contains(r"\SYSVOL\"),
                "the share is named, and without it a client asks for a share `Policies`: {path}"
            );
        }
    }

    /// A missing server name is refused, not turned into `\\\SYSVOL\...`.
    #[test]
    fn a_policy_without_a_server_name_is_refused() {
        let error = checked_server("  ").expect_err("an empty host is not a host");
        assert!(
            error.contains("gPCFileSysPath"),
            "the refusal says what the value is for: {error}"
        );
        assert_eq!(
            checked_server(" dc1.ad.example.com ").expect("a name, with the space trimmed"),
            "dc1.ad.example.com"
        );
    }

    /// The container comes before what it holds: a directory refuses a child whose parent is absent.
    #[test]
    fn the_parents_are_written_first() {
        let dns: Vec<String> = entries(BASE, "dc1.ad.example.com", DOMAIN)
            .iter()
            .map(|entry| entry.dn().to_string())
            .collect();
        assert_eq!(dns[0], system_dn(BASE));
        assert_eq!(dns[1], policies_dn(BASE));
        assert_eq!(dns[2], policy_dn(BASE, DEFAULT_DOMAIN_POLICY));
        assert_eq!(dns[3], policy_dn(BASE, DEFAULT_CONTROLLERS_POLICY));
    }
}
