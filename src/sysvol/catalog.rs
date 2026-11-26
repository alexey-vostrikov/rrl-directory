//! The volume, read out of the directory's own policy container.
//!
//! This is the join between the two halves: [`crate::gpo`] writes `groupPolicyContainer` entries, and
//! a template renders one of them into files. Nothing is stored twice, so the version a client
//! compares in `GPT.INI` is the `versionNumber` of the entry it just read - not a copy that can lag.
//!
//! # Why a snapshot and not a live read
//!
//! A share answers many requests for the same policy within milliseconds, and a directory read per
//! file is a directory read per byte-range as far as latency goes. The volume therefore takes the
//! snapshot it was built from: [`crate::reload::Source`] swaps the snapshot in one step, and a caller
//! that wants a fresh volume builds one. That is the same contract the DNS listener has, and for the
//! same reason - one snapshot per answer, never a mixture.

use super::{Machine, Policy, Rendered, Template};
use crate::directory::Directory;

/// The policy a `groupPolicyContainer` describes, or `None` for an entry that is not one.
///
/// The GUID is the `cn`, which is how AD names a policy and how a client addresses its folder. The
/// version comes from `versionNumber`, and a policy without one is read as zero rather than skipped:
/// a policy a client fetches and then declines to apply is better than one it cannot find.
pub fn policy_of(entry: &crate::model::Entry) -> Option<Policy> {
    let attributes = entry.attributes();
    let classes = attributes.get("objectClass")?;
    if !classes
        .values
        .iter()
        .any(|class| class.eq_ignore_ascii_case("groupPolicyContainer"))
    {
        return None;
    }

    let text = |name: &str| {
        attributes
            .get(name)
            .and_then(|attribute| attribute.values.first())
            .cloned()
    };

    Some(Policy {
        guid: text("cn")?,
        name: text("displayName").unwrap_or_default(),
        version: text("versionNumber")
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0),
        // The settings a policy carries: this server writes none of them yet, and an empty `Machine`
        // renders to a policy that sets nothing rather than to a policy that is broken. When the
        // settings arrive they arrive here, which is the point of keeping the two apart.
        machine: Machine::default(),
    })
}

/// Every policy the directory holds, in the order a client sorts them by name.
pub fn policies(directory: &Directory, base_dn: &str) -> Vec<Policy> {
    let container = crate::gpo::policies_dn(base_dn);
    let mut found: Vec<Policy> = directory
        .records_in_scope(&container, crate::directory::Scope::OneLevel)
        .into_iter()
        .filter_map(|(_, entry)| policy_of(entry.as_ref()))
        .collect();
    found.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
            .then_with(|| left.guid.cmp(&right.guid))
    });
    found
}

/// A volume over the policies `directory` holds, rendered by `template`.
pub fn volume<T: Template>(directory: &Directory, base_dn: &str, template: T) -> Rendered<T> {
    Rendered::new(policies(directory, base_dn), template)
}

/// A convenience for the two calls a share makes: read one file, or list a policy.
///
/// Not a second implementation of [`Volume`] - it forwards, and exists so that a caller holding a
/// `Source` does not have to spell out the snapshot dance at every call site.
pub async fn read(
    source: &crate::reload::Source,
    base_dn: &str,
    template: &dyn Template,
    guid: &str,
    path: &str,
) -> Option<Vec<u8>> {
    let directory = source.directory().await;
    let policies = policies(&directory, base_dn);
    let policy = policies
        .iter()
        .find(|policy| policy.guid.eq_ignore_ascii_case(guid))?;
    template
        .files(policy)
        .into_iter()
        .find(|file| super::same_path(&file.path, path))
        .map(|file| file.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysvol::profiles::{DEFAULT_DOMAIN_POLICY, Sssd, Windows};
    // The trait brings `read` and `files` into scope: `Rendered` implements them, and a method from
    // a trait is not callable until the trait is named on the importing side.
    use crate::sysvol::Volume as _;

    /// A directory with the two policies [`crate::gpo`] provisions.
    ///
    /// Through `Directory::from_entries` rather than a backend, because what is under test is the
    /// join - an entry with `objectClass: groupPolicyContainer` becoming a policy a template renders
    /// - and a store would add a file and a lifetime to that without adding a fact.
    fn directory() -> Directory {
        let base = "dc=ad,dc=example,dc=com";
        Directory::from_entries(
            base,
            "users",
            "groups",
            crate::gpo::entries(base, "ad.example.com"),
        )
    }

    #[test]
    fn both_policies_are_read_out_of_the_directory() {
        let found = policies(&directory(), "dc=ad,dc=example,dc=com");
        assert_eq!(found.len(), 2, "the two the domain has: {found:?}");
        assert!(
            found
                .iter()
                .any(|policy| policy.guid == DEFAULT_DOMAIN_POLICY
                    && policy.name == "Default Domain Policy"),
            "the GUID and the name a client shows"
        );
        assert!(
            found
                .iter()
                .all(|policy| policy.version == crate::gpo::VERSION),
            "the directory's versionNumber, not a number chosen here"
        );
    }

    /// The end-to-end property a share depends on: a path in, bytes out, for every client.
    #[test]
    fn a_file_is_answered_for_each_client_and_a_missing_one_is_absent() {
        let directory = directory();
        let base = "dc=ad,dc=example,dc=com";

        let windows = volume(&directory, base, Windows);
        let sssd = volume(&directory, base, Sssd);

        // SSSD gets the security template even though this policy carries no settings, because a
        // policy it cannot evaluate is a denied logon for every user on every member.
        assert!(
            sssd.read(
                DEFAULT_DOMAIN_POLICY,
                r"MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            )
            .is_some(),
            "SSSD has to find the file it decides by"
        );
        assert!(
            sssd.read(DEFAULT_DOMAIN_POLICY, r"Machine\registry.pol")
                .is_none(),
            "and must not be sent the file it does not read"
        );

        // Windows gets the version file, and nothing for a component the policy does not have.
        let gpt = windows
            .read(DEFAULT_DOMAIN_POLICY, "GPT.INI")
            .expect("GPT.INI is always published");
        assert_eq!(
            crate::sysvol::inf::decode(&gpt).expect("UTF-16").trim_end(),
            "[General]\r\nVersion=0"
        );
        assert!(
            windows
                .read(DEFAULT_DOMAIN_POLICY, r"Machine\registry.pol")
                .is_none()
        );

        // A policy that does not exist answers nothing, whatever the path.
        assert!(
            windows
                .read("{00000000-0000-0000-0000-000000000000}", "GPT.INI")
                .is_none()
        );
    }

    #[test]
    fn a_name_that_is_not_a_policy_is_not_one() {
        let base = "dc=ad,dc=example,dc=com";
        let entry = crate::model::Entry::new(
            format!("cn=System,{base}"),
            crate::model::Attributes::new().push(crate::model::Attribute::new(
                "objectClass",
                vec!["top".to_string(), "container".to_string()],
            )),
        );
        assert!(
            policy_of(&entry).is_none(),
            "a container beside the policies is not a policy"
        );
    }
}
