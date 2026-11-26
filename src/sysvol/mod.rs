//! The policy volume as a trait: one set of policies, read by clients that disagree about files.
//!
//! A `SYSVOL` share is not a directory of files that happens to be replicated. It is a rendering of
//! the directory's `groupPolicyContainer` objects into the shape a particular client expects - and
//! the clients disagree, in ways that are documented and measurable:
//!
//! | client | fetches |
//! |---|---|
//! | Windows | `GPT.INI`, `Machine\registry.pol`, `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`, `Machine\Scripts\**` |
//! | Samba (`samba-gpupdate`, winbind) | the same set: its client-side extensions are ADMX-backed and read `registry.pol`, and its security extension reads `GptTmpl.inf` |
//! | SSSD | `GPT.INI` and `GptTmpl.inf` only - it applies Windows **logon rights** and nothing else |
//!
//! So the volume is one trait with three implementations, and the implementations differ by which
//! files they publish rather than by how they render them. Two of the three publish the same set,
//! and that is a fact about the clients rather than a shortcut: Samba's extensions read the same
//! two files Windows does. Where they differ is `gPCMachineExtensionNames`, which names the
//! extensions a client should run - not the files it should fetch - and that attribute is written
//! from the policy, not from here.
//!
//! # Why a trait and not three branches
//!
//! A branch on "which client" can only be taken when the client is known, and over SMB2/3 it is not:
//! the `NativeOS` field that would say so exists only in SMB1 `SessionSetup`, and neither Samba nor
//! Windows sends it in SMB2 or later. The server cannot decide; it publishes a volume and lets each
//! client take what it understands. A trait makes that the only shape the code can take.
//!
//! # What is rendered, and from what
//!
//! Everything is derived from [`Policy`], which is what a `groupPolicyContainer` says: its GUID, its
//! version, and the settings it carries. Nothing is stored as files, so there is no second copy of a
//! policy to drift from the first - the same reason this server does not cache its DNS zone.

pub mod catalog;
pub mod inf;
pub mod pol;
pub mod profiles;
/// The volume as an SMB share. Present only when SMB is built: a backend for a protocol that is not
/// compiled is a dependency on nothing.
#[cfg(feature = "smb")]
pub mod share;

use std::fmt::Debug;

/// Which client a template is for.
///
/// Not a guess about a connection: a value a caller picks when it builds the volume, because the
/// volume is built for a deployment's fleet and not for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    /// `gpupdate` and the Group Policy engine: the full template.
    Windows,
    /// `samba-gpupdate`, or winbind with `apply group policies = yes`.
    Samba,
    /// SSSD's GPO-based access control: logon rights and nothing more.
    Sssd,
}

impl Client {
    /// The name this client is known by, for the log line that says which volume is served.
    pub fn name(self) -> &'static str {
        match self {
            Client::Windows => "windows",
            Client::Samba => "samba",
            Client::Sssd => "sssd",
        }
    }
}

/// One file of a template: a path relative to `Policies\{GUID}`, and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// Relative to the policy's own folder. Backslash-separated, as SMB and AD spell paths; compared
    /// without case, because SMB is and because a client is free to ask either way.
    pub path: String,
    pub bytes: Vec<u8>,
}

/// A setting the policy carries, in the form `registry.pol` needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registry {
    /// Under `HKLM` for a machine policy; the root is implicit (MS-GPREG §2.2.1).
    pub key: String,
    pub value: String,
    pub kind: pol::Kind,
    /// The data as the wire form carries it: a UTF-16LE string with its terminator for `RegSz`,
    /// four little-endian octets for `Dword`.
    pub data: Vec<u8>,
}

impl Registry {
    /// A `REG_SZ`: the value and its terminating null, in UTF-16LE.
    pub fn string(key: impl Into<String>, value: impl Into<String>, text: &str) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            kind: pol::Kind::Sz,
            data: pol::utf16_null_terminated(text),
        }
    }

    /// A `REG_DWORD`: four octets, little-endian.
    pub fn dword(key: impl Into<String>, value: impl Into<String>, number: u32) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            kind: pol::Kind::Dword,
            data: number.to_le_bytes().to_vec(),
        }
    }
}

/// One startup script: the name a policy publishes and the command it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    pub name: String,
    /// The command line, as `scripts.ini` records it.
    pub command: String,
    pub parameters: String,
}

/// What one `groupPolicyContainer` says, in the shape a template renders.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Policy {
    /// The GUID as AD spells it, braces included: `{31B2F340-...}`.
    pub guid: String,
    /// `displayName`, which is what an administrator sees.
    pub name: String,
    /// `versionNumber`. Also the `Version=` in `GPT.INI`, from this one value - the two halves of a
    /// policy disagreeing is a policy a client skips without an error anywhere.
    pub version: u32,
    /// The machine settings.
    pub machine: Machine,
}

/// The half of a policy that applies to the computer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Machine {
    pub registry: Vec<Registry>,
    /// `[Privilege Rights]` of `GptTmpl.inf`: the right, and the principals that hold it.
    ///
    /// Principals are SIDs, because that is what `GptTmpl.inf` carries: `*S-1-5-32-544` is
    /// `BUILTIN\Administrators`, and a name is resolved by the client that reads it.
    pub rights: Vec<(String, Vec<String>)>,
    pub startup: Vec<Script>,
    /// `[System Access]`: password and lockout policy, in the spelling `GptTmpl.inf` uses.
    pub system_access: Vec<(String, String)>,
}

/// A rendered template: the files one client fetches for one policy.
pub trait Template: Debug + Send + Sync {
    /// Which client this is for.
    fn client(&self) -> Client;

    /// The files, in the order a client should find them.
    ///
    /// A file with nothing to say is absent rather than empty: a `registry.pol` of zero entries is
    /// a claim that the policy sets nothing, while an absent one is a policy that has no registry
    /// settings at all - and a client that reads the first is right to treat them as different.
    fn files(&self, policy: &Policy) -> Vec<File>;
}

/// The volume: policies, and a template that renders them.
///
/// The trait, in the shape the share needs: a path in, bytes out. `None` is a file this volume does
/// not have, which the caller turns into `STATUS_OBJECT_NAME_NOT_FOUND` - not an empty file, which
/// a client would read as a policy with no settings.
pub trait Volume: Debug + Send + Sync {
    /// The policies this volume holds, for the share's listing and for `GPT.INI` of each.
    fn policies(&self) -> Vec<Policy>;

    /// The bytes of one file of one policy, or `None`.
    fn read(&self, guid: &str, path: &str) -> Option<Vec<u8>>;

    /// Every file of one policy, as `(path, bytes)` - what a secondary would copy.
    fn files(&self, guid: &str) -> Vec<File>;
}

/// A volume rendered by one template.
#[derive(Debug)]
pub struct Rendered<T: Template> {
    policies: Vec<Policy>,
    template: T,
}

impl<T: Template> Rendered<T> {
    pub fn new(policies: Vec<Policy>, template: T) -> Self {
        Self { policies, template }
    }

    /// The template in use, so a caller can say which client it is serving.
    pub fn template(&self) -> &T {
        &self.template
    }
}

/// The path of a policy's own folder under the share, as a client spells it.
///
/// `<domain>\Policies\{GUID}` - what `gPCFileSysPath` names, minus the share and the server. The
/// domain is repeated under the share because that is where a controller keeps it: one `SYSVOL`
/// serves the whole forest, and `Policies` directly under it would be ambiguous between two domains
/// on one server. It is not cosmetic - a client appends this to `\\<server>\SYSVOL\` and expects to
/// find the folder that `gPCFileSysPath` promised.
pub fn policy_root(domain: &str, guid: &str) -> String {
    format!(r"{domain}\Policies\{guid}")
}

/// Whether two paths name the same file.
///
/// Without case, because SMB is and because a client is free to ask either way: Windows writes
/// `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` and SSSD asks for
/// `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf`, and the same file answers both. Separators
/// are normalised too, for the same reason.
pub fn same_path(left: &str, right: &str) -> bool {
    normalise(left) == normalise(right)
}

fn normalise(path: &str) -> String {
    path.trim_start_matches(['\\', '/'])
        .replace('/', r"\")
        .to_ascii_lowercase()
}

impl<T: Template> Volume for Rendered<T> {
    fn policies(&self) -> Vec<Policy> {
        self.policies.clone()
    }

    fn read(&self, guid: &str, path: &str) -> Option<Vec<u8>> {
        let policy = self
            .policies
            .iter()
            .find(|policy| policy.guid.eq_ignore_ascii_case(guid))?;
        self.template
            .files(policy)
            .into_iter()
            .find(|file| same_path(&file.path, path))
            .map(|file| file.bytes)
    }

    fn files(&self, guid: &str) -> Vec<File> {
        match self
            .policies
            .iter()
            .find(|policy| policy.guid.eq_ignore_ascii_case(guid))
        {
            Some(policy) => self.template.files(policy),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            guid: profiles::DEFAULT_DOMAIN_POLICY.to_string(),
            name: "Default Domain Policy".to_string(),
            version: 7,
            machine: Machine {
                registry: vec![Registry::string(
                    r"Software\Policies\Samba\smbconf",
                    "log level",
                    "2",
                )],
                rights: vec![(
                    "SeInteractiveLogonRight".to_string(),
                    vec!["*S-1-5-32-544".to_string()],
                )],
                ..Machine::default()
            },
        }
    }

    #[test]
    fn a_path_is_matched_without_case_or_a_leading_separator() {
        assert!(same_path(r"Machine\Scripts", r"machine\scripts"));
        assert!(same_path(r"\Machine\Scripts", "MACHINE\\SCRIPTS"));
        assert!(same_path("Machine/Scripts", r"machine\scripts"));
        assert!(!same_path(r"Machine\scripts", r"Machine\Startup"));
    }

    #[test]
    fn a_policy_root_is_the_path_a_client_appends_to_the_share() {
        assert_eq!(
            policy_root("ad.example.com", "{31B2F340-016D-11D2-945F-00C04FB984F9}"),
            r"ad.example.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "the domain is under the share, as one SYSVOL serves the whole forest"
        );
    }

    #[test]
    fn a_volume_reads_one_file_and_lists_the_rest() {
        let volume = Rendered::new(vec![policy()], profiles::Windows);
        let guid = profiles::DEFAULT_DOMAIN_POLICY;

        // The same file under either spelling: Windows writes it one way, SSSD asks the other.
        let written = volume
            .read(guid, r"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf")
            .expect("the security settings are there");
        let asked = volume
            .read(guid, r"MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf")
            .expect("and under the spelling a client asks for");
        assert_eq!(written, asked);

        // A file the template does not publish is absent, and not an empty file.
        assert_eq!(volume.read(guid, r"Machine\registry.pol.bak"), None);
        assert!(
            volume
                .read("{00000000-0000-0000-0000-000000000000}", "GPT.INI")
                .is_none()
        );
        assert!(
            volume.files(guid).len() >= 3,
            "GPT.INI, registry.pol, GptTmpl.inf"
        );
    }
}
