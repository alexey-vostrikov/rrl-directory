//! The three templates: what Windows, Samba and SSSD each fetch.
//!
//! # Why Windows and Samba are the same set, and that is not laziness
//!
//! A temptation with three names on a task is three different renderings. Measured against the
//! clients, there are two: Samba's client-side extensions are ADMX-backed and read `registry.pol`
//! exactly as Windows does, and its security extension reads `GptTmpl.inf` exactly as Windows does.
//! What differs between them is which extensions a client is *told* to run, in
//! `gPCMachineExtensionNames` - and that attribute lives on the `groupPolicyContainer`, not in the
//! template. A second rendering would be a second answer to a question both clients ask identically.
//!
//! SSSD is the one that really differs: it applies Windows logon rights, so it reads `GptTmpl.inf`,
//! and it reads `GPT.INI` to decide whether the policy changed. It does not read `registry.pol` at
//! all, and publishing one for it would be a file nobody fetches.

use super::inf;
use super::pol;
use super::{Client, File, Machine, Policy, Template};

/// The policy every domain has. The GUID is MS-GPOD's and Samba's, not one of ours.
pub const DEFAULT_DOMAIN_POLICY: &str = "{31B2F340-016D-11D2-945F-00C04FB984F9}";
/// The policy that applies to domain controllers themselves.
pub const DEFAULT_CONTROLLERS_POLICY: &str = "{6AC1786C-016F-11D2-945F-00C04FB984F9}";

/// Where the Security Settings extension keeps its template, as Windows writes it.
///
/// Upper-case `Machine` because that is what AD creates; the share answers any case.
const SECURITY: &str = r"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf";
/// The registry component, at the policy's root.
const REGISTRY: &str = r"Machine\registry.pol";
/// The startup scripts' index, which names the files beside it.
const SCRIPTS: &str = r"Machine\Scripts\scripts.ini";

/// `GPT.INI`: the version a client compares before it fetches anything else.
///
/// Two lines and a CRLF after each - Samba's `create_gpo_struct` writes `[General]\r\nVersion=0`
/// with no trailing newline, and both readings are accepted by the clients that read it. The
/// trailing newline is written because a line-oriented reader that meets a last line without one is
/// a reader whose behaviour nothing defines.
pub fn gpt_ini(version: u32) -> Vec<u8> {
    inf::text(&format!("[General]\r\nVersion={version}"))
}

/// The startup scripts' index: a numbered command line per script, in `[Startup]`.
///
/// Absent when a policy has no scripts, because an index with no entries is a claim that the policy
/// had scripts and lost them.
fn scripts_ini(machine: &Machine) -> Option<Vec<u8>> {
    if machine.startup.is_empty() {
        return None;
    }
    let mut lines = vec!["[Startup]".to_string()];
    for (index, script) in machine.startup.iter().enumerate() {
        lines.push(format!("{index}CmdLine={}", script.command));
        if !script.parameters.is_empty() {
            lines.push(format!("{index}Parameters={}", script.parameters));
        }
    }
    Some(inf::text(&lines.join("\r\n")))
}

/// Whether the policy carries anything for the Security Settings extension.
fn has_security(machine: &Machine) -> bool {
    !machine.rights.is_empty() || !machine.system_access.is_empty()
}

/// The files Windows and Samba both fetch.
fn full(policy: &Policy) -> Vec<File> {
    let mut files = vec![File {
        path: "GPT.INI".to_string(),
        bytes: gpt_ini(policy.version),
    }];

    if !policy.machine.registry.is_empty() {
        files.push(File {
            path: REGISTRY.to_string(),
            bytes: pol::encode(&policy.machine.registry),
        });
    }
    if has_security(&policy.machine) {
        files.push(File {
            path: SECURITY.to_string(),
            bytes: inf::encode(&policy.machine),
        });
    }
    if let Some(bytes) = scripts_ini(&policy.machine) {
        files.push(File {
            path: SCRIPTS.to_string(),
            bytes,
        });
    }
    files
}

/// The Windows Group Policy client: `gpupdate`, and the engine behind `gpedit`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Windows;

impl Template for Windows {
    fn client(&self) -> Client {
        Client::Windows
    }

    fn files(&self, policy: &Policy) -> Vec<File> {
        full(policy)
    }
}

/// `samba-gpupdate`, or winbind with `apply group policies = yes`.
///
/// The same files as [`Windows`], for the reason in this module's header. Named separately anyway,
/// because a deployment picks a client by name and a log line saying "samba" is what an operator
/// looks for - and because the day Samba reads something Windows does not, this is the type that
/// grows the file rather than a branch inside the other.
#[derive(Debug, Clone, Copy, Default)]
pub struct Samba;

impl Template for Samba {
    fn client(&self) -> Client {
        Client::Samba
    }

    fn files(&self, policy: &Policy) -> Vec<File> {
        full(policy)
    }
}

/// SSSD's GPO-based access control: `GPT.INI` and `GptTmpl.inf`, and nothing else.
///
/// The `GptTmpl.inf` is unconditional here, unlike in the other two, and the difference is the
/// client: SSSD decides whether a policy allows a logon by reading that file, and a policy without
/// one is a policy it cannot evaluate. Its own failure mode when the file is missing is to log the
/// error and deny - which reads at the user as "access denied by policy" rather than as "the
/// template was never written".
#[derive(Debug, Clone, Copy, Default)]
pub struct Sssd;

impl Template for Sssd {
    fn client(&self) -> Client {
        Client::Sssd
    }

    fn files(&self, policy: &Policy) -> Vec<File> {
        vec![
            File {
                path: "GPT.INI".to_string(),
                bytes: gpt_ini(policy.version),
            },
            File {
                path: SECURITY.to_string(),
                bytes: inf::encode(&policy.machine),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysvol::{Machine, Policy, Registry};

    fn policy() -> Policy {
        Policy {
            guid: DEFAULT_DOMAIN_POLICY.to_string(),
            name: "Default Domain Policy".to_string(),
            version: 3,
            machine: Machine {
                registry: vec![Registry::string(
                    r"Software\Policies\Samba\smbconf",
                    "log level",
                    "1",
                )],
                rights: vec![(
                    "SeInteractiveLogonRight".to_string(),
                    vec!["*S-1-5-32-544".to_string()],
                )],
                startup: vec![crate::sysvol::Script {
                    name: "onstart.sh".to_string(),
                    command: r"\\ad.example.com\NETLOGON\onstart.sh".to_string(),
                    parameters: "-n".to_string(),
                }],
                ..Machine::default()
            },
        }
    }

    fn paths(files: &[File]) -> Vec<&str> {
        files.iter().map(|file| file.path.as_str()).collect()
    }

    #[test]
    fn windows_publishes_every_component_the_policy_has() {
        let files = Windows.files(&policy());
        assert_eq!(paths(&files), vec!["GPT.INI", REGISTRY, SECURITY, SCRIPTS]);
    }

    /// The fact this module's header records: Samba reads the files Windows reads.
    #[test]
    fn samba_publishes_the_same_files_as_windows() {
        assert_eq!(
            paths(&Windows.files(&policy())),
            paths(&Samba.files(&policy()))
        );
        assert_ne!(
            Windows.client(),
            Samba.client(),
            "and is still a distinct client"
        );
    }

    #[test]
    fn sssd_publishes_only_what_it_reads() {
        let files = Sssd.files(&policy());
        assert_eq!(paths(&files), vec!["GPT.INI", SECURITY]);
        assert!(
            !paths(&files).contains(&REGISTRY),
            "SSSD does not read registry.pol, so publishing one is a file nobody fetches"
        );
    }

    /// SSSD's template is unconditional where the others are not: it cannot evaluate a policy whose
    /// `GptTmpl.inf` is absent, so a policy with no settings still gets one.
    #[test]
    fn sssd_still_publishes_the_security_template_when_the_policy_is_empty() {
        let empty = Policy {
            guid: DEFAULT_CONTROLLERS_POLICY.to_string(),
            version: 0,
            ..Policy::default()
        };
        assert_eq!(paths(&Windows.files(&empty)), vec!["GPT.INI"]);
        assert_eq!(paths(&Sssd.files(&empty)), vec!["GPT.INI", SECURITY]);
    }

    #[test]
    fn the_version_in_gpt_ini_is_the_versions_number() {
        let file = Windows
            .files(&policy())
            .into_iter()
            .find(|file| file.path == "GPT.INI")
            .expect("GPT.INI is always published");
        let text = inf::decode(&file.bytes).expect("it is UTF-16 with a mark");
        assert!(
            text.contains("Version=3"),
            "the directory's versionNumber: {text}"
        );
    }

    /// The index numbers its entries from zero and names the command line beside the script.
    #[test]
    fn the_scripts_index_numbers_the_commands() {
        let file = Windows
            .files(&policy())
            .into_iter()
            .find(|file| file.path == SCRIPTS)
            .expect("the policy has a script");
        let text = inf::decode(&file.bytes).expect("UTF-16");
        assert!(text.contains("[Startup]"), "{text}");
        assert!(
            text.contains(r"0CmdLine=\\ad.example.com\NETLOGON\onstart.sh"),
            "{text}"
        );
        assert!(text.contains("0Parameters=-n"), "{text}");
    }

    #[test]
    fn a_policy_with_no_registry_settings_publishes_no_registry_file() {
        let mut bare = policy();
        bare.machine.registry.clear();
        bare.machine.startup.clear();
        let files = Windows.files(&bare);
        assert_eq!(paths(&files), vec!["GPT.INI", SECURITY]);
        assert!(
            !paths(&files).contains(&REGISTRY),
            "an absent registry.pol says the policy has no registry component; an empty one says it sets nothing"
        );
    }

    #[test]
    fn an_empty_registry_file_is_a_header_and_nothing_else() {
        // The distinction the template makes: `pol::empty()` is only reachable through `encode` with
        // no values, and the template never does that.
        assert_eq!(pol::empty().len(), 8);
    }
}
