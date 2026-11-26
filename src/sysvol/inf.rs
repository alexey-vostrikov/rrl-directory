//! `GptTmpl.inf`: the Security Settings extension's template.
//!
//! An INF file, and three things about it are not obvious:
//!
//! * **It is UTF-16LE with a byte-order mark.** A file written as ASCII parses as one long
//!   key with a NUL between every letter, and the reader reports a section it never found.
//! * **The order of the first two sections is fixed**: `[Unicode]` first, because it is what says
//!   the file is UTF-16 at all, then `[Version]` with `signature="$CHICAGO$"`.
//! * **Principals are SIDs, not names**, and a right's members are comma-separated on one line:
//!   `SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545`. The leading `*` is part of the
//!   spelling, and a name where a client expects a SID is a right granted to nobody.
//!
//! This is the file SSSD reads - and the only one it reads for policy - so it is the one that has to
//! be right for a Linux fleet. SSSD takes `[Privilege Rights]` and maps the logon rights onto PAM
//! service names; a missing `GptTmpl.inf` makes it evaluate nothing at all, which reads as "the
//! policy grants no access" rather than as a broken template.

use super::Machine;

/// The byte-order mark of UTF-16LE, which the format requires.
const BOM: [u8; 2] = [0xFF, 0xFE];

/// The right SSSD reads first, and the one a policy for a Linux fleet almost always sets.
pub const INTERACTIVE_LOGON: &str = "SeInteractiveLogonRight";
/// Logon over the network: an SSH session, and `samba` in SSSD's default PAM mapping.
pub const NETWORK_LOGON: &str = "SeNetworkLogonRight";
/// Remote interactive: `sshd` in SSSD's default mapping.
pub const REMOTE_INTERACTIVE_LOGON: &str = "SeRemoteInteractiveLogonRight";
/// Batch: `crond`.
pub const BATCH_LOGON: &str = "SeBatchLogonRight";
/// Deny interactive - the blacklist that takes precedence over the whitelist.
pub const DENY_INTERACTIVE_LOGON: &str = "SeDenyInteractiveLogonRight";

/// Encodes the machine half of a policy as `GptTmpl.inf`.
///
/// Sections with nothing in them are left out: an empty `[Privilege Rights]` and an absent one mean
/// the same thing to a client, and writing the empty one would suggest the policy had been through
/// an editor that found no rights to set.
pub fn encode(machine: &Machine) -> Vec<u8> {
    let mut lines: Vec<String> = vec![
        "[Unicode]".to_string(),
        "Unicode=yes".to_string(),
        "[Version]".to_string(),
        r#"signature="$CHICAGO$""#.to_string(),
        "Revision=1".to_string(),
    ];

    if !machine.system_access.is_empty() {
        lines.push("[System Access]".to_string());
        for (name, value) in &machine.system_access {
            lines.push(format!("{name} = {value}"));
        }
    }

    if !machine.rights.is_empty() {
        lines.push("[Privilege Rights]".to_string());
        for (right, principals) in &machine.rights {
            lines.push(format!("{right} = {}", principals.join(",")));
        }
    }

    text(&lines.join("\r\n"))
}

/// The same file with no settings: what a policy with no security component publishes.
pub fn empty() -> Vec<u8> {
    encode(&Machine::default())
}

/// The bytes of a text file in the encoding the format requires: BOM, UTF-16LE, CRLF line endings.
///
/// Public because every `.inf` and `.ini` under a policy is written this way, and one function is
/// what keeps them from disagreeing about the terminator.
pub fn text(contents: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(BOM.len() + contents.len() * 2 + 4);
    out.extend_from_slice(&BOM);
    for unit in contents.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    // A final CRLF: `INF` parsers differ about a last line without a terminator, and there is no
    // reason to be one of the files that finds out.
    for unit in "\r\n".encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Reads a file back as text, for the tests and for a caller that wants to show what a policy says.
pub fn decode(bytes: &[u8]) -> Result<String, String> {
    if !bytes.starts_with(&BOM) {
        return Err("no UTF-16LE byte-order mark".to_string());
    }
    let units: Vec<u16> = bytes[BOM.len()..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16(&units).map_err(|err| format!("not UTF-16LE text: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> Machine {
        Machine {
            rights: vec![
                (
                    INTERACTIVE_LOGON.to_string(),
                    vec!["*S-1-5-32-544".to_string(), "*S-1-5-32-545".to_string()],
                ),
                (
                    REMOTE_INTERACTIVE_LOGON.to_string(),
                    vec!["*S-1-5-32-544".to_string()],
                ),
            ],
            system_access: vec![("MinimumPasswordLength".to_string(), "12".to_string())],
            ..Machine::default()
        }
    }

    #[test]
    fn the_file_is_utf16_with_a_mark_and_starts_with_unicode_then_version() {
        let file = encode(&machine());
        assert_eq!(
            &file[..2],
            &[0xFF, 0xFE],
            "the mark, or a reader sees one long key"
        );

        let text = decode(&file).expect("it reads back");
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(
            lines[0], "[Unicode]",
            "first, because it says what the encoding is"
        );
        assert_eq!(lines[1], "Unicode=yes");
        assert_eq!(lines[2], "[Version]");
        assert_eq!(lines[3], r#"signature="$CHICAGO$""#);
        assert_eq!(lines[4], "Revision=1");
    }

    /// The shape SSSD reads: one line per right, SIDs with their leading `*`, comma-separated.
    #[test]
    fn the_rights_are_sids_on_one_line_each() {
        let text = decode(&encode(&machine())).expect("it reads back");
        assert!(
            text.contains("SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545"),
            "{text}"
        );
        assert!(
            text.contains("SeRemoteInteractiveLogonRight = *S-1-5-32-544"),
            "{text}"
        );
        assert!(text.contains("MinimumPasswordLength = 12"), "{text}");
    }

    /// A section with nothing in it is absent rather than empty.
    #[test]
    fn a_policy_with_no_rights_writes_no_rights_section() {
        let text = decode(&empty()).expect("it reads back");
        assert!(!text.contains("[Privilege Rights]"), "{text}");
        assert!(!text.contains("[System Access]"), "{text}");
        assert!(text.contains("[Unicode]"), "the header is always there");
    }

    /// Line endings are CRLF: an INF parser that meets a bare LF in a UTF-16 file can read the two
    /// octets of the newline as a character, and a section header that does not start a line is a
    /// section the client never finds.
    #[test]
    fn the_lines_end_with_carriage_return_and_newline() {
        let file = encode(&machine());
        let units: Vec<u16> = file[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        for (index, unit) in units.iter().enumerate() {
            if *unit == u16::from(b'\n') {
                assert_eq!(
                    units.get(index - 1),
                    Some(&u16::from(b'\r')),
                    "a newline at {index} is not preceded by a carriage return"
                );
            }
        }
    }

    #[test]
    fn a_file_without_the_mark_is_refused_rather_than_guessed_at() {
        let error = decode(b"[Unicode]\r\nUnicode=yes\r\n").expect_err("ASCII is not this format");
        assert!(error.contains("byte-order mark"), "{error}");
    }
}
