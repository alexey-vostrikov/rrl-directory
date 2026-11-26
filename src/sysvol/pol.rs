//! `registry.pol`, as [MS-GPREG] §2.2.1 defines it.
//!
//! ```text
//! PolicyFile = Header Body
//! Header     = Signature Version
//! Signature  = %x50.52.65.67          "PReg", four ASCII octets - not UTF-16
//! Version    = %x01                   32-bit little-endian
//! Instruction = "[" KeyPath ";" Value ";" Type ";" Size ";" Data "]"
//! ```
//!
//! Every field of an instruction is UTF-16LE, and so are the brackets and semicolons - which is
//! where a first implementation goes wrong: the header is ASCII and the body is not, and a file
//! written with an ASCII `;` parses as a key name of nonsense length. Confirmed against Microsoft's
//! own reader (`GPRegistryPolicyParser.psm1`, which splits on a two-byte semicolon and steps over
//! the null terminator that precedes it).
//!
//! The size field is the length of `Data` in **bytes**, not characters, and it is ASCII-decimal in
//! some producers and a 32-bit little-endian integer in the specification. This writes the integer:
//! the specification is what a client is required to read, and a producer that writes the other
//! form is what makes readers disagree.

use super::Registry;

/// A value's type, by the number MS-GPREG gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `0x01`: a null-terminated UTF-16LE string.
    Sz,
    /// `0x02`: a string with environment variables, same encoding.
    ExpandSz,
    /// `0x03`: an octet stream, untouched.
    Binary,
    /// `0x04`: four octets, little-endian.
    Dword,
    /// `0x05`: four octets, big-endian.
    DwordBigEndian,
    /// `0x07`: strings separated by one null, ending in two.
    MultiSz,
    /// `0x0B`: eight octets, little-endian.
    Qword,
}

impl Kind {
    /// The number the wire carries.
    pub fn id(self) -> u32 {
        match self {
            Kind::Sz => 0x01,
            Kind::ExpandSz => 0x02,
            Kind::Binary => 0x03,
            Kind::Dword => 0x04,
            Kind::DwordBigEndian => 0x05,
            Kind::MultiSz => 0x07,
            Kind::Qword => 0x0B,
        }
    }
}

/// The signature, in ASCII: MS-GPREG puts these four octets outside the UTF-16 encoding.
const SIGNATURE: [u8; 4] = *b"PReg";

/// The only version the specification defines.
const VERSION: u32 = 1;

/// A string as the file carries it: UTF-16LE with a terminating null.
///
/// Public because a registry value's data is written in this form by whoever builds the setting, and
/// two implementations of it would be two chances to forget the terminator.
pub fn utf16_null_terminated(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2 + 2);
    push_utf16(&mut out, text);
    push_utf16(&mut out, "\0");
    out
}

fn push_utf16(out: &mut Vec<u8>, text: &str) {
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
}

fn push_char(out: &mut Vec<u8>, character: char) {
    push_utf16(out, &character.to_string());
}

fn push_u32(out: &mut Vec<u8>, number: u32) {
    out.extend_from_slice(&number.to_le_bytes());
}

/// Encodes the whole file: header, then one instruction per value.
///
/// The order is kept, because MS-GPREG says it is significant: two files that differ only in the
/// order of their instructions are not equivalent, and a client applies them in sequence.
pub fn encode(values: &[Registry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + values.len() * 64);
    out.extend_from_slice(&SIGNATURE);
    push_u32(&mut out, VERSION);
    for value in values {
        // The bracket is part of the UTF-16 body, like every other field of an instruction.
        push_char(&mut out, '[');
        push_utf16(&mut out, &value.key);
        push_char(&mut out, '\0');
        push_char(&mut out, ';');
        push_utf16(&mut out, &value.value);
        push_char(&mut out, '\0');
        push_char(&mut out, ';');
        push_u32(&mut out, value.kind.id());
        push_char(&mut out, ';');
        push_u32(&mut out, value.data.len() as u32);
        push_char(&mut out, ';');
        out.extend_from_slice(&value.data);
        push_char(&mut out, ']');
    }
    out
}

/// The file with no settings at all.
///
/// A header and nothing else, which is what a policy that sets no registry values renders to. It is
/// **not** what a policy with no registry settings publishes - that one has no `registry.pol` - and
/// the difference is the one a client acts on: an empty file says "this policy sets nothing", an
/// absent one says "this policy has no registry component".
pub fn empty() -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&SIGNATURE);
    push_u32(&mut out, VERSION);
    out
}

/// Reads a file back, for the tests that check what this wrote.
///
/// Deliberately small: it is here so the encoder is checked against something other than itself in
/// shape - a round trip through the same function proves only that the function is consistent.
#[cfg(test)]
pub fn decode(bytes: &[u8]) -> Result<Vec<Registry>, String> {
    if bytes.len() < 8 {
        return Err(format!("{} octets is shorter than a header", bytes.len()));
    }
    if bytes[..4] != SIGNATURE {
        return Err("the signature is not PReg".to_string());
    }
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != VERSION {
        return Err(format!("version {version}, and only {VERSION} is written"));
    }

    let mut out = Vec::new();
    let units: Vec<u16> = bytes[8..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    let mut index = 0usize;
    let text = |index: &mut usize| -> String {
        let start = *index;
        while *index < units.len() && units[*index] != 0 {
            *index += 1;
        }
        let text = String::from_utf16_lossy(&units[start..*index]);
        *index += 1; // the null
        text
    };

    while index < units.len() {
        if units[index] != u16::from(b'[') {
            return Err(format!("instruction {index} does not start with '['"));
        }
        index += 1;
        let key = text(&mut index);
        if units.get(index) != Some(&u16::from(b';')) {
            return Err("no ';' after the key".to_string());
        }
        index += 1;
        let value = text(&mut index);
        if units.get(index) != Some(&u16::from(b';')) {
            return Err("no ';' after the value".to_string());
        }
        index += 1;
        // The type and the size are 32-bit integers, which are two units each.
        let number = |index: &mut usize| -> u32 {
            let low = units[*index] as u32;
            let high = units[*index + 1] as u32;
            *index += 2;
            low | (high << 16)
        };
        let kind = number(&mut index);
        if units.get(index) != Some(&u16::from(b';')) {
            return Err("no ';' after the type".to_string());
        }
        index += 1;
        let size = number(&mut index) as usize;
        if units.get(index) != Some(&u16::from(b';')) {
            return Err("no ';' after the size".to_string());
        }
        index += 1;

        // The data is octets, not units, so it is read from the byte stream rather than from `units`.
        let at_units = index;
        let data_at = 8 + at_units * 2;
        let data = bytes[data_at..data_at + size].to_vec();
        // `size` is in octets, so the unit cursor advances by half of it, rounded up - a value whose
        // data is an odd number of octets is padded to the next unit by the ']' that follows.
        index += size.div_ceil(2);

        if units.get(index) != Some(&u16::from(b']')) {
            return Err(format!("no ']' after the data of instruction {index}"));
        }
        index += 1;
        out.push(Registry {
            key,
            value,
            kind: match kind {
                0x01 => Kind::Sz,
                0x02 => Kind::ExpandSz,
                0x03 => Kind::Binary,
                0x04 => Kind::Dword,
                0x05 => Kind::DwordBigEndian,
                0x07 => Kind::MultiSz,
                other => return Err(format!("type {other:#x} is not one this reads")),
            },
            data,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_is_ascii_and_the_version_is_one() {
        let file = empty();
        assert_eq!(
            &file[..4],
            b"PReg",
            "four ASCII octets, outside the UTF-16 body"
        );
        assert_eq!(
            file.len(),
            8,
            "and a 32-bit version: MS-GPREG says four octets"
        );
        assert_eq!(u32::from_le_bytes([file[4], file[5], file[6], file[7]]), 1);
    }

    /// The property a first implementation gets wrong: every field of an instruction is UTF-16,
    /// including the brackets and the semicolons.
    #[test]
    fn the_body_is_utf16_including_the_punctuation() {
        let file = encode(&[Registry::string(r"Software\Policies\Samba", "Level", "2")]);
        // After the header the first thing is '[' as two octets, then a null-bearing key.
        assert_eq!(&file[8..10], &[0x5b, 0x00], "'[' little-endian");
        let body = &file[8..];
        assert_eq!(
            body.len() % 2,
            0,
            "the body is a whole number of UTF-16 units"
        );
        // 'S' of the key, and a null after the key's last character.
        assert_eq!(&body[2..4], &[0x53, 0x00]);
    }

    #[test]
    fn a_string_value_carries_its_terminator_and_a_dword_four_octets() {
        let text = Registry::string(r"Software\Policies\Samba", "Level", "2");
        assert_eq!(text.data, vec![0x32, 0x00, 0x00, 0x00], "'2' then its null");

        let number = Registry::dword(r"Software\Policies\Samba", "Enabled", 0x0102_0304);
        assert_eq!(number.data, vec![0x04, 0x03, 0x02, 0x01], "little-endian");
    }

    #[test]
    fn what_is_written_reads_back() {
        let values = vec![
            Registry::string(r"Software\Policies\Samba\smbconf", "log level", "3"),
            Registry::dword(r"Software\Policies\Samba\smbconf", "server signing", 1),
        ];
        let file = encode(&values);
        assert_eq!(decode(&file).expect("it reads back"), values);
    }

    #[test]
    fn the_order_is_kept_because_the_specification_says_it_matters() {
        let first = Registry::dword(r"A", "one", 1);
        let second = Registry::dword(r"B", "two", 2);
        let forwards = decode(&encode(&[first.clone(), second.clone()])).expect("reads");
        assert_eq!(forwards[0].key, "A");
        assert_eq!(forwards[1].key, "B");
    }

    #[test]
    fn the_types_are_the_numbers_the_specification_gives() {
        for (kind, id) in [
            (Kind::Sz, 0x01),
            (Kind::ExpandSz, 0x02),
            (Kind::Binary, 0x03),
            (Kind::Dword, 0x04),
            (Kind::DwordBigEndian, 0x05),
            (Kind::MultiSz, 0x07),
            (Kind::Qword, 0x0B),
        ] {
            assert_eq!(kind.id(), id, "{kind:?}");
        }
    }
}
