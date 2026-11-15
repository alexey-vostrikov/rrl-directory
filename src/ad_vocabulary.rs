//! AD's schema, read from the files Microsoft publishes, in the syntax this server enforces.
//!
//! # Why the files and not a transcription
//!
//! This repository used to carry a hand-written AD vocabulary: `attributetype` and `objectclass`
//! lines typed out of memory and out of the documentation. Checking it against
//! `schema/ad/attributes.ldf` found eight OIDs that disagreed with AD's - `objectGUID` and
//! `objectSid` held each other's number, `primaryGroupID` was two attributes off, `container` was
//! the OID of a different class - and none of them was caught by anything, because the tests were
//! written against the same transcription.
//!
//! So the published files are the source. `classes.ldf` and `attributes.ldf` sit in `schema/ad/`,
//! `include_str!` puts them in the binary, and this module turns them into RFC 4512 definitions each
//! time the schema is built. There is nothing to drift: an entry that does not validate is either
//! wrong or an addition of ours, and both are visible.
//!
//! # What the translation has to decide
//!
//! AD's file describes an attribute with `attributeSyntax` (`2.5.5.x`) and `oMSyntax`; LDAP names a
//! syntax by its own OID (`1.3.6.1.4.1.1466.115.121.1.y`). The mapping below is the one MS-ADTS
//! §3.1.1.2.2.9 documents, and the matching rules are chosen from the result - without them a
//! filter like `(sAMAccountName=ADMIN)` would stop matching `admin`, because the default for an
//! unparsed syntax is a byte comparison.
//!
//! AD's `systemAuxiliaryClass` becomes the vocabulary's `AUXCLASS`: see the note on
//! [`crate::schema::ObjectClass::aux`].

use std::collections::BTreeMap;

/// The class list, as Microsoft publishes it.
pub const CLASSES_LDF: &str = include_str!("../schema/ad/classes.ldf");
/// The attribute list, as Microsoft publishes it.
pub const ATTRIBUTES_LDF: &str = include_str!("../schema/ad/attributes.ldf");

/// One LDIF entry: its attributes, in the order the file lists them.
type Entry = BTreeMap<String, Vec<String>>;

/// Splits an LDIF file into entries.
///
/// Only what a schema file uses: `name: value`, `name:: base64`, folded continuation lines, comments.
/// Anything else - a `changetype`, a control - is ignored, because it carries nothing a definition
/// needs and refusing the file over it would make this depend on an LDIF parser the server does not
/// otherwise want.
fn entries(ldf: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut current: Option<Entry> = None;
    let mut last_key: Option<String> = None;

    for raw in ldf.lines() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            if let Some(entry) = current.take() {
                out.push(entry);
            }
            last_key = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix(' ') {
            // A folded value: the rest of the line belongs to the attribute above.
            if let (Some(entry), Some(key)) = (current.as_mut(), last_key.as_ref())
                && let Some(values) = entry.get_mut(key)
                && let Some(last) = values.last_mut()
            {
                last.push_str(rest);
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.strip_prefix(':').map_or_else(
            || value.trim().to_string(),
            |encoded| decode_base64(encoded.trim()).unwrap_or_default(),
        );
        let entry = current.get_or_insert_with(Entry::new);
        // `changetype` and the objectClass list are not definitions; keeping them costs nothing and
        // keeps the parser honest about what it saw.
        entry.entry(name.clone()).or_default().push(value);
        last_key = Some(name);
    }
    if let Some(entry) = current.take() {
        out.push(entry);
    }
    out
}

/// The decoded value of an `::` field, or `None` when it is not base64.
fn decode_base64(text: &str) -> Option<String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The first value of `name`, trimmed.
fn first<'a>(entry: &'a Entry, name: &str) -> Option<&'a str> {
    entry
        .get(name)
        .and_then(|values| values.first())
        .map(|value| value.trim())
}

fn all<'a>(entry: &'a Entry, name: &str) -> Vec<&'a str> {
    entry
        .get(name)
        .map(|values| values.iter().map(|value| value.trim()).collect())
        .unwrap_or_default()
}

/// Whether a boolean AD field says `TRUE`.
fn is_true(entry: &Entry, name: &str) -> bool {
    first(entry, name).is_some_and(|value| value.eq_ignore_ascii_case("TRUE"))
}

/// The LDAP syntax OID for an AD attribute, from its `oMSyntax`.
///
/// `attributeSyntax` alone is misleading and must not be trusted: AD writes `2.5.5.10` on
/// `objectGUID`, which reads as GeneralizedTime, while `oMSyntax: 4` says octet string - and an
/// octet string is what a GUID is. Measured by reading the file, and by the first version of this
/// module getting it wrong.
///
/// `oMSyntax: 127` is the "object" escape: what the value really is depends on `oMObjectClass`, and
/// a distinguished name is the only one this server meets (a DN carries
/// `2a864886f71401010101`).
///
/// The fallback is octet string, which is what AD does with everything it does not interpret: an
/// attribute compared as bytes matches less than one compared as text, never more.
fn ldap_syntax(om_syntax: Option<&str>, om_object_class: Option<&str>) -> &'static str {
    match om_syntax {
        Some("1") => "1.3.6.1.4.1.1466.115.121.1.7", // Boolean
        Some("2" | "10" | "65") => "1.3.6.1.4.1.1466.115.121.1.27", // Integer, ENUMERATED, LargeInteger
        Some("6") => "1.3.6.1.4.1.1466.115.121.1.38",               // OID
        Some("18") => "1.3.6.1.4.1.1466.115.121.1.36",              // NumericString
        Some("19") => "1.3.6.1.4.1.1466.115.121.1.44",              // PrintableString
        Some("22") => "1.3.6.1.4.1.1466.115.121.1.26",              // IA5String
        Some("23") => "1.3.6.1.4.1.1466.115.121.1.23",              // UTCTime
        Some("24") => "1.3.6.1.4.1.1466.115.121.1.24",              // GeneralizedTime
        Some("64") => "1.3.6.1.4.1.1466.115.121.1.15",              // Unicode
        Some("127") => {
            if om_object_class
                .is_some_and(|class| class.eq_ignore_ascii_case("2a864886f71401010101"))
            {
                "1.3.6.1.4.1.1466.115.121.1.12" // DN
            } else {
                "1.3.6.1.4.1.1466.115.121.1.40"
            }
        }
        _ => "1.3.6.1.4.1.1466.115.121.1.40", // OctetString
    }
}

/// The matching rules a syntax implies, as `(EQUALITY, ORDERING, SUBSTR)`.
///
/// From the syntax and not from AD's file, which carries none: AD decides by `oMSyntax` at runtime,
/// and an LDAP definition has to state it. A `DirectoryString` without `caseIgnoreMatch` is a schema
/// where `(sAMAccountName=admin)` does not find `Admin`, and one without `SUBSTR` is a schema where
/// `(cn=adm*)` does not find it either.
fn matching_rules(syntax: &str) -> (&'static str, Option<&'static str>, Option<&'static str>) {
    match syntax {
        "1.3.6.1.4.1.1466.115.121.1.12" => ("distinguishedNameMatch", None, None),
        "1.3.6.1.4.1.1466.115.121.1.15" => {
            ("caseIgnoreMatch", None, Some("caseIgnoreSubstringsMatch"))
        }
        "1.3.6.1.4.1.1466.115.121.1.44" => {
            ("caseIgnoreMatch", None, Some("caseIgnoreSubstringsMatch"))
        }
        "1.3.6.1.4.1.1466.115.121.1.36" => (
            "numericStringMatch",
            None,
            Some("numericStringSubstringsMatch"),
        ),
        "1.3.6.1.4.1.1466.115.121.1.27" => ("integerMatch", Some("integerOrderingMatch"), None),
        "1.3.6.1.4.1.1466.115.121.1.7" => ("booleanMatch", None, None),
        "1.3.6.1.4.1.1466.115.121.1.24" => (
            "generalizedTimeMatch",
            Some("generalizedTimeOrderingMatch"),
            None,
        ),
        "1.3.6.1.4.1.1466.115.121.1.23" => (
            "generalizedTimeMatch",
            Some("generalizedTimeOrderingMatch"),
            None,
        ),
        "1.3.6.1.4.1.1466.115.121.1.38" => ("objectIdentifierMatch", None, None),
        _ => ("octetStringMatch", None, None),
    }
}

/// The `attributetype` definitions of the whole file, one per line.
#[must_use]
pub fn attribute_types(ldf: &str) -> String {
    let mut out = String::new();
    for entry in entries(ldf) {
        let Some(oid) = first(&entry, "attributeid") else {
            continue;
        };
        let Some(name) = first(&entry, "ldapdisplayname") else {
            continue;
        };
        let syntax = ldap_syntax(first(&entry, "omsyntax"), first(&entry, "omobjectclass"));
        let (equality, ordering, substr) = matching_rules(syntax);

        out.push_str(&format!("attributetype ( {oid} NAME '{name}'"));
        out.push_str(&format!(" EQUALITY {equality}"));
        if let Some(ordering) = ordering {
            out.push_str(&format!(" ORDERING {ordering}"));
        }
        if let Some(substr) = substr {
            out.push_str(&format!(" SUBSTR {substr}"));
        }
        out.push_str(&format!(" SYNTAX {syntax}"));
        if is_true(&entry, "issinglevalued") {
            out.push_str(" SINGLE-VALUE");
        }
        out.push_str(" )\n");
    }
    out
}

/// The `objectclass` definitions of the whole file, one per line.
#[must_use]
pub fn object_classes(ldf: &str) -> String {
    let mut out = String::new();
    for entry in entries(ldf) {
        let Some(oid) = first(&entry, "governsid") else {
            continue;
        };
        let Some(name) = first(&entry, "ldapdisplayname") else {
            continue;
        };
        let kind = match first(&entry, "objectclasscategory").unwrap_or("1") {
            "2" => "ABSTRACT",
            "3" => "AUXILIARY",
            // 1 is structural, and 0 - the "88 class" of AD's earliest schema - is one too: it has
            // instances of its own, which an abstract class does not.
            _ => "STRUCTURAL",
        };
        out.push_str(&format!("objectclass ( {oid} NAME '{name}'"));
        if let Some(sup) = first(&entry, "subclassof")
            && !sup.is_empty()
            && !sup.eq_ignore_ascii_case("top")
        {
            out.push_str(&format!(" SUP {sup}"));
        } else {
            out.push_str(" SUP top");
        }
        out.push_str(&format!(" {kind}"));

        let mut must = all(&entry, "mustcontain");
        must.extend(all(&entry, "systemmustcontain"));
        let mut may = all(&entry, "maycontain");
        may.extend(all(&entry, "systemmaycontain"));
        push_list(&mut out, "MUST", &must);
        push_list(&mut out, "MAY", &may);

        let mut aux = all(&entry, "auxiliaryclass");
        aux.extend(all(&entry, "systemauxiliaryclass"));
        push_list(&mut out, "AUXCLASS", &aux);
        out.push_str(" )\n");
    }
    out
}

/// Appends `KEYWORD value` or `KEYWORD ( a $ b )`, skipping an empty list.
fn push_list(out: &mut String, keyword: &str, values: &[&str]) {
    let mut values: Vec<&str> = values
        .iter()
        .copied()
        .filter(|value| !value.is_empty())
        .collect();
    values.sort_unstable();
    values.dedup();
    match values.len() {
        0 => {}
        1 => out.push_str(&format!(" {keyword} {}", values[0])),
        _ => out.push_str(&format!(" {keyword} ( {} )", values.join(" $ "))),
    }
}

/// Both vocabularies, ready for [`crate::schema::Schema::extend`].
#[must_use]
pub fn vocabulary() -> String {
    let mut text = attribute_types(ATTRIBUTES_LDF);
    text.push_str(&object_classes(CLASSES_LDF));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_published_files_are_what_they_claim_to_be() {
        let attributes = attribute_types(ATTRIBUTES_LDF);
        let classes = object_classes(CLASSES_LDF);
        let attribute_count = attributes.lines().count();
        let class_count = classes.lines().count();
        assert!(
            attribute_count > 1200,
            "the attribute file holds {attribute_count} definitions, which is not AD's schema"
        );
        assert!(
            class_count > 200,
            "the class file holds {class_count} definitions, which is not AD's schema"
        );
    }

    /// The definitions an AD client asks for, by the numbers AD publishes.
    #[test]
    fn the_definitions_carry_ad_s_oids_and_syntaxes() {
        let attributes = attribute_types(ATTRIBUTES_LDF);
        for (name, oid, syntax) in [
            (
                "objectSid",
                "1.2.840.113556.1.4.146",
                "1.3.6.1.4.1.1466.115.121.1.40",
            ),
            (
                "objectGUID",
                "1.2.840.113556.1.4.2",
                "1.3.6.1.4.1.1466.115.121.1.40",
            ),
            (
                "sAMAccountName",
                "1.2.840.113556.1.4.221",
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
            (
                "primaryGroupID",
                "1.2.840.113556.1.4.98",
                "1.3.6.1.4.1.1466.115.121.1.27",
            ),
            (
                "dNSHostName",
                "1.2.840.113556.1.4.619",
                "1.3.6.1.4.1.1466.115.121.1.15",
            ),
        ] {
            let line = attributes
                .lines()
                .find(|line| line.contains(&format!("NAME '{name}'")))
                .unwrap_or_else(|| panic!("{name} is missing from the vocabulary"));
            assert!(line.contains(oid), "{name} has the wrong OID: {line}");
            assert!(line.contains(syntax), "{name} has the wrong syntax: {line}");
            assert!(
                line.contains("EQUALITY"),
                "{name} has no matching rule, so a filter on it compares bytes: {line}"
            );
        }
    }

    /// `domainDNS` attaches `samDomain`, and not one attribute of AD's domain object is listed on it.
    #[test]
    fn a_class_keeps_the_auxiliary_classes_ad_attaches_to_it() {
        let classes = object_classes(CLASSES_LDF);
        let line = classes
            .lines()
            .find(|line| line.contains("NAME 'domainDNS'"))
            .expect("domainDNS is in AD's class list");
        assert!(
            line.contains("AUXCLASS samDomain"),
            "systemAuxiliaryClass became AUXCLASS: {line}"
        );
        assert!(
            !line.contains("objectSid"),
            "objectSid reaches the class through samDomain, not by being listed: {line}"
        );
    }

    /// The whole vocabulary parses into a schema, on top of the core one.
    #[test]
    fn the_vocabulary_parses_into_a_schema() {
        let mut schema = crate::schema::Schema::core();
        // `replace`, not `extend`: AD's reading of a name wins over the core one, which is what a
        // domain controller is - `info` is AD's `info`, not this server's.
        schema
            .replace(&vocabulary())
            .expect("AD's own definitions parse");
        let (_, may) = schema
            .allowed_attributes("domainDNS")
            .expect("the class is known");
        assert!(
            may.contains("objectsid") && may.contains("ms-ds-machineaccountquota"),
            "the domain object permits what samDomain permits: {may:?}"
        );
    }
}
