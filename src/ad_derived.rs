//! The attributes AD fills in when it creates an object, and this server now does the same.
//!
//! They exist because AD's schema makes them **required on every entry**: `top` carries
//! `systemMustContain: objectClass, objectCategory, nTSecurityDescriptor, instanceType`
//! (`schema/ad/classes.ldf`). A directory that publishes AD's vocabulary and then writes an object
//! without them has published a schema it does not satisfy - which is what `schema: strict` said,
//! entry by entry, the first time the two were put together.
//!
//! # Written, not computed per read
//!
//! None of the three carries the `CONSTRUCTED` bit (`0x4` in `systemFlags`) that AD sets on the
//! attributes it computes per read, and all of them are in the partial attribute set: AD stores
//! them, replicates them and, for `objectCategory`, **indexes** them (`searchFlags: 1`).
//!
//! That is the distinction this module exists to respect. An attribute computed on read cannot be
//! indexed and cannot be filtered on; one written when the object is created is an ordinary value
//! with an ordinary index entry. `objectCategory` is AD's clearest case - nobody writes it by hand,
//! the DSA fills it in at `add`, and there is an index on it.
//!
//! What AD really does compute per read - `canonicalName`, `tokenGroups`, `sDRightsEffective`,
//! `msDS-PrincipalName`, `structuralObjectClass` - is `CONSTRUCTED` for a reason that is not the
//! cost of computing it: its inputs are other objects (an ancestor's name, a group's membership) or
//! the caller itself, so materialising it would need an invalidation the server does not have.
//!
//! # Written once, and never overwritten
//!
//! An entry that already carries one of these keeps it: a directory grown from an AD import arrives
//! with AD's own values, and replacing them would turn a faithful copy into this server's reading of
//! the same object.

use crate::model::{Attribute, Attributes};

/// `instanceType` of a naming-context head: `IT_WRITE`.
const IT_WRITE: u32 = 0x0000_0004;
/// `instanceType` of an ordinary object.
const IT_NONE: u32 = 0x0000_0000;

/// The attributes this module synthesises, lowercase.
pub const SYNTHESISED: [&str; 3] = ["objectcategory", "instancetype", "ntsecuritydescriptor"];

/// Whether `name` is one of them.
#[must_use]
pub fn is_synthesised(name: &str) -> bool {
    SYNTHESISED
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
}

/// The DN of the configuration partition, for the schema and description references.
fn configuration_dn(base_dn: &str) -> String {
    format!("cn=Configuration,{base_dn}")
}

/// `instanceType`: a naming-context head is writable here, everything else is an ordinary object.
///
/// AD's value is a bit field, and `4` on a head is the bit that says "this is a naming context". A
/// replica would set `8` instead, and `1` marks a constructed object; this server is neither.
#[must_use]
pub fn instance_type(dn: &str, base_dn: &str) -> u32 {
    let dn = dn.trim().to_ascii_lowercase();
    let base = base_dn.trim().to_ascii_lowercase();
    let configuration = configuration_dn(&base).to_ascii_lowercase();
    if dn == base || dn == configuration || dn == format!("cn=schema,{configuration}") {
        IT_WRITE
    } else {
        IT_NONE
    }
}

/// The attributes in [`synthesised`], by name: the three AD writes into every object it creates.
pub const MAINTAINED: [&str; 3] = ["objectCategory", "instanceType", "nTSecurityDescriptor"];

/// Whether `name` is one of the attributes the directory fills in rather than a client.
///
/// Asked by the schema check, which skips them among the required ones: they are `MUST` on AD's
/// `top` class, and a store written before this server wrote them - a seed, an import from
/// OpenLDAP - would otherwise be refused at start for the absence of a value no client may set.
/// A client that tries to write one is refused by AD too: `instanceType` and
/// `nTSecurityDescriptor` are maintained by the DSA, and `objectCategory` follows from the class.
#[must_use]
pub fn is_maintained(name: &str) -> bool {
    MAINTAINED
        .iter()
        .any(|maintained| maintained.eq_ignore_ascii_case(name))
}

/// The same, but only when the schema this server runs with publishes AD's vocabulary.
///
/// A plain directory - one configured without a realm, which loads only the core schema - has no
/// `objectCategory` for a client to ask about, and an entry carrying it is refused by that very
/// schema with "not allowed by any object class". The attributes belong to AD; writing them into a
/// store that does not describe AD is writing a shape its own schema rejects.
///
/// The schema is the authority rather than a flag in the configuration: what matters is whether the
/// attribute type is known, which is exactly the condition under which `check` accepts it.
#[must_use]
pub fn synthesised_for(
    schema: &crate::schema::Schema,
    dn: &str,
    attributes: &Attributes,
    base_dn: &str,
) -> Attributes {
    if schema.attribute("objectCategory").is_none() {
        return attributes.clone();
    }
    synthesised(dn, attributes, base_dn)
}

/// The entry's attributes with the ones AD would have filled in, for the ones it does not carry.
///
/// Called by every path that writes an entry, which is what makes the result an ordinary value: the
/// store holds it, the index has it, and a filter on `objectCategory` is a filter on a stored
/// attribute rather than a scan with a function called once per entry.
#[must_use]
pub fn synthesised(dn: &str, attributes: &Attributes, base_dn: &str) -> Attributes {
    let mut out = attributes.clone();

    if out.get("objectCategory").is_none()
        && let Some(classes) = out.get(crate::model::ATTR_OBJECT_CLASS)
        && let Some(category) = crate::ad_vocabulary::object_category(&classes.values, base_dn)
    {
        out = out.push(Attribute::single("objectCategory", &category));
    }

    if out.get("instanceType").is_none() {
        out = out.push(Attribute::single(
            "instanceType",
            &instance_type(dn, base_dn).to_string(),
        ));
    }

    if out.get("nTSecurityDescriptor").is_none() {
        out =
            out.push(Attribute::new("nTSecurityDescriptor", vec![security_descriptor()]).binary());
    }

    out
}

/// The same descriptor with only the portions a client asked for.
///
/// `LDAP_SERVER_SD_FLAGS_OID` (`MS-ADTS` 3.1.1.3.4.1.10) lets a client name which sections of a
/// security descriptor it wants: owner `1`, group `2`, DACL `4`, SACL `8`. A mask of zero means no
/// preference, and the whole descriptor is returned.
///
/// This server's descriptor carries a DACL and nothing else - no owner, no group, no SACL - so the
/// only thing the mask can change is whether that DACL is present. Stripping it is not deleting
/// bytes at the end: the header's `Dacl` offset has to become zero and `SE_DACL_PRESENT` has to come
/// off, because a receiver reads those two as the answer to "is a DACL here", and a descriptor that
/// claims one and has none is what makes a client report a malformed descriptor.
#[must_use]
pub fn security_descriptor_portions(descriptor: &[u8], mask: u32) -> Vec<u8> {
    const SE_DACL_PRESENT: u16 = 0x0004;
    const HEADER: usize = 20;
    /// `OWNER | GROUP | DACL | SACL`, the four sections `SD_FLAGS` numbers.
    const ALL: u32 = 0x0F;
    const DACL: u32 = 0x04;

    if descriptor.len() < HEADER {
        return descriptor.to_vec();
    }
    let wanted = if mask == 0 { ALL } else { mask };
    if wanted & DACL != 0 {
        return descriptor.to_vec();
    }
    let dacl_offset = u32::from_le_bytes([
        descriptor[16],
        descriptor[17],
        descriptor[18],
        descriptor[19],
    ]);
    if dacl_offset == 0 {
        return descriptor.to_vec();
    }
    let mut out = descriptor[..HEADER].to_vec();
    let control = u16::from_le_bytes([out[2], out[3]]) & !SE_DACL_PRESENT;
    out[2..4].copy_from_slice(&control.to_le_bytes());
    out[16..20].copy_from_slice(&0u32.to_le_bytes());
    out
}

/// A self-relative security descriptor with one DACL and two allow-ACEs.
///
/// MS-DTYP §2.4.6 lays the header out as: revision, `sbz1`, control flags, four offsets into the
/// body; and §2.4.5 the DACL as: revision, `sbz1`, size, ACE count, then the ACEs. Every offset is
/// measured from the start of the descriptor, and an offset of zero means "this part is absent" -
/// which is why a descriptor with no SACL is not the same bytes as one with an empty SACL.
///
/// The two ACEs: `Authenticated Users` (S-1-5-11) may read, and `Domain Admins` (the domain SID with
/// RID 512) has full control. Both are allow-ACEs of type `ACCESS_ALLOWED_ACE_TYPE` (0), and their
/// `AceSize` includes the four-octet header and the SID.
#[must_use]
pub fn security_descriptor() -> String {
    use base64::Engine as _;

    // `SE_SELF_RELATIVE | SE_DACL_PRESENT`: the offsets are relative, and a DACL follows.
    const SE_SELF_RELATIVE: u16 = 0x8000;
    const SE_DACL_PRESENT: u16 = 0x0004;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
    // `GENERIC_READ | GENERIC_EXECUTE` for an authenticated reader; `0xF01FF` is full control over a
    // directory object, which is what `Domain Admins` has on everything in a domain.
    const READ: u32 = 0x0012_0089;
    const FULL: u32 = 0x000F_01FF;

    /// `S-1-5-11`, `Authenticated Users`: revision 1, one sub-authority, authority 5, sub-authority 11.
    const AUTHENTICATED_USERS: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];

    /// A SID with the given RID under the domain, in the octets an ACE carries.
    fn domain_sid(rid: u32) -> Vec<u8> {
        // `S-1-5-21-<a>-<b>-<c>-<rid>`: revision, five sub-authorities, the six-octet NT authority,
        // then the four sub-authorities as little-endian words.
        let mut sid = vec![1u8, 5];
        sid.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
        for sub in [21u32, 1, 2, 3, rid] {
            sid.extend_from_slice(&sub.to_le_bytes());
        }
        sid
    }

    /// One allow-ACE.
    ///
    /// `AceSize` counts the **whole** ACE - the four-octet header, the mask and the SID - and the
    /// padding that keeps the next one aligned, because the next ACE starts after it. A size that
    /// stopped at the SID leaves the receiver reading an ACE four octets short, and the masks after
    /// it come out of the middle of a SID.
    fn ace(mask: u32, sid: &[u8]) -> Vec<u8> {
        // Header (type, flags, size) and the mask, then the SID.
        let unpadded = 4 + 4 + sid.len();
        let size = unpadded.next_multiple_of(4);
        let mut out = Vec::with_capacity(size);
        out.push(ACCESS_ALLOWED_ACE_TYPE);
        out.push(0); // AceFlags: no inheritance, no audit
        out.extend_from_slice(
            &u16::try_from(size)
                .expect("an ACE fits a half word")
                .to_le_bytes(),
        );
        out.extend_from_slice(&mask.to_le_bytes());
        out.extend_from_slice(sid);
        while out.len() < size {
            out.push(0);
        }
        out
    }

    let administrators = domain_sid(512);
    let aces = [ace(READ, &AUTHENTICATED_USERS), ace(FULL, &administrators)];

    let owner = administrators.clone();
    let group = administrators;

    let mut acl = Vec::new();
    acl.push(0x02); // ACL_REVISION
    acl.push(0); // Sbz1
    let acl_size = 8 + aces.iter().map(|ace| ace.len()).sum::<usize>();
    acl.extend_from_slice(
        &u16::try_from(acl_size)
            .expect("the ACL fits a half word")
            .to_le_bytes(),
    );
    acl.extend_from_slice(&u16::try_from(aces.len()).expect("two ACEs").to_le_bytes());
    // `Sbz2`: the ACL header is eight octets - revision, sbz1, size, count, sbz2 - and leaving it out
    // makes every ACE start two octets early, which is a descriptor a client reads as one ACE short
    // and with masks taken from the wrong place.
    acl.extend_from_slice(&[0, 0]);
    for ace in &aces {
        acl.extend_from_slice(ace);
    }

    // The header is twenty octets; the body follows in the order the offsets point at.
    let header = 20;
    let owner_at = header;
    let group_at = owner_at + owner.len();
    let dacl_at = group_at + group.len();

    let mut out = Vec::with_capacity(dacl_at + acl.len());
    out.push(0x01); // Revision
    out.push(0x00); // Sbz1
    out.extend_from_slice(&(SE_SELF_RELATIVE | SE_DACL_PRESENT).to_le_bytes());
    for offset in [owner_at, group_at, 0] {
        // Owner, group, SACL. The SACL is absent: offset zero is "no SACL", and an empty one would be
        // a different descriptor with different bytes.
        out.extend_from_slice(
            &u32::try_from(offset)
                .expect("an offset fits a word")
                .to_le_bytes(),
        );
    }
    out.extend_from_slice(
        &u32::try_from(dacl_at)
            .expect("an offset fits a word")
            .to_le_bytes(),
    );
    out.extend_from_slice(&owner);
    out.extend_from_slice(&group);
    out.extend_from_slice(&acl);

    base64::engine::general_purpose::STANDARD.encode(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes(names: &[&str]) -> Attributes {
        Attributes::new().push(Attribute::new(
            crate::model::ATTR_OBJECT_CLASS,
            names
                .iter()
                .map(|name| (*name).to_string())
                .collect::<Vec<_>>(),
        ))
    }

    #[test]
    fn only_a_naming_context_head_is_writable() {
        let base = "dc=ad,dc=example,dc=com";
        assert_eq!(instance_type(base, base), IT_WRITE);
        assert_eq!(
            instance_type("cn=Configuration,dc=ad,dc=example,dc=com", base),
            IT_WRITE
        );
        assert_eq!(
            instance_type("cn=schema,cn=configuration,dc=ad,dc=example,dc=com", base),
            IT_WRITE
        );
        assert_eq!(
            instance_type("cn=admin,ou=users,dc=ad,dc=example,dc=com", base),
            IT_NONE,
            "an ordinary object is not a naming context"
        );
    }

    #[test]
    fn the_attributes_follow_the_classes() {
        let base = "dc=ad,dc=example,dc=com";
        let attributes = synthesised(
            "cn=admin,ou=users,dc=ad,dc=example,dc=com",
            &classes(&["top", "person", "user"]),
            base,
        );

        let category = attributes
            .get("objectCategory")
            .expect("every object has one");
        assert!(
            category.values[0].starts_with("CN=Person,CN=Schema,CN=Configuration,"),
            "{}",
            category.values[0]
        );
        assert!(
            category.values[0].ends_with(base),
            "and it names this domain"
        );
        assert_eq!(
            attributes.get("instanceType").expect("every object").values[0],
            "0"
        );
        assert!(
            attributes
                .get("nTSecurityDescriptor")
                .expect("every object")
                .flags
                .binary,
            "a descriptor is octets, not text"
        );
    }

    /// A value an entry already carries is kept: a directory grown from an AD import has AD's own.
    #[test]
    fn an_existing_value_is_not_replaced() {
        let base = "dc=ad,dc=example,dc=com";
        let carried = classes(&["top", "user"]).push(Attribute::single(
            "objectCategory",
            "CN=Person,CN=Schema,CN=Configuration,DC=other,DC=example",
        ));
        let attributes = synthesised("cn=admin,ou=users,dc=ad,dc=example,dc=com", &carried, base);
        assert_eq!(
            attributes.get("objectCategory").expect("kept").values[0],
            "CN=Person,CN=Schema,CN=Configuration,DC=other,DC=example"
        );
    }

    /// The objects this server creates for itself pass AD's own schema.
    ///
    /// The shapes are taken from `provision`, not written here by hand: a test that built its own
    /// entries would pass while the server's own bootstrap was refused, which is how seventeen
    /// `ObjectClassViolation`s reached the stand with the whole suite green.
    #[test]
    fn the_server_s_own_bootstrap_passes_ad_s_schema() {
        let base = "dc=ad,dc=example,dc=com";
        let mut schema = crate::schema::Schema::core();
        crate::ad_schema::extend(&mut schema).expect("the AD vocabulary parses");

        let mut entries = crate::provision::Partition {
            base_dn: base.to_string(),
            dns_domain: "ad.example.com".to_string(),
            netbios: "AD".to_string(),
        }
        .entries();
        for dn in crate::provision::containers(base) {
            entries.push(crate::provision::container_entry(&dn));
        }

        let mut broken = Vec::new();
        for entry in &entries {
            let attributes = synthesised(entry.dn(), entry.attributes(), base);
            let entry = crate::model::Entry::new(entry.dn().to_string(), attributes);
            if let Err(violations) = schema.check(&entry) {
                for violation in violations {
                    broken.push(format!("{}: {}", entry.dn(), violation.detail));
                }
            }
        }
        assert!(
            broken.is_empty(),
            "the server's own bootstrap must pass AD's schema: {broken:#?}"
        );
    }

    /// The descriptor is a self-relative one whose offsets land where the parts really are.
    ///
    /// Written out rather than trusted: a descriptor whose offsets are wrong is one a Windows client
    /// refuses to parse, and it says so with `ERROR_INVALID_ACL` somewhere far from the cause.
    #[test]
    fn a_client_that_asks_for_the_dacl_alone_gets_it_alone() {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(security_descriptor())
            .expect("the descriptor is base64");

        // `4` is the DACL, and it is the only section this server puts in a descriptor.
        assert_eq!(
            security_descriptor_portions(&raw, 4),
            raw,
            "asking for the DACL must return the descriptor as it is"
        );

        // Asking for the owner alone means no DACL: the offset goes to zero and the present-bit
        // comes off, because a receiver reads those two as the answer to "is a DACL here".
        let stripped = security_descriptor_portions(&raw, 1);
        assert_eq!(stripped.len(), 20, "only the header is left");
        let control = u16::from_le_bytes([stripped[2], stripped[3]]);
        assert_eq!(control & 0x0004, 0, "SE_DACL_PRESENT has to come off");
        assert_eq!(
            u32::from_le_bytes([stripped[16], stripped[17], stripped[18], stripped[19]]),
            0,
            "the Dacl offset has to be zero"
        );

        // Zero is not "no sections": a control with an empty mask asks for no preference.
        assert_eq!(security_descriptor_portions(&raw, 0), raw);
    }

    #[test]
    fn the_security_descriptor_is_well_formed() {
        use base64::Engine as _;
        let encoded = security_descriptor();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .expect("base64");

        assert_eq!(bytes[0], 1, "revision 1");
        let control = u16::from_le_bytes([bytes[2], bytes[3]]);
        assert_eq!(control & 0x8000, 0x8000, "self-relative");
        assert_eq!(control & 0x0004, 0x0004, "a DACL is present");

        let offset = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        let owner_at = offset(4);
        let group_at = offset(8);
        let sacl_at = offset(12);
        let dacl_at = offset(16);
        assert_eq!(sacl_at, 0, "no SACL: offset zero, not an empty one");
        assert_eq!(owner_at, 20, "the owner starts where the header ends");
        assert_eq!(group_at, owner_at + 28, "S-1-5-21-a-b-c-512 is 28 octets");
        assert_eq!(dacl_at, group_at + 28);

        let acl = &bytes[dacl_at..];
        assert_eq!(acl[0], 2, "ACL_REVISION");
        let acl_size = usize::from(u16::from_le_bytes([acl[2], acl[3]]));
        let ace_count = u16::from_le_bytes([acl[4], acl[5]]);
        assert_eq!(ace_count, 2);
        assert_eq!(acl_size, acl.len(), "the DACL is the last part");
        assert_eq!(
            &acl[6..8],
            &[0, 0],
            "Sbz2 is there, so the ACEs start at eight"
        );

        // Walk the ACEs: the first is Authenticated Users with read, the second Domain Admins with
        // full control. A SID that is one octet short is a mask read out of the wrong place.
        let mut at = 8;
        let mut masks = Vec::new();
        for _ in 0..ace_count {
            assert_eq!(acl[at], 0, "ACCESS_ALLOWED_ACE_TYPE at {at}");
            let size = usize::from(u16::from_le_bytes([acl[at + 2], acl[at + 3]]));
            masks.push(u32::from_le_bytes(acl[at + 4..at + 8].try_into().unwrap()));
            assert_eq!(size % 4, 0, "an ACE is four-octet aligned");
            at += size;
        }
        assert_eq!(at, acl.len(), "the ACEs account for the whole DACL");
        assert_eq!(masks, vec![0x0012_0089, 0x000F_01FF]);
    }
}
