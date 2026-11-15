# AD's own schema, as Microsoft publishes it

`classes.ldf` and `attributes.ldf` are the schema Microsoft ships for AD DS
(`AD_DS_Schema`, the class and attribute lists behind
<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/>). They are LDIF: one entry
per class or attribute, with the attribute IDs, the LDAP display names, the syntaxes and the
`systemMustContain`/`systemMayContain`/`systemAuxiliaryClass` lists.

They are here as **data, not documentation**: `src/ad_vocabulary.rs` reads them at start and derives
the RFC 4512 definitions this server enforces and publishes. That is the point - a directory that
claims to be AD-compatible is judged by AD's schema, and a hand-written paraphrase of it is a claim
nobody can check. The previous version of this repository had one, and checking it found eight
attribute OIDs that disagreed with these files (`objectGUID` and `objectSid` held each other's
number, and `container` was the class OID of something else).

Microsoft's notice at the top of each file permits distributing the schema "in your implementations
using this software ... as necessary to properly document the implementation", which is what this is.

The two files are re-encoded from the publication's cp1252 to UTF-8 and their CRLF line endings are
normalised, because `include_str!` refuses anything else. That is the only transformation: not one
character of a definition is edited, and the notice Microsoft puts at the top of each file is kept
with it. If a newer publication of the schema is wanted, the files are
replaced whole and the tests in `src/ad_vocabulary.rs` say whether the vocabulary still parses and
still validates this server's own bootstrap.
