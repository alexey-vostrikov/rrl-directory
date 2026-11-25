#!/usr/bin/env python3
"""Build a zone file from what the server answers on the wire, for a third-party validator.

`ldns-verify-zone` and `dnssec-verify` read a zone file, and this server denies AXFR by design -
the records are the directory's and a transfer would be a second, unreplicated copy. So the zone is
reconstructed the way a client sees it: the inventory of names and types comes from an LDIF export,
and every record, every `RRSIG` and the whole `NSEC3` chain come from queries against the live
server. Nothing here signs anything; it only asks and writes down the answers.

    rrl-directory --config ... --export-ldif /tmp/zone.ldif
    python3 scripts/zone-dump.py /tmp/zone.ldif ad.example.com 127.0.0.1 15353 > /tmp/ad.example.com.zone

The chain walk matters: `NSEC3` records live under hashed names nobody can guess, and the only way
to reach the next link is the `next hashed owner name` field of the one in hand. So it starts at an
`NXDOMAIN` for a name that cannot exist, takes the proofs it is given, and follows them round until
the chain closes. A chain that does not close within the number of links a zone can hold is an error
rather than a truncated file, because a truncated file passes a weaker check than a whole one.
"""
import base64
import sys

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype

# The types this server stores in its own name encoding rather than as wire RDATA. Everything else
# - the DNSSEC types above all - is kept as the octets that go on the wire, which is why those can be
# rendered straight from the bytes.
OWN = {
    dns.rdatatype.A,
    dns.rdatatype.AAAA,
    dns.rdatatype.NS,
    dns.rdatatype.CNAME,
    dns.rdatatype.PTR,
    dns.rdatatype.DNAME,
    dns.rdatatype.SOA,
    dns.rdatatype.MX,
    dns.rdatatype.SRV,
    dns.rdatatype.TXT,
}


def ldif_entries(path):
    """The `dn` and `dnsRecord` values of every entry, per [MS-DNSP]'s LDAP shape."""
    entries, current, key, buffer = [], None, None, None
    for line in open(path, encoding="utf-8"):
        if line.startswith(" "):  # a continuation of the previous value
            buffer += line[1:].rstrip("\n")
            continue
        if key is not None:
            if key == "dn":
                current["dn"] = buffer
            elif key == "dnsRecord":
                current["records"].append(base64.b64decode(buffer))
            key, buffer = None, None
        if line.startswith("\n") or not line.strip():
            if current is not None:
                entries.append(current)
                current = None
            continue
        if line.startswith("dn:"):
            current = {"dn": "", "records": []}
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key == "dnsRecord" and value.startswith(":"):
            value = value[1:]
        buffer = value.strip()
    if current is not None:
        entries.append(current)
    return entries


def read_name(data, at):
    """`DNS_COUNT_NAME`: a length, a label count, then the labels. Not the RFC 1035 wire form."""
    length = data[at]
    labels = data[at + 1]
    raw = data[at + 2 : at + 2 + length]
    parts, offset = [], 0
    for _ in range(labels):
        size = raw[offset]
        parts.append(raw[offset + 1 : offset + 1 + size].decode("ascii"))
        offset += 1 + size
    return (".".join(parts) + ".") if parts else ".", 2 + length


def to_wire(rtype, data):
    """The RDATA as it goes on the wire, so `dnspython` renders the text form."""
    if rtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
        return data
    if rtype in (dns.rdatatype.NS, dns.rdatatype.CNAME, dns.rdatatype.PTR, dns.rdatatype.DNAME):
        name, _ = read_name(data, 0)
        return dns.name.from_text(name).to_wire()
    if rtype == dns.rdatatype.SOA:
        primary, used = read_name(data, 20)
        admin, used2 = read_name(data, 20 + used)
        return data[:20] + dns.name.from_text(primary).to_wire() + dns.name.from_text(admin).to_wire()
    if rtype == dns.rdatatype.MX:
        exchange, _ = read_name(data, 2)
        return data[:2] + dns.name.from_text(exchange).to_wire()
    if rtype == dns.rdatatype.SRV:
        target, _ = read_name(data, 6)
        return data[:6] + dns.name.from_text(target).to_wire()
    if rtype == dns.rdatatype.TXT:
        count, rest, out = data[0], data[1:], b""
        for _ in range(count):
            size = rest[0]
            out += bytes([size]) + rest[1 : 1 + size]
            rest = rest[1 + size :]
        return out
    return data


def inventory(path, zone_text):
    """Every (`owner`, `type`) the zone holds, from the directory's own record values."""
    zone = dns.name.from_text(zone_text)
    zone_dn = "dc=%s,cn=RRLDNS,dc=DomainDnsZones,dc=ad,dc=example,dc=com" % zone_text
    suffix = "," + zone_dn
    rows = []
    for entry in ldif_entries(path):
        dn = entry["dn"]
        if not dn.startswith("dc=") or not dn.endswith(suffix):
            continue
        relative = dn[3 : -len(suffix)]
        if relative == "@":
            owner = zone
        else:
            owner = dns.name.from_text(f"{relative}.{zone_text}")
        for record in entry["records"]:
            rtype = int.from_bytes(record[2:4], "little")
            ttl = int.from_bytes(record[12:16], "big")
            declared = int.from_bytes(record[0:2], "little")
            rows.append((owner.derialize() if hasattr(owner, "derialize") else owner, rtype, ttl))
    return rows


def ask(server, port, name, rtype):
    request = dns.message.make_query(name, rtype, want_dnssec=True)
    request.flags |= dns.flags.AD
    return dns.query.udp(request, server, port=port, timeout=5)


def main():
    ldif, zone_text, server, port = (
        sys.argv[1],
        sys.argv[2],
        sys.argv[3],
        int(sys.argv[4]),
    )
    zone = dns.name.from_text(zone_text)

    lines = [f"$ORIGIN {zone_text}.", "$TTL 600"]
    seen = set()

    # `DNSKEY` is not a directory record: the zone publishes it from the signing key at read time,
    # so it is asked for rather than looked up - and without it `ldns-verify-zone` has no key to
    # check anything against and says so.
    # The same holds for `NSEC3PARAM`, which the zone states from its configuration rather than
    # storing. It is not decoration: BIND reads it to learn the hash parameters and answers
    # "no valid NSEC3 chain" for a zone that carries the chain but not this record.
    for asked in (dns.rdatatype.DNSKEY, dns.rdatatype.NSEC3PARAM):
        response = ask(server, port, zone, asked)
        for rrset in response.answer:
            for record in rrset:
                lines.append(
                    f"{rrset.name.to_text()}\t{rrset.ttl}\tIN\t"
                    f"{dns.rdatatype.to_text(rrset.rdtype)}\t{record.to_text()}"
                )

    for owner, rtype, _ttl in inventory(ldif, zone_text):
        # `RRSIG` rides with the set it covers, and `NSEC3` is walked as a chain below. Everything
        # else - `NSEC3PARAM` included, which BIND wants at the apex before it will check a chain -
        # is asked for by name and type.
        if rtype in (dns.rdatatype.RRSIG, dns.rdatatype.NSEC3):
            continue
        response = ask(server, port, owner, rtype)
        for rrset in response.answer:
            if rrset.rdtype != rtype or rrset.name != owner:
                continue
            for record in rrset:
                key = (owner, rtype, record.to_text())
                if key in seen:
                    continue
                seen.add(key)
                lines.append(
                    f"{owner.to_text()}\t{rrset.ttl}\tIN\t"
                    f"{dns.rdatatype.to_text(rtype)}\t{record.to_text()}"
                )
        for rrset in response.answer:
            if rrset.rdtype != dns.rdatatype.RRSIG:
                continue
            for record in rrset:
                if record.type_covered != rtype:
                    continue
                key = (owner, "RRSIG", record.to_text())
                if key in seen:
                    continue
                seen.add(key)
                lines.append(
                    f"{owner.to_text()}\t{rrset.ttl}\tIN\tRRSIG\t{record.to_text()}"
                )

    # The NSEC3 chain, followed from an NXDOMAIN round to itself.
    probe = ask(server, port, f"zzz-does-not-exist.{zone_text}", "A")
    assert probe.rcode() == dns.rcode.NXDOMAIN, "the probe name exists, so nothing can be walked"
    pending = [
        rr
        for rr in probe.authority
        if rr.rdtype == dns.rdatatype.NSEC3
    ]
    walked = 0
    while pending:
        rrset = pending.pop()
        if rrset.name in seen:
            continue
        seen.add(rrset.name)
        walked += 1
        assert walked < 4096, "the chain did not close: it is longer than a zone can be"
        for record in rrset:
            lines.append(
                f"{rrset.name.to_text()}\t{rrset.ttl}\tIN\tNSEC3\t{record.to_text()}"
            )
        response = ask(server, port, rrset.name, dns.rdatatype.NSEC3)
        for answered in response.answer:
            if answered.rdtype == dns.rdatatype.RRSIG:
                for record in answered:
                    lines.append(
                        f"{answered.name.to_text()}\t{answered.ttl}\tIN\tRRSIG\t{record.to_text()}"
                    )
            elif answered.rdtype == dns.rdatatype.NSEC3:
                for record in answered:
                    # `next` is the raw hash octets, and the owner name is their base32hex
                    # spelling - so it is read off the record rather than re-derived.
                    label = base64.b32hexencode(record.next).decode().rstrip("=").lower()
                    next_owner = dns.name.from_text(f"{label}.{zone_text}")
                    if next_owner not in seen:
                        follow = ask(server, port, next_owner, dns.rdatatype.NSEC3)
                        for link in follow.answer:
                            if link.rdtype == dns.rdatatype.NSEC3:
                                pending.append(link)

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
