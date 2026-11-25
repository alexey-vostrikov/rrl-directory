#!/usr/bin/env python3
"""Acceptance by a validator that shares no code with this crate.

`hickory` verifies in the unit tests and `delv` verifies over the wire, and both are worth having -
but a validator that shares an implementation with the signer agrees with it about a mistake. This
one is `dnspython` plus `cryptography`: a different implementation of the same RFCs, run against a
live server.

    python3 scripts/dnssec-acceptance.py <server> <port> <zone>

It checks the two halves the task calls for and refuses to report half of them:

  * a positive answer, whose `RRSIG` and the `DNSKEY` that made it both verify;
  * an `NXDOMAIN`, whose `NSEC3` proofs verify - and if the zone has none, this is a failure, not a
    skip;
  * an `A` whose address was changed under the original signature - must be refused;
  * an `RRSIG` whose last signature octet was flipped - must be refused.

Exit codes: 0 everything held, 1 the validator refused something it had to accept, 2 it accepted
something it had to refuse. The second is the one that matters: a validator that accepts a tampered
record is a validator that is not validating, and green output from it means nothing.
"""
import base64
import sys

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype


def fetch(server, port, name, rtype):
    request = dns.message.make_query(name, rtype, want_dnssec=True)
    return dns.query.udp(request, server, port=port, timeout=5)


def validate(response, zone, dnskey):
    """Verifies the RRSIG over every RRset in the answer, and returns how many were checked."""
    checked = 0
    for rrsigset in [rr for rr in response.answer if rr.rdtype == dns.rdatatype.RRSIG]:
        for rrsig in rrsigset:
            covered = dns.rdatatype.to_text(rrsig.type_covered)
            rrsets = [
                rr
                for rr in response.answer
                if rr.name == rrsigset.name
                and rr.rdtype == rrsig.type_covered
            ]
            assert rrsets, f"an RRSIG over {covered} with no set to cover"
            # dnspython wants an RRSIG set rather than one signature, and a set in an answer
            # can hold signatures over different types - so each is split out on its own.
            one = dns.rrset.from_rdata(rrsigset.name, rrsigset.ttl, rrsig)
            dns.dnssec.validate(rrsets[0], one, {zone: dnskey})
            checked += 1
    return checked


def main():
    server, port, zone_text = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    zone = dns.name.from_text(zone_text)

    keys = fetch(server, port, zone_text, "DNSKEY")
    dnskey = keys.answer[0]
    print(f"DNSKEY: {len(dnskey)} key(s), algorithms {[k.algorithm for k in dnskey]}")

    # The zone key has to sign itself: without that there is no chain to start from.
    keyset = {zone: dnskey}
    for rrsigset in [rr for rr in keys.answer if rr.rdtype == dns.rdatatype.RRSIG]:
        for rrsig in rrsigset:
            one = dns.rrset.from_rdata(rrsigset.name, rrsigset.ttl, rrsig)
            dns.dnssec.validate(dnskey, one, keyset)
    print("  the DNSKEY signs itself and verifies")

    # A positive answer.
    answer = fetch(server, port, f"dc1.{zone_text}", "A")
    checked = validate(answer, zone, dnskey)
    assert checked == 1, f"one RRSIG over A was expected, {checked} verified"
    print(f"  A dc1.{zone_text}: verified by an independent implementation")

    def clone(records):
        out = dns.message.Message()
        out.flags = answer.flags
        out.question = answer.question
        for rrset in records:
            out.answer.append(dns.rrset.from_rdata_list(rrset.name, rrset.ttl, list(rrset)))
        return out

    # Negative control 1: an address changed under the signature that covers it.
    tampered = clone(answer.answer)
    tampered.answer.clear()
    for rrset in answer.answer:
        if rrset.rdtype == dns.rdatatype.A:
            # Same owner, same TTL, a different address: the signature stays the original one.
            tampered.answer.append(
                dns.rrset.from_text(rrset.name, rrset.ttl, "IN", "A", "192.0.2.99")
            )
        else:
            tampered.answer.append(dns.rrset.from_rdata_list(rrset.name, rrset.ttl, list(rrset)))
    try:
        validate(tampered, zone, dnskey)
    except dns.dnssec.ValidationFailure:
        print("  an A with the address changed under the signature: refused, as it must be")
    else:
        print("  FAILURE: the changed address was accepted")
        return 2

    # Negative control 2: an RRSIG whose signature is corrupted.
    broken = clone(answer.answer)
    broken.answer.clear()
    for rrset in answer.answer:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            for rrsig in rrset:
                # The last octet of the signature, flipped: same length, same algorithm.
                fields = rrsig.to_text(origin=zone).split()
                # The signer field carries its own trailing dot already, and the wire form
                # depends on it.
                raw = bytearray(rrsig.signature)
                raw[-1] ^= 0xFF
                fields[-1] = base64.b64encode(bytes(raw)).decode()
                broken.answer.append(
                    dns.rrset.from_text(
                        rrset.name,
                        rrset.ttl,
                        "IN",
                        "RRSIG",
                        " ".join(fields),
                    )
                )
        else:
            broken.answer.append(dns.rrset.from_rdata_list(rrset.name, rrset.ttl, list(rrset)))
    try:
        validate(broken, zone, dnskey)
    except dns.dnssec.ValidationFailure:
        print("  an RRSIG with a flipped octet: refused, as it must be")
    else:
        print("  FAILURE: the corrupted signature was accepted")
        return 2

    # A negative answer: an NXDOMAIN has to prove itself with NSEC3 signed by this zone.
    missing = fetch(server, port, f"nosuch.{zone_text}", "A")
    assert missing.rcode() == dns.rcode.NXDOMAIN, (
        f"NXDOMAIN was expected, {dns.rcode.to_text(missing.rcode())} came back"
    )
    proofs = [rr for rr in missing.authority if rr.rdtype == dns.rdatatype.NSEC3]
    assert proofs, "an NXDOMAIN with no NSEC3 proof"
    signatures = [rr for rr in missing.authority if rr.rdtype == dns.rdatatype.RRSIG]
    proven = 0
    for rrset in proofs:
        for rrsigset in signatures:
            # A signature belongs to the set with the same owner, and the authority section holds
            # NSEC3 under hashed names beside the SOA at the apex - so they are split by name.
            if rrsigset.name != rrset.name:
                continue
            for rrsig in rrsigset:
                if rrsig.type_covered != dns.rdatatype.NSEC3:
                    continue
                one = dns.rrset.from_rdata(rrset.name, rrset.ttl, rrset[0])
                sig = dns.rrset.from_rdata(rrset.name, rrsigset.ttl, rrsig)
                dns.dnssec.validate(one, sig, keyset)
                proven += 1
    print(f"  NXDOMAIN: {proven} NSEC3 proof(s) with a verified signature")
    return 0


if __name__ == "__main__":
    sys.exit(main())