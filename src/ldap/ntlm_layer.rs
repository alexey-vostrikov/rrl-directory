//! The NTLM security layer, which is what a Windows LDAP client demands after an NTLM bind.
//!
//! An NTLM bind that completes without a layer is refused by `wldap32` even though the password was
//! right: `NetSetup.log` says `NetpLdapBind: ldap_bind failed on dc1.ad.example.com: 53: Unwilling To
//! Perform` while this server has just answered `success`, and the join ends at `0x3eb`. The result
//! code is produced by the client, not sent by the server - it is the verdict of a security package
//! that negotiated `SIGN | SEAL | ALWAYS_SIGN` and was then handed a connection it cannot protect.
//!
//! So this module is the layer: per-message integrity and confidentiality exactly as [MS-NLMP]
//! 3.4.4.2 defines them, once per direction, on the session key the authentication produced.
//!
//! # What a protected message is
//!
//! ```text
//! 16 octets                  the signature: 01 00 00 00, the checksum, the sequence number
//! n octets                   the message - in the clear when only SIGN was negotiated, RC4-encrypted
//!                            when SEAL was
//! ```
//!
//! The message and the checksum share one RC4 stream, and **the message comes first**: the payload
//! consumes the first `n` octets of the keystream and the checksum the eight after them. This is the
//! opposite of the order [MS-NLMP] 3.4.4.2 is usually read as, and it is why this module was wrong
//! for a while: with the checksum taking the first eight octets the signature never verified, which
//! looks like a wrong key rather than a wrong order. Measured on the stand - a `wldap32` frame
//! decrypted to a BER `SEQUENCE` with the stream taken from octet zero, and its checksum matched
//! `HMAC-MD5(signing key, seq || plaintext)` only when masked with the stream's octets 145..153.
//!
//! # Why the keys are derived here and not taken from the acceptor
//!
//! `smb_server::NtlmMac` computes the same signature, but it keeps its RC4 state private and applies
//! it only to the checksum, which is right for SMB signing and not enough for sealing. The derivation
//! is four lines of [MS-NLMP] 3.4.5.2/3.4.5.3 and it is written out here rather than duplicated from
//! memory: the magic constants are the whole of the difference between the two directions, and a
//! signer that used the wrong one would verify nothing.

use rc4::{KeyInit, Rc4, StreamCipher};

/// `SIGNKEY`: the key a signature is computed with, per direction ([MS-NLMP] 3.4.5.2).
const SIGN_MAGIC: (&[u8], &[u8]) = (
    b"session key to client-to-server signing key magic constant\0",
    b"session key to server-to-client signing key magic constant\0",
);

/// `SEALKEY`: the key the RC4 stream is seeded with, per direction ([MS-NLMP] 3.4.5.3).
const SEAL_MAGIC: (&[u8], &[u8]) = (
    b"session key to client-to-server sealing key magic constant\0",
    b"session key to server-to-client sealing key magic constant\0",
);

/// `NTLMSSP_NEGOTIATE_SIGN`.
const NEGOTIATE_SIGN: u32 = 0x0000_0010;
/// `NTLMSSP_NEGOTIATE_SEAL`.
const NEGOTIATE_SEAL: u32 = 0x0000_0020;
/// `NTLMSSP_NEGOTIATE_128`.
const NEGOTIATE_128: u32 = 0x2000_0000;
/// `NTLMSSP_NEGOTIATE_56`.
const NEGOTIATE_56: u32 = 0x8000_0000;
/// `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY`.
const NEGOTIATE_EXTENDED: u32 = 0x0008_0000;
/// `NTLMSSP_NEGOTIATE_KEY_EXCH`.
const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;

/// The length of a signature: [MS-NLMP] `NTLMSSP_MESSAGE_SIGNATURE` with extended session security.
pub const SIGNATURE_LEN: usize = 16;

/// Which side is sealing, and therefore which pair of keys applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Keys for messages this client sends and we read.
    ClientToServer,
    /// Keys for messages we send and this client reads.
    ServerToClient,
}

/// One direction of the NTLM security layer.
pub struct NtlmLayer {
    signing_key: [u8; 16],
    /// The RC4 stream, present exactly when `NTLMSSP_NEGOTIATE_KEY_EXCH` was agreed.
    stream: Option<Rc4>,
    /// Whether the payload travels encrypted (`SEAL`) or in the clear with a signature (`SIGN`).
    sealing: bool,
    seq: u32,
}

impl std::fmt::Debug for NtlmLayer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The keys are never printed: this type ends up in a session's `Debug` the moment anything
        // containing it does.
        formatter
            .debug_struct("NtlmLayer")
            .field("sealing", &self.sealing)
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl NtlmLayer {
    /// The layer for one direction, or `None` when the negotiated flags carry no protection.
    ///
    /// `None` is the honest answer for a client that asked for neither signing nor sealing: a layer
    /// invented for it would protect messages nobody asked to have protected, and the flags are the
    /// only statement either side makes about what runs on the connection.
    pub fn new(flags: u32, session_key: &[u8; 16], direction: Direction) -> Option<Self> {
        if flags & NEGOTIATE_EXTENDED == 0 || flags & (NEGOTIATE_SIGN | NEGOTIATE_SEAL) == 0 {
            return None;
        }
        let (sign_magic, seal_magic) = match direction {
            Direction::ClientToServer => (SIGN_MAGIC.0, SEAL_MAGIC.0),
            Direction::ServerToClient => (SIGN_MAGIC.1, SEAL_MAGIC.1),
        };
        let sealing = flags & NEGOTIATE_SEAL != 0;
        // The sealing key is shorter when 128-bit keys were not agreed, and the short key is a
        // prefix of the long one - not a truncation of the *derived* key.
        let seal_len = if flags & NEGOTIATE_128 != 0 {
            16
        } else if flags & NEGOTIATE_56 != 0 {
            7
        } else {
            5
        };
        let sealing_key = digest(&[&session_key[..seal_len], seal_magic]);
        // With key exchange the session key is exported already and no further derivation happens;
        // without it the sealing key *is* the session key and the stream is seeded from it. Either
        // way the stream is needed only when sealing.
        let stream = (sealing && flags & NEGOTIATE_KEY_EXCH != 0)
            .then(|| Rc4::new_from_slice(&sealing_key).expect("RC4 accepts a 16-octet key"));
        Some(Self {
            signing_key: digest(&[session_key, sign_magic]),
            stream,
            sealing,
            seq: 0,
        })
    }

    /// Whether the payload is encrypted as well as signed.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_sealing(&self) -> bool {
        self.sealing
    }

    /// The next sequence number this direction will use.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// A message and its signature, ready for the wire.
    ///
    /// The checksum is taken over the plaintext and consumes the first eight octets of the RC4
    /// stream; the payload - encrypted when sealing - consumes the rest. Both halves use one stream,
    /// and that is the whole reason this is one function rather than two.
    pub fn protect(&mut self, message: &[u8]) -> Vec<u8> {
        let mut payload = message.to_vec();
        if self.sealing
            && let Some(stream) = self.stream.as_mut()
        {
            stream.apply_keystream(&mut payload);
        }
        let mut checksum = self.checksum(message);
        if let Some(stream) = self.stream.as_mut() {
            stream.apply_keystream(&mut checksum);
        }
        let seq = self.seq.to_le_bytes();
        self.seq = self.seq.wrapping_add(1);

        let mut out = Vec::with_capacity(SIGNATURE_LEN + payload.len());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&checksum);
        out.extend_from_slice(&seq);
        out.extend_from_slice(&payload);
        out
    }

    /// The message inside a protected frame, or why it is not one.
    ///
    /// The order is forced by the algorithm: the payload is decrypted first (the RC4 stream has to
    /// advance past the checksum's eight octets before it can), then the checksum is recomputed over
    /// the plaintext and compared. A frame whose payload does not decrypt to what its signature
    /// covers is refused, and the sequence number does not advance for it.
    pub fn unprotect(&mut self, frame: &[u8]) -> Result<Vec<u8>, String> {
        if frame.len() < SIGNATURE_LEN {
            return Err(format!(
                "a protected message is at least {SIGNATURE_LEN} octets and this one is {}",
                frame.len()
            ));
        }
        if frame[..4] != 1u32.to_le_bytes() {
            return Err(format!(
                "the signature opens with {:02x?}, which is not version 1",
                &frame[..4]
            ));
        }
        let received = &frame[4..12];
        let seq = u32::from_le_bytes([frame[12], frame[13], frame[14], frame[15]]);

        // The stream is consumed in the order the sender produced it - the payload first, then the
        // eight octets that mask the checksum. XOR is its own inverse, so the octets read here are
        // exactly what has to be applied to the computed checksum before the comparison.
        let mut payload = frame[SIGNATURE_LEN..].to_vec();
        let mut head = [0u8; 8];
        if self.sealing
            && let Some(stream) = self.stream.as_mut()
        {
            stream.apply_keystream(&mut payload);
            stream.apply_keystream(&mut head);
        }

        let mut expected = self.checksum_at(seq, &payload);
        for (byte, mask) in expected.iter_mut().zip(head.iter()) {
            *byte ^= mask;
        }
        if !constant_time(&expected, received) {
            return Err(format!(
                "the signature does not cover this message at sequence {seq}"
            ));
        }
        self.seq = seq.wrapping_add(1);
        Ok(payload)
    }

    fn checksum(&self, message: &[u8]) -> [u8; 8] {
        self.checksum_at(self.seq, message)
    }

    fn checksum_at(&self, seq: u32, message: &[u8]) -> [u8; 8] {
        // RRL-7.6: the MAC comes from the crypto layer, the same one NTOWFv2 is keyed with.
        let digest = rrl_crypto::hmac_md5(&self.signing_key, &[&seq.to_le_bytes(), message]);
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[..8]);
        out
    }
}

/// `MD5(a || b || ...)`, which is how both keys are derived.
///
/// RRL-7.6: the digest comes from the crypto layer, so this file holds no primitive of its own.
fn digest(parts: &[&[u8]]) -> [u8; 16] {
    rrl_crypto::md5_parts(parts)
}

/// Comparison that takes the same time whatever it finds, so a signature cannot be walked one octet
/// at a time.
///
/// RRL-7.6: this was the eighth copy of the loop in the family, and the one my first sweep missed -
/// it is named `constant_time` and not `ct_eq`, so a search for the name found seven.
fn constant_time(left: &[u8], right: &[u8]) -> bool {
    rrl_crypto::ct_eq(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session key of the shape a real exchange produces, and flags with everything on.
    fn key() -> [u8; 16] {
        let mut key = [0u8; 16];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17).wrapping_add(3);
        }
        key
    }

    fn flags() -> u32 {
        NEGOTIATE_EXTENDED | NEGOTIATE_SIGN | NEGOTIATE_SEAL | NEGOTIATE_KEY_EXCH | NEGOTIATE_128
    }

    /// Two ends of one direction: what one protects, the other reads.
    #[test]
    fn a_sealed_message_is_the_message_the_other_end_sealed() {
        let mut sender = NtlmLayer::new(flags(), &key(), Direction::ServerToClient)
            .expect("signing and sealing are negotiated");
        let mut receiver =
            NtlmLayer::new(flags(), &key(), Direction::ServerToClient).expect("the same flags");

        for (seq, message) in [
            (0u32, &b"the first answer"[..]),
            (1, b""),
            (2, &[0u8; 300][..]),
        ] {
            assert_eq!(sender.seq(), seq, "the sender counts its own messages");
            let frame = sender.protect(message);
            assert_eq!(&frame[..4], &1u32.to_le_bytes(), "version 1");
            assert_eq!(&frame[12..16], &seq.to_le_bytes(), "the sequence travels");
            if !message.is_empty() {
                // Not asserted for the empty message: sealing nothing leaves nothing, and what the
                // check is for is that a payload of substance is not readable on the wire.
                assert_ne!(
                    &frame[SIGNATURE_LEN..],
                    message,
                    "a sealed payload is not the plaintext on the wire"
                );
            }
            assert_eq!(
                receiver.unprotect(&frame).expect("the other end opens it"),
                message
            );
            assert_eq!(receiver.seq(), seq.wrapping_add(1));
        }
    }

    /// The two directions use different keys: a frame sealed one way must not open the other way,
    /// or a message the server sent could be replayed at the server.
    #[test]
    fn the_two_directions_do_not_open_each_others_messages() {
        let mut server = NtlmLayer::new(flags(), &key(), Direction::ServerToClient).expect("layer");
        let mut client = NtlmLayer::new(flags(), &key(), Direction::ClientToServer).expect("layer");
        let frame = server.protect(b"an answer");
        assert!(
            client.unprotect(&frame).is_err(),
            "a message sealed with the server's key must not verify with the client's"
        );
    }

    /// A frame whose payload was altered is refused, and the sequence number stays where it was: a
    /// receiver that had counted the failed frame would refuse the next good one.
    #[test]
    fn an_altered_frame_is_refused_and_does_not_advance_the_sequence() {
        let mut sender = NtlmLayer::new(flags(), &key(), Direction::ServerToClient).expect("layer");
        let mut receiver =
            NtlmLayer::new(flags(), &key(), Direction::ServerToClient).expect("layer");
        let mut frame = sender.protect(b"a message of some length");
        let last = frame.len() - 1;
        frame[last] ^= 0xff;
        assert!(receiver.unprotect(&frame).is_err());
        assert_eq!(receiver.seq(), 0, "the refused frame did not count");

        let good = sender.protect(b"the next one");
        assert_eq!(
            receiver.unprotect(&good).expect("opens"),
            b"the next one".to_vec()
        );
    }

    /// Integrity only: the payload travels in the clear and is still signed.
    #[test]
    fn a_signed_message_travels_in_the_clear() {
        let only_sign = NEGOTIATE_EXTENDED | NEGOTIATE_SIGN | NEGOTIATE_KEY_EXCH | NEGOTIATE_128;
        let mut sender =
            NtlmLayer::new(only_sign, &key(), Direction::ServerToClient).expect("layer");
        let mut receiver =
            NtlmLayer::new(only_sign, &key(), Direction::ServerToClient).expect("layer");
        let frame = sender.protect(b"in the clear");
        assert_eq!(&frame[SIGNATURE_LEN..], b"in the clear");
        assert!(!sender.is_sealing());
        assert_eq!(
            receiver.unprotect(&frame).expect("opens"),
            b"in the clear".to_vec()
        );
    }

    /// A client that negotiated neither signing nor sealing gets no layer: protecting a connection
    /// nobody asked to have protected is a change of the terms.
    #[test]
    fn no_protection_negotiated_is_no_layer() {
        assert!(NtlmLayer::new(NEGOTIATE_EXTENDED, &key(), Direction::ClientToServer).is_none());
        assert!(NtlmLayer::new(NEGOTIATE_SIGN, &key(), Direction::ClientToServer).is_none());
    }

    /// The bytes below are a `wldap32` frame, captured on the stand from the first `Search` after an
    /// NTLM bind - the message this layer could not open for a whole session because it expected the
    /// checksum's keystream before the message's. Kept as a fixture rather than a re-derived one: a
    /// test that seals with the same code it verifies with cannot see the order at all.
    const WLDAP32_FRAME: &[u8] = &[
        0x01, 0x00, 0x00, 0x00, 0x6f, 0x1d, 0xf2, 0x62, 0xc8, 0xba, 0x47, 0x90, 0x00, 0x00, 0x00,
        0x00, 0x58, 0x68, 0x55, 0x57, 0xd3, 0xc8, 0xed, 0xd4, 0x7c, 0x24, 0xda, 0x02, 0xfd, 0xe9,
        0x59, 0x1b, 0x1a, 0x8d, 0x5c, 0x2f, 0x90, 0xab, 0x69, 0xc6, 0x9c, 0x3b, 0xa7, 0xfd, 0x0b,
        0xa7, 0x71, 0xf4, 0xd5, 0x51, 0x7f, 0x3a, 0x2d, 0xd6, 0x49, 0xf2, 0x7e, 0x1b, 0xc7, 0xae,
        0x72, 0x63, 0xa6, 0x8a, 0x45, 0x7b, 0x91, 0xbf, 0xc1, 0x84, 0x99, 0x32, 0x60, 0xe1, 0x27,
        0x8f, 0x19, 0x9d, 0xff, 0x8c, 0xa3, 0xa0, 0x5e, 0xf6, 0xb8, 0xb6, 0x31, 0x1a, 0xb9, 0x5c,
        0x7f, 0x20, 0xc4, 0x55, 0x47, 0xf4, 0x7a, 0xb8, 0xbe, 0xfa, 0x88, 0x95, 0x58, 0x09, 0x6e,
        0x40, 0xdd, 0x75, 0x4c, 0x48, 0x6c, 0x72, 0x9d, 0xc0, 0x5d, 0x9f, 0x02, 0x1a, 0x31, 0xda,
        0xda, 0x2d, 0xea, 0x3f, 0x78, 0x99, 0x4f, 0x20, 0xc6, 0x5b, 0x22, 0xef, 0xed, 0xc9, 0x89,
        0xb7, 0x99, 0xa4, 0xd1, 0x4f, 0x44, 0x19, 0x74, 0xd9, 0xb4, 0xbb, 0x48, 0x07, 0x9c, 0xf9,
        0xbc, 0x61, 0xfc, 0xb1, 0xcc, 0xa1, 0x62, 0xd9, 0xc4, 0xc3, 0xea,
    ];

    #[test]
    fn the_frame_a_windows_client_actually_sent_opens() {
        let mut layer = NtlmLayer::new(
            0xe288_8235,
            &[
                0x6b, 0xd0, 0xbf, 0xf4, 0x8a, 0xd6, 0xc7, 0x5c, 0xc1, 0x7e, 0xb5, 0x2e, 0x1b, 0xd0,
                0xf5, 0xbb,
            ],
            Direction::ClientToServer,
        )
        .expect("these flags carry a layer");

        let message = layer
            .unprotect(WLDAP32_FRAME)
            .expect("the captured frame must open");
        assert_eq!(
            &message[..4],
            &[0x30, 0x84, 0x00, 0x00],
            "and open to the BER SEQUENCE it was"
        );
        let declared =
            u32::from_be_bytes([message[2], message[3], message[4], message[5]]) as usize;
        assert_eq!(
            declared + 6,
            message.len(),
            "the length in the header accounts for the octets that follow it"
        );
        assert_eq!(layer.seq(), 1, "and the sequence advances for it");
    }
}
