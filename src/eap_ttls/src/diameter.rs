//! diameter.rs - RFC 3588 Diameter AVP encoding for EAP-TTLS inner PAP.

/// Encode a single Diameter AVP with Mandatory flag (0x40) set.
pub fn encode_avp(code: u32, data: &[u8]) -> Vec<u8> {
    let mut avp = Vec::new();
    // AVP Code (4 octets, big-endian)
    avp.extend_from_slice(&code.to_be_bytes());
    // AVP Flags (1 octet): Mandatory = 0x40
    avp.push(0x40);
    // AVP Length (3 octets, big-endian) = 8 header bytes + payload length
    let len = (8 + data.len()) as u32;
    let len_be = len.to_be_bytes();
    avp.extend_from_slice(&len_be[1..4]);
    // AVP Data
    avp.extend_from_slice(data);
    // Padding to 4-octet boundary
    let pad = (4 - (avp.len() % 4)) % 4;
    for _ in 0..pad {
        avp.push(0);
    }
    avp
}

/// Build combined User-Name and User-Password AVPs for inner PAP.
pub fn build_pap_avps(username: &str, password: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    // AVP Code 1: User-Name
    buf.extend_from_slice(&encode_avp(1, username.as_bytes()));
    // AVP Code 2: User-Password
    buf.extend_from_slice(&encode_avp(2, password.as_bytes()));
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_avp() {
        let avp = encode_avp(1, b"test");
        assert_eq!(avp.len(), 12); // 8 header + 4 data = 12 (multiple of 4)
        assert_eq!(&avp[0..4], &[0, 0, 0, 1]); // Code 1
        assert_eq!(avp[4], 0x40); // Flags: Mandatory
        assert_eq!(&avp[5..8], &[0, 0, 12]); // Length 12
        assert_eq!(&avp[8..12], b"test");
    }

    #[test]
    fn test_padding() {
        let avp = encode_avp(2, b"pass"); // 8+4 = 12
        assert_eq!(avp.len(), 12);
        let avp2 = encode_avp(2, b"pwd"); // 8+3 = 11 -> padded to 12
        assert_eq!(avp2.len(), 12);
        assert_eq!(&avp2[5..8], &[0, 0, 11]); // length field reports 11
        assert_eq!(avp2[11], 0); // padding byte is 0
    }
}
