//! Helper functions for working with SNMP Engine Ids.
//!
//! Engine Ids are OctetStrings, of between 5 and 32 bytes length. All zeros and all FF values are
//! not allowed. There is a Text Convention for the interpretation of Engine IDs, defined in RFC3411.
//! At least some SNMP implementations will not interoperate with Engine Ids that do not conform.
//!
//! There are 6 schemes for Engine Ids defined in RFC3411. In all schemes, the first four bytes are an
//! IANA enterprise number (so far, all assigned numbers fit in two bytes). Most significant bit of
//! first byte is used indicate the static scheme (bit is zero) vs one of the dynamic schemes (bit is
//! one).
//!
//! There is also a single fixed constant, the "Local Engine ID" defined in RFC5345, used
//! in the mechanism documented there for Engine Id discovery. This is not needed when using
//! the User Security Model with SNMP v3, as the USM includes its own simpler method of discovery.
//!

use core::cmp::min;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::str::{from_utf8, FromStr};
use rasn::types::OctetString;

/// Static Scheme.
///
/// Output is always exactly 12 bytes long. Eight bytes for the enterprise to use as they think fit.
///
/// If more than one formatting scheme is in use in that enterprise, it is *recommended* that
/// the first payload octet is used to distinguish between formats of the remaining seven bytes.
pub fn static_engine_id(enterprise_number: u32, octets: &[u8]) -> OctetString {
    let mut buf: [u8; 12] = [0; 12];
    let enterprise_bytes = enterprise_number.to_be_bytes();
    buf[..4].copy_from_slice(&enterprise_bytes);
    buf[4..12].copy_from_slice(octets);
    OctetString::copy_from_slice(&buf)
}

/// IPv4 dynamic Scheme.
///
/// Address format as string with "." delimiters like "192.0.2.0"
///
/// Output is always exactly 9 bytes long. 4bytes for enterprise, but bit 1 is high.
/// 5th byte contains 01, for scheme. Final four bytes are address.
///
/// Will panic if address cannot be parsed.
pub fn ipv4_engine_id(enterprise_number: u32, address: &str) -> OctetString {
    let mut buf: [u8; 9] = [0; 9];
    let enterprise_bytes = enterprise_number.to_be_bytes();
    let ipv4 = Ipv4Addr::from_str(address).unwrap();
    buf[..4].copy_from_slice(&enterprise_bytes);
    buf[0] |= 128;
    buf[4] = 1;
    buf[5..9].copy_from_slice(&ipv4.octets());
    OctetString::copy_from_slice(&buf)
}

/// IPv6 dynamic Scheme.
///
/// Address format as string with : delimiters like "2001:0DB8::1"
///
/// Output is always exactly 21 bytes long. 4bytes for enterprise, but bit 1 is high.
/// 5th byte contains 02, for scheme. Final 16 bytes are address.
///
/// Will panic if address cannot be parsed.
pub fn ipv6_engine_id(enterprise_number: u32, address: &str) -> OctetString {
    let mut buf: [u8; 21] = [0; 21];
    let enterprise_bytes = enterprise_number.to_be_bytes();
    let ipv6 = Ipv6Addr::from_str(address).unwrap();
    buf[..4].copy_from_slice(&enterprise_bytes);
    buf[0] |= 128;
    buf[4] = 2;
    buf[5..21].copy_from_slice(&ipv6.octets());
    OctetString::copy_from_slice(&buf)
}

fn mac_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() == 17 {
        (0..s.len())
            .step_by(3)
            .map(|i| {
                s.get(i..i + 2)
                    .and_then(|sub| u8::from_str_radix(sub, 16).ok())
            })
            .collect()
    } else {
        None
    }
}

/// MAC dynamic Scheme.
///
/// Output is always exactly 11 bytes long. 4bytes for enterprise, but bit 1 is high.
/// 5th byte contains 03, for scheme. Final 6 bytes are MAC address. Address format as
/// string with : delimiters like "AA:BB:CC:DD:FF:11"
///
/// Will panic if address cannot be parsed.
pub fn mac_engine_id(enterprise_number: u32, address: &str) -> OctetString {
    let mut buf: [u8; 11] = [0; 11];
    let enterprise_bytes = enterprise_number.to_be_bytes();
    let bytes = mac_to_bytes(address).unwrap();
    buf[..4].copy_from_slice(&enterprise_bytes);
    buf[0] |= 128;
    buf[4] = 3;
    buf[5..11].copy_from_slice(&bytes[..6]);
    OctetString::copy_from_slice(&buf)
}

/// Text dynamic Scheme.
///
/// Variable length. Text argument is converted to utf-8, and up to 27 bytes are used.
///
/// *FIXME* Potentially, this could result in a broken final character, if encoded representation
/// exceeds 27bytes, and end straddles a character boundary. For now, play safe by keeping it short
/// or stick to US-ASCII characters.
///
/// Output contains 4bytes for enterprise, but bit 1 is high.
/// 5th byte contains 04, for scheme. Final up to 27 bytes are text - remember number
/// of bytes can be more than number of characters in string.
///
pub fn text_engine_id(enterprise_number: u32, text: &str) -> OctetString {
    let mut buf: [u8; 32] = [0; 32];
    let enterprise_bytes = enterprise_number.to_be_bytes();
    let bytes = text.as_bytes();
    let byte_len = bytes.len();
    buf[..4].copy_from_slice(&enterprise_bytes);
    buf[0] |= 128;
    buf[4] = 4;
    buf[5..(byte_len + 5)].copy_from_slice(&bytes[..byte_len]);
    let buf_len = 5 + byte_len;
    let buf = &buf[..buf_len];
    OctetString::copy_from_slice(buf)
}

/// Byte dynamic Scheme.
///
/// Variable length. Arbitrary byte argument, of which up to the first 27bytes will be used.
///
/// Output contains 4bytes for enterprise, but bit 1 is high.
/// 5th byte contains 05, for scheme. Final up to 27 bytes are byte argument
///
pub fn byte_engine_id(enterprise_number: u32, bytes: &[u8]) -> OctetString {
    let mut buf: [u8; 32] = [0; 32];
    let enterprise_bytes = enterprise_number.to_be_bytes();
    let byte_len = min(bytes.len(), 27);
    buf[..4].copy_from_slice(&enterprise_bytes);
    // Set MSB for dynamic scheme
    buf[0] |= 128;
    buf[4] = 5;
    buf[5..(byte_len + 5)].copy_from_slice(&bytes[..byte_len]);
    let buf_len = 5 + byte_len;
    let buf = &buf[..buf_len];
    OctetString::copy_from_slice(buf)
}

/// Local Engine ID "magic" value
///
/// Local Engine ID is defined in RFC5343, used for alternative mechanism for authoritative engine_id discovery.
/// Never use this as an actual engine ID. This is not needed when using the User Security Model with SNMP v3,
/// as the USM includes its own simpler method of discovery. This corresponds to an Enterprise ID
/// of zero, and formatting scheme 6.
pub const LOCAL_ENGINE_ID: OctetString = OctetString::from_static(b"\x80\x00\x00\x00\x06");

/// Format the engine_id into a descriptive string.
///
/// Probably behaves badly if you feed an arbitrary OctetString that is not
/// actually an engine_id.
pub fn format_engine_id(engine_id: OctetString) -> String {
    let mut vid = engine_id.to_vec();
    if vid.len() < 5 {
        return "Engine ID is too short, less than 5 bytes".to_string();
    }
    if vid.len() > 31 {
        return "Engine ID is too long, more than 31 bytes".to_string();
    }
    if vid[0] & 0x80 == 0x0 {
        if vid.len() != 12 {
            "Static ID scheme must be exactly 12 bytes".to_string()
        } else {
            let enterprise = u32::from_be_bytes(vid[..4].try_into().unwrap());
            format!(
                "Static ID. Enterprise Number {} Bytes {:?}",
                enterprise,
                vid[4..].to_vec()
            )
        }
    } else {
        // Set MSB to zero
        vid[0] &= 0x7F;
        let enterprise = u32::from_be_bytes(vid[..4].try_into().unwrap());

        match vid[4] {
            0 => "Reserved scheme 0, should never be used".to_string(),
            1 => {
                if vid.len() != 9 {
                    "IPv4 scheme must be exactly 9 bytes".to_string()
                } else {
                    let ipv4 = Ipv4Addr::new(vid[5], vid[6], vid[7], vid[8]);
                    format!("IPv4 Enterprise Number {} Address {}", enterprise, ipv4)
                }
            }
            2 => {
                if vid.len() != 21 {
                    "IPv6 scheme must be exactly 21 bytes".to_string()
                } else {
                    let ipv6 = Ipv6Addr::from(
                        <&[u8] as TryInto<[u8; 16]>>::try_into(&vid[5..21]).unwrap(),
                    );
                    format!("IPv6 Enterprise Number {} Address {}", enterprise, ipv6)
                }
            }
            3 => {
                format!(
                    "MAC Enterprise Number {} {:X}:{:X}:{:X}:{:X}:{:X}:{:X}",
                    enterprise, vid[5], vid[6], vid[7], vid[8], vid[9], vid[10]
                )
            }
            4 => {
                let bytes = vid[5..].to_vec();
                let text = from_utf8(&bytes).unwrap();
                format!("Text Enterprise Number {} Text {}", enterprise, text)
            }
            5 => {
                format!(
                    "Byte Enterprise Number {} Bytes {:?}",
                    enterprise,
                    vid[5..].to_vec()
                )
            }
            6 => {
                if engine_id == LOCAL_ENGINE_ID {
                    "Local Engine ID for RFC5354".to_string()
                } else {
                    "Scheme 6 is reseved for RFC5354, misused here".to_string()
                }
            }
            7..127 => "Reserved scheme number for future use. Are you sure this is an Engine ID?"
                .to_string(),
            _ => "Private enterprise use formatting scheme. Are you sure this is an Engine ID?"
                .to_string(),
        }
    }
}

/// Generates an engine ID from a text description.
///
/// Description text has three fields, separated by single spaces.
/// * The IANA enterprise number as decimal integer,
/// * Either the string Static for the static scheme above, or a number between 1 and 6, corresponding to a dynamic scheme,
/// * The scheme dependent payload.
///
/// # Panics
/// On parse errors
///
pub fn engine_id_from_str(text: &str) -> OctetString {
    let parts: Vec<&str> = text.splitn(3, ' ').collect();
    let ent: u32 = u32::from_str(parts[0]).unwrap();
    match parts[1] {
        "Static" => {
            let octets = hex::decode(parts[2]).unwrap();
            static_engine_id(ent, &octets)
        }
        "1" => ipv4_engine_id(ent, parts[2]),
        "2" => ipv6_engine_id(ent, parts[2]),
        "3" => mac_engine_id(ent, parts[2]),
        "4" => text_engine_id(ent, parts[2]),
        "5" => {
            let octets = hex::decode(parts[2]).unwrap();
            byte_engine_id(ent, &octets)
        }
        _ => panic!("Unsupported scheme"),
    }
}

#[cfg(test)]
mod tests {
    use crate::engine_id;

    #[test]
    fn test_rfc5343() {
        assert_eq!(
            "Local Engine ID for RFC5354",
            engine_id::format_engine_id(engine_id::LOCAL_ENGINE_ID)
        );
    }

    #[test]
    fn test_static() {
        assert_eq!(
            "Static ID. Enterprise Number 1234 Bytes [97, 98, 99, 100, 101, 102, 103, 104]",
            engine_id::format_engine_id(engine_id::static_engine_id(1234, b"abcdefgh"))
        );
    }

    #[test]
    fn test_engine_id_from_str() {
        assert_eq!(
            engine_id::engine_id_from_str("1234 1 127.0.0.1"),
            engine_id::ipv4_engine_id(1234, "127.0.0.1")
        )
    }
}
