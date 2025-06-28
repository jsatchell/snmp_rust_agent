//! User module
//!
//! This only implements a very restricted subset of RFC3414.
//!
//! The user data is read from a file called "users.txt", one line per user.
//!
//! The fields on the line are:
//! * the username (no spaces!)
//! * the group name of the user (must match a name in groups.txt, see perms module)
//! * the hash type in use. Currently only sha1 is accepted here.
//! * the localised authentication hahs
//! * the privacy type (only aes alllowed)
//! * the localised privacy hash
//!
//!
use crate::perms::Perm;
use regex::Regex;
use sha1::{Digest, Sha1};
use std::fs::read_to_string;

/// User struct holds data about user.
///
/// Contains localised hashes, and pre calculated values for k1 and k2, used
/// in generating the checksums.
#[derive(Debug, PartialEq)]
pub struct User<'a> {
    pub group: Vec<u8>,
    pub perm: &'a Perm,
    pub name: Vec<u8>,
    auth_key: Vec<u8>,
    pub priv_key: Vec<u8>,
    k1: [u8; 64],
    k2: [u8; 64],
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseUserError;

impl<'a> User<'a> {
    /// Create a User from a line in the file
    ///
    /// Will throw ParseUserError on problems.
    /// User group name (the second item on the line) must match a group in perms
    fn from_str(s: &str, perms: &'a Vec<Perm>) -> Result<Self, ParseUserError> {
        if perms.is_empty() {
            return Err(ParseUserError);
        }
        let re =
            Regex::new(r"^(?<name>[^ ]+) (?<group>[^ ]+) (?<hash>[^ ]+) (?<ak>[^ ]+) (?<priv>[^ ]+) (?<pk>[^ ]+)$")
                .unwrap();

        let captures = re.captures(s).ok_or(ParseUserError)?;

        // Change this when we support additional hash types from RFC7630
        if captures["hash"] != *"sha1" {
            return Err(ParseUserError);
        }
        let akb = hex::decode(&captures["ak"]).unwrap();
        let group = captures["group"].as_bytes().to_vec();

        for perm_entry in perms {
            if group == perm_entry.group_name {
                return Ok(User {
                    group,
                    perm: perm_entry,
                    name: captures["name"].as_bytes().to_vec(),
                    auth_key: akb.clone(),
                    priv_key: hex::decode(&captures["pk"]).unwrap(),
                    k1: k1_from_ak(&akb),
                    k2: k2_from_ak(&akb),
                });
            }
        }
        Err(ParseUserError)
    }

    /// Calculate the HMAC checksum from the data.
    ///
    /// Will need to be templated or parameterised to support RFC7630
    pub fn auth_from_bytes(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(self.k1);
        hasher.update(data);
        let mid = hasher.finalize();
        let mut hash2 = Sha1::new();
        hash2.update(self.k2);
        hash2.update(mid);
        let last: [u8; 20] = hash2.finalize().into();
        last[0..12].to_owned()
    }

    /// Keychange algoritm from RFC3414#page-84 for HMAC SHA-1.
    /// In this case, L=20, K=20. data must be 40 bytes.
    pub fn keychange(&self, data: &[u8]) -> Vec<u8> {
        let mut temp = self.auth_key.clone();

        // append random bytes
        for item in data.iter().take(20) {
            temp.push(*item);
        }
        let mut hasher = Sha1::new();
        hasher.update(temp);
        let next = hasher.finalize();
        let mut newkey = vec![];
        for i in 0..20 {
            newkey.push(next[i] ^ data[20 + i]);
        }
        newkey
    }
}

fn k1_from_ak(ak: &[u8]) -> [u8; 64] {
    let mut eak: [u8; 64] = [0; 64];
    eak[..20].copy_from_slice(&ak[..20]);
    for i in &mut eak {
        // XOR with 0x36
        *i ^= 0x36;
    }
    eak
}

fn k2_from_ak(ak: &[u8]) -> [u8; 64] {
    let mut eak: [u8; 64] = [0; 64];
    eak[..20].copy_from_slice(&ak[..20]);
    for i in &mut eak {
        // XOR with 0x5C
        *i ^= 0x5C;
    }
    eak
}

fn read_lines(filename: &str) -> Vec<String> {
    let mut result = Vec::new();

    for line in read_to_string(filename).unwrap().lines() {
        result.push(line.to_string())
    }

    result
}

/// Load user definitions from "users.txt"
pub fn load_users(perms: &Vec<Perm>) -> Vec<User<'_>> {
    let lines = read_lines("users.txt");
    let mut users = Vec::new();
    for line in lines {
        users.push(User::from_str(&line, perms).expect("Parse error reading users.txt"));
    }
    users
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perms() -> Vec<Perm> {
        vec![Perm {
            read: true,
            write: true,
            security_level: 1u8, // Just flags
            group_name: "test".as_bytes().to_vec(),
        }]
    }

    #[test]
    fn wrong_group() {
        let s ="test wrong sha1 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv = perms();
        let u = User::from_str(s, &pv);

        assert!(u.is_err());
    }

    #[test]
    fn wrong_hash() {
        let s ="test test zzz 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv = perms();
        let u = User::from_str(s, &pv);
        assert!(u.is_err());
    }

    #[test]
    fn rfc2202_case1_test() {
        let s ="test test sha1 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv = perms();
        let u = User::from_str(s, &pv).unwrap();

        assert_eq!(
            u.auth_from_bytes(b"Hi There"),
            b"\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6"
        );
    }

    #[test]
    fn rfc2202_case3_test() {
        let s ="test test sha1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv = perms();
        let u = User::from_str(s, &pv).unwrap();
        assert_eq!(
            u.auth_from_bytes(b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"),
            b"\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4"
        );
    }

    #[test]
    fn test_keychange() {
        // Appendix A5.2 of RFC3414, localized key from A3.2
        let hex_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9c\x10\x17\xf4\xfd\x48\x3d\x2d\xe8\xd5\xfa\xdb\xf8\x43\x92\xcb\x06\x45\x70\x51";
        let p = perms();
        let u = User {
            group: vec![0, 1],
            perm: &p[0],
            name: b"twst".to_vec(),
            auth_key:
                b"\x66\x95\xfe\xbc\x92\x88\xe3\x62\x82\x23\x5f\xc7\x15\x1f\x12\x84\x97\xb3\x8f\x3f"
                    .to_vec(),
            priv_key: vec![],
            k1: [0; 64],
            k2: [0; 64],
        };
        let newk = u.keychange(hex_data);
        assert_eq!(
            newk,
            b"\x78\xe2\xdc\xce\x79\xd5\x94\x03\xb5\x8c\x1b\xba\xa5\xbf\xf4\x63\x91\xf1\xcd\x25"
                .to_vec()
        );
    }
    // When we do rfc7630, there are HMAC test cases in RFC 4231 for the other hashes
}
