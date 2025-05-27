//use hex;
use regex::Regex;
use sha1::{Digest, Sha1};
use std::fs::read_to_string;
//use std::str::FromStr;
use crate::perms::{Perm};


#[derive(Debug, PartialEq)]
pub struct User <'a> {
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

impl <'a> User<'a> {

    fn from_str(s: &str, perms: &'a Vec<Perm>) -> Result<Self, ParseUserError> {
        if perms.is_empty() {
             return Err(ParseUserError);
        }
        let re =
            Regex::new(r"^(?<name>[^ ]+) (?<group>[^ ]+) (?<hash>[^ ]+) (?<ak>[^ ]+) (?<priv>[^ ]+) (?<pk>[^ ]+)$")
                .unwrap();

        let captures = re.captures(s).ok_or(ParseUserError)?;

        if captures["hash"] != *"sha1" {
            return Err(ParseUserError);
        }
        let akb = hex::decode(&captures["ak"]).unwrap();
        let group = captures["group"].as_bytes().to_vec();

        for perm_entry in perms {
            if group == perm_entry.group_name {
                return  Ok(User {
            group: group,
            perm: perm_entry,
            name: captures["name"].as_bytes().to_vec(),
            auth_key: akb.clone(),
            priv_key: hex::decode(&captures["pk"]).unwrap(),
            k1: k1_from_ak(&akb),
            k2: k2_from_ak(&akb),
        });
            }
        }
        return Err(ParseUserError);
    }

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

pub fn  load_users <'a>(perms: &'a Vec<Perm>) -> Vec<User<'a>> {
    let lines = read_lines("users.txt");
    let mut users = Vec::new();
    for line in lines {
        users.push(User::from_str(&line, &perms).expect("Parse error reading users.txt"));
    }
    users
}

#[cfg(test)]
mod tests {
    use super::*;
  
     fn perms() -> Vec<Perm> {
vec![Perm{read: true,
     write: true,
    security_level: 1u8,  // Just flags
     group_name: "test".as_bytes().to_vec(),}]
     }

    #[test]
    fn rfc2202_case1_test() {
        let s ="test test sha1 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv =perms();
        let u = User::from_str(s, &pv).unwrap();

        assert_eq!(
            u.auth_from_bytes(b"Hi There"),
            b"\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6"
        );
    }

    #[test]
    fn rfc2202_case3_test() {
        let s ="test test sha1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv =perms();
        let u = User::from_str(s, &pv).unwrap();
        assert_eq!(
            u.auth_from_bytes(b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"),
            b"\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4"
        );
    }

    // When we do rfc7360, there are HMAC test cases in RFC 4231 for the other hashes
}
