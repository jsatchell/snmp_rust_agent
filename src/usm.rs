//use hex;
use regex::Regex;
use sha1::{Digest, Sha1};
use std::fs::read_to_string;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub struct User {
    pub name: Vec<u8>,
    auth_key: Vec<u8>,
    pub priv_key: Vec<u8>,
    k1: [u8; 64],
    k2: [u8; 64],
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseUserError;

impl FromStr for User {
    type Err = ParseUserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let re = Regex::new(r"^(?<name>[^ ]+) sha1 (?<ak>[^ ]+) aes (?<pk>[^ ]+)$").unwrap();

        let captures = re.captures(s).ok_or(ParseUserError)?;

        let akb = hex::decode(&captures["ak"]).unwrap();
        Ok(User {
            name: captures["name"].as_bytes().to_vec(),
            auth_key: akb.clone(),
            priv_key: hex::decode(&captures["pk"]).unwrap(),
            k1: k1_from_ak(&akb),
            k2: k2_from_ak(&akb),
        })
    }
}

impl User {
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

pub fn load_users() -> Vec<User> {
    let lines = read_lines("users.txt");
    let mut users = Vec::new();
    for line in lines {
        users.push(User::from_str(&line).expect("Parse error reading users.txt"));
    }
    users
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc2021_test() {
        let s ="test sha1 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let u = User::from_str(s).unwrap();

        assert_eq!(
            u.auth_from_bytes(b"Hi There"),
            b"\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6"
        );
    }
}
