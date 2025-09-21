//! User module
//!
//! This only implements a very restricted subset of RFC3414.
//!
//! The user data is read from a file called "users.txt", one line per user.
//!
//! The fields on the line are:
//! * the username (no spaces!)
//! * the group name of the user (must match a name in groups.toml, see perms module)
//! * the hash type in use. Currently only sha1 is accepted here.
//! * the localized authentication hash
//! * the privacy type. Currently only aes allowed.
//! * the localized privacy hash
//!
//!
use crate::perms::Perm;
use digest::DynDigest;
use log::warn;
use regex::Regex;
use sha1;
use sha2;
use std::cell::RefCell;
use std::fs::File;
use std::io::{Error, Write};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum WhatHash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

/// User struct holds data about user.
///
/// Contains localized hashes, and pre calculated values for k1 and k2, used
/// in generating the checksums.
#[derive(Debug, PartialEq, Eq)]
pub struct User {
    what: WhatHash,
    pub group: Vec<u8>,
    pub perm: Perm,
    pub name: Vec<u8>,
    pub trunc: usize,
    auth_key: RefCell<Vec<u8>>,
    pub priv_key: RefCell<Vec<u8>>,
    pub auth_length: usize,
    k1: RefCell<Vec<u8>>, //[u8; 64],
    k2: RefCell<Vec<u8>>, //[u8; 64],
    pub clean: RefCell<bool>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseUserError;

impl User {
    /// Create a User from a line in the file
    ///
    /// Will throw ParseUserError on problems.
    /// User group name (the second item on the line) must match a group in perms
    pub fn from_str(s: &str, perms: &Vec<Perm>) -> Result<Self, ParseUserError> {
        if perms.is_empty() {
            return Err(ParseUserError);
        }
        let re =
            Regex::new(r"^(?<name>[^ ]+) (?<group>[^ ]+) (?<hash>[^ ]+) (?<ak>[^ ]+) (?<priv>[^ ]+) (?<pk>[^ ]+)$")
                .unwrap(); // Checked - regex compiles

        let captures = re.captures(s).ok_or(ParseUserError)?;

        // Change this when we support additional hash types from RFC7630
        let (what, trunc, auth_length) = match &captures["hash"] {
            "sha1" => (WhatHash::Sha1, 20, 12),
            "sha224" => (WhatHash::Sha224, 28, 16),
            "sha256" => (WhatHash::Sha256, 32, 24),
            "sha384" => (WhatHash::Sha384, 48, 32),
            "sha512" => (WhatHash::Sha512, 64, 48),
            _ => return Err(ParseUserError),
        };

        if captures["priv"] != *"aes" {
            return Err(ParseUserError);
        }
        let akb = hex::decode(&captures["ak"]).unwrap(); // Startup, who cares?
        let group = captures["group"].as_bytes().to_vec();

        for perm_entry in perms {
            if group == perm_entry.group_name {
                return Ok(User {
                    what,
                    group,
                    perm: perm_entry.clone(),
                    name: captures["name"].as_bytes().to_vec(),
                    trunc,
                    auth_key: RefCell::new(akb.clone()),
                    priv_key: RefCell::new(hex::decode(&captures["pk"]).unwrap()), // Startup, who cares?
                    auth_length,
                    k1: if trunc < 40 {
                        RefCell::new(k1_from_ak(&akb, trunc))
                    } else {
                        RefCell::new(k1_128_from_ak(&akb, trunc))
                    },
                    k2: if trunc < 40 {
                        RefCell::new(k2_from_ak(&akb, trunc))
                    } else {
                        RefCell::new(k2_128_from_ak(&akb, trunc))
                    },
                    clean: RefCell::new(true),
                });
            }
        }
        Err(ParseUserError)
    }

    /// Generates the bytes for a line in the file for the user.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![];
        out.extend(self.name.clone());
        out.push(b' ');
        out.extend(self.group.clone());
        match self.what {
            WhatHash::Sha1 => {
                out.extend(b" sha1 ");
            }
            WhatHash::Sha224 => {
                out.extend(b" sha224 ");
            }
            WhatHash::Sha256 => {
                out.extend(b" sha256 ");
            }
            WhatHash::Sha384 => {
                out.extend(b" sha384 ");
            }
            WhatHash::Sha512 => {
                out.extend(b" sha512 ");
            }
        };
        out.extend(hex::encode(self.auth_key.borrow().clone()).as_bytes());
        out.extend(b" aes ");
        out.extend(hex::encode(self.priv_key.borrow().clone()).as_bytes());
        out.push(b'\n');
        out
    }

    fn choose_hasher(&self) -> Box<dyn DynDigest> {
        match self.what {
            WhatHash::Sha1 => Box::new(sha1::Sha1::default()),
            WhatHash::Sha224 => Box::new(sha2::Sha224::default()),
            WhatHash::Sha256 => Box::new(sha2::Sha256::default()),
            WhatHash::Sha384 => Box::new(sha2::Sha384::default()),
            WhatHash::Sha512 => Box::new(sha2::Sha512::default()),
        }
    }

    /// Calculate the HMAC checksum from the data.
    ///
    /// Parameterized to support RFC7630
    pub fn auth_from_bytes(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = self.choose_hasher();
        hasher.update(&self.k1.borrow());
        hasher.update(data);
        let mid = hasher.finalize();
        let mut hash2 = self.choose_hasher();
        hash2.update(&self.k2.borrow());
        hash2.update(&mid);
        let trunc = match self.what {
            WhatHash::Sha1 => 12,
            WhatHash::Sha224 => 16,
            WhatHash::Sha256 => 24,
            WhatHash::Sha384 => 32,
            WhatHash::Sha512 => 48,
        };
        hash2.finalize()[0..trunc].to_owned()
    }

    /// Key change algorithm from RFC3414#page-84 for HMAC SHA-1.
    /// In this case, L=20, K=20. data must be 40 bytes.
    pub fn key_change(&self, data: &[u8], auth_priv: bool) -> Vec<u8> {
        let mut temp = if auth_priv {
            self.auth_key.borrow().clone()
        } else {
            self.priv_key.borrow().clone()
        };
        let l = match self.what {
            WhatHash::Sha1 => 20,
            WhatHash::Sha224 => 28,
            WhatHash::Sha256 => 32,
            WhatHash::Sha384 => 48,
            WhatHash::Sha512 => 64,
        };

        // append random bytes
        for item in data.iter().take(l) {
            temp.push(*item);
        }
        let mut hasher = self.choose_hasher();
        hasher.update(&temp);
        let next = hasher.finalize();
        let mut new_key = vec![];
        // Only 20 for sha1!
        for i in 0..l {
            new_key.push(next[i] ^ data[l + i]);
        }
        new_key
    }

    pub fn update_password(&self, new_val: &[u8], auth_priv: bool) -> Result<(), Error> {
        let new_key = self.key_change(new_val, auth_priv);
        if auth_priv {
            let mut ak = self.auth_key.borrow_mut();
            ak.clear();
            ak.extend(new_key);
            *self.k1.borrow_mut() = if self.auth_length < 30 {
                k1_from_ak(&ak, self.trunc)
            } else {
                k1_128_from_ak(&ak, self.trunc)
            };
            *self.k2.borrow_mut() = if self.auth_length < 30 {
                k2_from_ak(&ak, self.trunc)
            } else {
                k2_128_from_ak(&ak, self.trunc)
            } // end of ak, k1 and k2 borrows
        } else {
            let mut pk = self.priv_key.borrow_mut();
            pk.clear();
            pk.extend(new_key);
        } // endof pk borrow
        *self.clean.borrow_mut() = false;
        Ok(())
    }
}

fn k1_from_ak(ak: &[u8], trunc: usize) -> Vec<u8> {
    let mut eak: [u8; 64] = [0; 64];
    eak[..trunc].copy_from_slice(&ak[..trunc]);
    for i in &mut eak {
        // XOR with 0x36
        *i ^= 0x36;
    }
    eak.to_vec()
}

fn k2_from_ak(ak: &[u8], trunc: usize) -> Vec<u8> {
    let mut eak: [u8; 64] = [0; 64];
    eak[..trunc].copy_from_slice(&ak[..trunc]);
    for i in &mut eak {
        // XOR with 0x5C
        *i ^= 0x5C;
    }
    eak.to_vec()
}

fn k1_128_from_ak(ak: &[u8], trunc: usize) -> Vec<u8> {
    let mut eak: [u8; 128] = [0; 128];
    eak[..trunc].copy_from_slice(&ak[..trunc]);
    for i in &mut eak {
        // XOR with 0x36
        *i ^= 0x36;
    }
    eak.to_vec()
}

fn k2_128_from_ak(ak: &[u8], trunc: usize) -> Vec<u8> {
    let mut eak: [u8; 128] = [0; 128];
    eak[..trunc].copy_from_slice(&ak[..trunc]);
    for i in &mut eak {
        // XOR with 0x5C
        *i ^= 0x5C;
    }
    eak.to_vec()
}

#[derive(Debug, PartialEq, Eq)]
pub struct Users {
    filename: String,
    pub users: Vec<User>,
}

impl Default for Users {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Users {
    pub fn new() -> Self {
        Users {
            filename: "users.txt".to_string(),
            users: vec![],
        }
    }

    pub fn lookup_user(&self, name: Vec<u8>) -> Option<&User> {
        // FIXME change to binary search to support many users better
        for user in &self.users {
            let uname = user.name.clone();
            if uname == name {
                return Some(user);
            }
        }
        warn!("Name doesn't match");
        None
    }

    pub fn load_from_str(&mut self, perms: &'a Vec<Perm>, user_text: &str) {
        for line in user_text.lines() {
            // Startup, who cares?
            self.users
                .push(User::from_str(line, perms).expect("Parse error reading users.txt"));
        }
        //  Sort so we can do binary search lookups in the future
        self.users.sort_by(|a, b| a.name.cmp(&b.name));
    }

    pub fn save_to_file(&self) -> Result<(), Error> {
        let mut save = File::create(&self.filename)?;
        for user in &self.users {
            save.write_all(&user.to_bytes())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perms::Rule;

    fn perms() -> Vec<Perm> {
        let rules = vec![Rule {
            read: true,
            write: true,
            include: vec![vec![1u32]],
            exclude: vec![],
        }];
        vec![Perm {
            rules,
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
    fn test_bytes() {
        let s ="test test sha1 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv = perms();
        let u = User::from_str(s, &pv).unwrap(); // Checked #test
        let b = u.to_bytes();
        let l = s.len();
        assert_eq!(&b[..l], s.as_bytes()); // Trim last byte, as output from to_bytes has \n added.
    }

    #[test]
    fn rfc2202_case1_test() {
        let s ="test test sha1 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv = perms();
        let u = User::from_str(s, &pv).unwrap(); // Checked #test

        assert_eq!(
            u.auth_from_bytes(b"Hi There"),
            b"\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6"
        );
    }

    #[test]
    fn roundtrip_case1_test() {
        let s ="test test sha1 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv = perms();
        let u = User::from_str(s, &pv).unwrap(); // Checked #test
        let b = u.to_bytes();
        // Strip newline off end
        let a = b.split_last().unwrap().1; // Checked #test
        assert_eq!(s.as_bytes(), a);
    }

    #[test]
    fn rfc2202_case3_test() {
        let s ="test test sha1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv = perms();
        let u = User::from_str(s, &pv).unwrap(); // Checked #test
        assert_eq!(
            u.auth_from_bytes(b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"),
            b"\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4"
        );
    }

    #[test]
    fn rfc4231_224_case1_test() {
        let s ="test test sha224 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000000 aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv = perms();
        let u = User::from_str(s, &pv).unwrap(); // Checked #test

        assert_eq!(
            u.auth_from_bytes(b"Hi There"),
            b"\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f"
        );
    }

    #[test]
    fn rfc4231_256_case1_test() {
        let s ="test test sha256 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b00000000000000000000000000000000 aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv = perms();
        let u = User::from_str(s, &pv).unwrap(); // Checked #test

        assert_eq!(
            u.auth_from_bytes(b"Hi There"),
            b"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7"
        );
    }

    #[test]
    fn rfc4231_384_case1_test() {
        let s ="test test sha384 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b00000000000000000000000000000000000000000000000000000000 aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv = perms();
        let u = User::from_str(s, &pv).unwrap();

        assert_eq!(
            u.auth_from_bytes(b"Hi There"),
            b"\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c"
        );
    }

    #[test]
    fn test_key_change() {
        // Appendix A5.2 of RFC3414, localized key from A3.2
        let hex_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9c\x10\x17\xf4\xfd\x48\x3d\x2d\xe8\xd5\xfa\xdb\xf8\x43\x92\xcb\x06\x45\x70\x51";
        let p = perms();
        let u = User {
            what: WhatHash::Sha1,
            group: vec![0, 1],
            perm: p[0].clone(),
            name: b"test".to_vec(),
            auth_key: RefCell::new(
                b"\x66\x95\xfe\xbc\x92\x88\xe3\x62\x82\x23\x5f\xc7\x15\x1f\x12\x84\x97\xb3\x8f\x3f"
                    .to_vec(),
            ),
            auth_length: 12,
            trunc: 20,
            priv_key: RefCell::new(vec![]),
            k1: RefCell::new([0; 64].to_vec()),
            k2: RefCell::new([0; 64].to_vec()),
            clean: RefCell::new(true),
        };
        let new_k = u.key_change(hex_data, true);
        assert_eq!(
            new_k,
            b"\x78\xe2\xdc\xce\x79\xd5\x94\x03\xb5\x8c\x1b\xba\xa5\xbf\xf4\x63\x91\xf1\xcd\x25"
                .to_vec()
        );
    }

    #[test]
    fn test_passwd_update() {
        // Appendix A5.2 of RFC3414, localized key from A3.2
        let hex_data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9c\x10\x17\xf4\xfd\x48\x3d\x2d\xe8\xd5\xfa\xdb\xf8\x43\x92\xcb\x06\x45\x70\x51";
        let p = perms();
        let u = User {
            what: WhatHash::Sha1,
            group: vec![0, 1],
            perm: p[0].clone(),
            name: b"test".to_vec(),
            auth_key: RefCell::new(
                b"\x66\x95\xfe\xbc\x92\x88\xe3\x62\x82\x23\x5f\xc7\x15\x1f\x12\x84\x97\xb3\x8f\x3f"
                    .to_vec(),
            ),
            auth_length: 12,
            trunc: 20,
            priv_key: RefCell::new(vec![]),
            k1: RefCell::new([0; 64].to_vec()),
            k2: RefCell::new([0; 64].to_vec()),
            clean: RefCell::new(true),
        };
        let res = u.update_password(hex_data, true);
        assert!(res.is_ok());
        assert_eq!(
            *u.auth_key.borrow(),
            b"\x78\xe2\xdc\xce\x79\xd5\x94\x03\xb5\x8c\x1b\xba\xa5\xbf\xf4\x63\x91\xf1\xcd\x25"
                .to_vec()
        );
    }

    #[test]
    fn test_empty_users() {
        let mut u = Users::default();
        assert!(u.users.is_empty());
        let user_text = "test test sha1 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let pv = perms();
        u.load_from_str(&pv, user_text);
        assert!(!u.users.is_empty());
        assert!(u.lookup_user(b"test".to_vec()).is_some());
        assert!(u.lookup_user(b"not".to_vec()).is_none());
    }
}
