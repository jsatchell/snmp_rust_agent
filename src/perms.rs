//! Minimal interim permissions model
//!
//! Radically simpler than the full VACM model!
//!
//! The permissions are read in from the file "groups.txt".
//!
//! This has a line per group. There are four entries per line:
//! * read permission ("t" or "f")
//! * write permission ("t" or "f")
//! * security level (1-3), where 1 is noAuth, 2 is AuthNoPriv, and 3 is AuthPriv
//! * group name
//!
//! The big difference from the VACM model is these permissions are global, rather than confined
//! to specific OIDs, and there is no provision to change them, except by editing groups.txt
use rasn::types::ObjectIdentifier;
use regex::Regex;
use std::fs::read_to_string;
use std::str::FromStr;

/// Associates a group name with read and write permissions for a
/// given security level.
#[derive(Debug, PartialEq, Eq)]
pub struct Perm {
    pub read: bool,
    pub write: bool,
    pub security_level: u8, // Just flags
    pub group_name: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParsePermError;

impl FromStr for Perm {
    type Err = ParsePermError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let re =
            Regex::new(r"^(?<read>[tf]) (?<write>[tf]) (?<level>[1-3]) (?<name>[^ ]+)$").unwrap();

        let captures = re.captures(s).ok_or(ParsePermError)?;

        Ok(Perm {
            read: captures["read"] == *"t",
            write: captures["write"] == *"t",
            security_level: captures["level"].parse().expect("Regex should have caught"),
            group_name: captures["name"].as_bytes().to_vec(),
        })
    }
}

impl Perm {
    pub fn check(&self, flags: u8, set: bool, _oid: &ObjectIdentifier) -> bool {
        // Ignore OID for now, but allow for a future version
        // to use it.
        let sec_level = 1 + (flags & 1) + (flags & 2);
        if sec_level < self.security_level {
            return false;
        }
        if set {
            self.write
        } else {
            self.read
        }
    }
}

/// Read "groups.txt" and return group definitions.
pub fn load_perms() -> Vec<Perm> {
    let mut perms = Vec::new();
    for line in read_to_string("groups.txt").unwrap().lines() {
        perms.push(Perm::from_str(line).expect("Parse error reading groups.txt"));
    }
    perms
}
