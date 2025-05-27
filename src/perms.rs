// Minimal interim permissions model
// 
// Radically simpler than the full VACM model!
use rasn::types::ObjectIdentifier;
use std::str::FromStr;
use std::fs::read_to_string;
use regex::Regex;


#[derive(Debug, PartialEq, Eq)]
pub struct Perm {
    pub read: bool,
    pub write: bool,
    pub security_level: u8,  // Just flags
    pub group_name: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParsePermError;

impl FromStr for Perm {
    type Err = ParsePermError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let re =
            Regex::new(r"^(?<read>[tf]) (?<write>[tf]) (?<level>[1-3]) (?<name>[^ ]+)$")
                .unwrap();

        let captures = re.captures(s).ok_or(ParsePermError)?;

        Ok(Perm {
            read: captures["read"]==*"t",
            write: captures["write"]==*"t",
            security_level: captures["level"].parse().expect("Regex should have caught"),
            group_name: captures["name"].as_bytes().to_vec(),
        })
    }
}

impl Perm {
    pub fn check(&self, flags: u8, set: bool, _oid: &ObjectIdentifier) -> bool {
        // Ignore OID for now, but allow for a future version
        // to use it.
        let sec_level = 1 + flags & 1 + flags & 2;
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
   

pub fn load_perms() -> Vec<Perm> {
    let mut perms = Vec::new();
    for line in read_to_string("groups.txt").unwrap().lines() {
        perms.push(Perm::from_str(&line).expect("Parse error reading groups.txt"));
    }
    perms
}
