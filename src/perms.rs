//! Permissions model
//!
//! Simpler than the full VACM model from RFC3415!
//!
//! The permissions are read in from a file, the example is in "groups.toml".
//!
//! This has a table per user group. The table has three compulsory entries and one optional,
//! * name, a string, used to correlate groups with users.
//! * level, a string, one of three permitted values: noAuthNoPriv, authNoPriv or authPriv
//! * rules, an array of rule tables. Usefully, you should have at least one rule.
//! * context, if present is the name of an alternate context that the group applies to. If absent, the default, blank context is assumed.
//!
//! The inner rule table has four entries:
//! * read, a boolean
//! * write, a boolean
//! * include, an array of strings. The strings are OID prefixes, in dotted notation, like "1.3.6.1". The rule applies to everything that starts with at least one of the entries.
//! * exclude, an array of strings, which could be empty. The strings are OID prefixes, in dotted notation, like "1.3.6.1". Anything that matches at least one will be excluded from matching the rule. The prefixes need to lie within an inclusion prefix to have any effect.
//!
//! The big difference from the VACM model is there is no provision to change them, except by editing the file.
//!
//! Not being able to attack them on the wire is a deliberate security feature, not a bug.
use log::warn;
use rasn::types::ObjectIdentifier;
use toml;

#[derive(Debug, PartialEq, Eq, Clone)]
/// Permissions to apply to a group.
pub struct Perm {
    /// The group name is used to identify which users this applies to.
    pub group_name: Vec<u8>,
    /// The minimum security level that the user's connection must have. 1 = noAuthNoPriv, 2 = authNoPriv, 3 = authPriv
    pub security_level: u8,
    /// There can be multiple Rules that apply for this group of users.
    pub rules: Vec<Rule>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Rule {
    /// Are read operations permitted? Needed for Get, GetNext, BulkGet PDUs
    pub read: bool,
    /// Are write operations permitted? Set PDU
    pub write: bool,
    /// This rule may only apply in a specific context. If not mentioned in the file, the Rule applies everywhere.
    pub context: Option<Vec<u8>>,
    /// OID prefixes that match this rule. You need at least one entry here; if nothing else try vec![1, 3, 6, 1]
    pub include: Vec<Vec<u32>>,
    /// Possibly empty vector of OID prefixes that are excluded from matching - each should lie wholly within an inclusion prefix.
    pub exclude: Vec<Vec<u32>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParsePermError;

impl Perm {
    /// Check if the operation is permitted.
    ///
    /// flags is the value ultimately from the Message header.
    ///
    /// set is true for Set operations, and false otherwise.
    ///
    /// The oid should be the OID for the associated object that will perform the operation.
    ///
    /// The context is the context of the calling Pdu;
    pub fn check(&self, flags: u8, set: bool, oid: &ObjectIdentifier, context: &[u8]) -> bool {
        let sec_level = 1 + (flags & 1) + (flags & 2);
        if sec_level < self.security_level {
            return false;
        }
        for rule in &self.rules {
            if rule.context.is_some() && context != rule.context.as_ref().unwrap() {
                continue;
            }
            if set && !rule.write {
                //No point examining if rule matches, if it doesn't give permission anyway
                continue;
            }
            if !set && !rule.read {
                //No point examining if rule matches, if it doesn't give permission anyway
                continue;
            }
            let mut excluded = false;
            for exc in &rule.exclude {
                excluded = excluded || oid.starts_with(exc.as_slice());
            }
            if excluded {
                continue;
            }
            let mut included = false;
            for inc in &rule.include {
                included = included || oid.starts_with(inc.as_slice());
            }
            if included {
                return true;
            }
        } // If we get to the end of the loop and no Rule provided the permission, return false.
        false
    }
}

/// Parse text and return group definitions.
///
/// Panics if parse fails - this is during startup so indicates a configuration error,
/// or file system corruption.
///
/// FIXME - setup serde stuff, including wrappers, so deserialize just works, rather than doing
/// it by hand.
pub fn load_from_str(toml_text: &str) -> Vec<Perm> {
    let mut perms = Vec::new();

    let data = toml_text.parse::<toml::Table>().unwrap(); // Startup
    let groups = data.get("groups").unwrap().as_array().unwrap(); // Startup
    for group in groups {
        let group_name = group
            .get("name")
            .unwrap() // Startup
            .as_str()
            .unwrap() // Startup
            .as_bytes()
            .to_vec();
        let level = group.get("level").unwrap().as_str().unwrap(); // Startup
        let trules = group.get("rules").unwrap().as_array().unwrap(); // Startup
        let mut rules = vec![];
        for rule in trules {
            let read = rule.get("read").unwrap().as_bool().unwrap(); // Startup
            let write = rule.get("write").unwrap().as_bool().unwrap(); // Startup
            let con_op = rule.get("context");
            let context = con_op.map(|cstr| cstr.as_str().unwrap().as_bytes().to_vec());

            let tinclude = rule.get("include").unwrap().as_array().unwrap(); // Startup
            let texclude = rule.get("exclude").unwrap().as_array().unwrap(); // Startup
            let mut include = vec![];
            let mut exclude = vec![];
            for arc in tinclude {
                let dots: Vec<u32> = arc
                    .as_str()
                    .unwrap() // Startup
                    .split(".")
                    .map(|s| {
                        let u: u32 = s.parse().unwrap(); // Startup
                        u
                    })
                    .collect();
                include.push(dots);
            }
            for arc in texclude {
                let dots: Vec<u32> = arc
                    .as_str()
                    .unwrap() // Startup
                    .split(".")
                    .map(|s| {
                        let u: u32 = s.parse().unwrap(); // Startup
                        u
                    })
                    .collect();
                exclude.push(dots);
            }
            let prule = Rule {
                read,
                write,
                context,
                include,
                exclude,
            };
            rules.push(prule);
        }
        let security_level = match level {
            "noAuthNoPriv" => 1,
            "authNoPriv" => 2,
            "authPriv" => 3,
            _ => {
                warn!("Unrecognized security level name {level}, denying all access");
                255
            }
        };

        let perm = Perm {
            group_name,
            security_level,
            rules,
        };
        perms.push(perm);
    }
    perms
}

pub struct FlagPerm<'a> {
    pub perm: &'a Perm,
    flags: u8,
    context: &'a [u8],
}

impl<'a> FlagPerm<'a> {
    pub fn new(flags: u8, context: &'a [u8], perm: &'a Perm) -> Self {
        FlagPerm {
            perm,
            flags,
            context,
        }
    }

    pub fn check(&self, set: bool, oid: &ObjectIdentifier) -> bool {
        self.perm.check(self.flags, set, oid, self.context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn::types::ObjectIdentifier;
    use test_log::test;

    const ARC_IN: [u32; 2] = [1, 1];
    const ARC_OUT: [u32; 2] = [2, 1];
    const ARC_EXC: [u32; 3] = [1, 3, 1];

    fn perms() -> Vec<Perm> {
        let rules = vec![
            Rule {
                read: false,
                write: false,
                context: None,
                include: vec![vec![1u32]],
                exclude: vec![],
            },
            Rule {
                read: true,
                write: true,
                context: None,
                include: vec![vec![1u32]],
                exclude: vec![vec![1u32, 3u32]],
            },
        ];
        vec![Perm {
            rules,
            security_level: 2u8, // Just flags
            group_name: "test".as_bytes().to_vec(),
        }]
    }

    #[test]
    fn test_check() {
        let o_in = ObjectIdentifier::new(&ARC_IN).unwrap(); // Checked #[test]
        let o_out = ObjectIdentifier::new(&ARC_OUT).unwrap(); // Checked #[test]
        let o_exc = ObjectIdentifier::new(&ARC_EXC).unwrap(); // Checked #[test]
        let p = &perms()[0];
        let context = [];
        assert!(p.check(2, true, &o_in, &context));
        assert!(p.check(2, false, &o_in, &context));
        assert!(!p.check(0, false, &o_in, &context));
        assert!(!p.check(2, false, &o_out, &context));
        assert!(!p.check(2, true, &o_exc, &context));
    }

    #[test]
    fn test_flag_check() {
        let o_in = ObjectIdentifier::new(&ARC_IN).unwrap(); // Checked #[test]
        let o_out = ObjectIdentifier::new(&ARC_OUT).unwrap(); // Checked #[test]
        let p = &perms()[0];
        let f = FlagPerm {
            perm: p,
            context: &[],
            flags: 2u8,
        };
        assert!(f.check(true, &o_in));
        assert!(f.check(false, &o_in));
        assert!(!f.check(false, &o_out));
    }

    #[test]
    fn test_load_from_str() {
        let o_in = ObjectIdentifier::new(&ARC_IN).unwrap(); // Checked #[test]
        let txt = "
[[groups]]
name = \"admin\"
level = \"authNoPriv\"
rules = [ {read = true, write = true, include=[ \"1.1\" ], exclude = [ \"1.3.6.1.6.3.1.25\"]} ]
";
        let perms = load_from_str(&txt);
        assert_eq!(perms.len(), 1);
        let p = &perms[0];
        let f = FlagPerm {
            perm: p,
            context: &[6],
            flags: 2u8,
        };
        assert!(f.check(false, &o_in))
    }

    #[test]
    fn test_load_from_bad_str() {
        let o_in = ObjectIdentifier::new(&ARC_IN).unwrap(); // Checked #[test]
        let txt = "
[[groups]]
name = \"admin\"
level = \"sillyLevel\"
rules = [ {read = true, write = true, include=[ \"1.1\" ], exclude = [ \"1.3.6.1.6.3.1.25\"]} ]
";
        let perms = load_from_str(&txt);
        assert_eq!(perms.len(), 1);
        let p = &perms[0];
        let f = FlagPerm {
            perm: p,
            context: &[6],
            flags: 2u8,
        };
        assert!(!f.check(false, &o_in))
    }

    #[test]
    fn test_no_rules() {
        let o_in = ObjectIdentifier::new(&ARC_IN).unwrap(); // Checked #[test]
        let txt = "
[[groups]]
name = \"admin\"
level = \"noAuthNoPriv\"
rules = [  ]
";
        let perms = load_from_str(&txt);
        assert_eq!(perms.len(), 1);
        let p = &perms[0];
        let f = FlagPerm {
            perm: p,
            context: &[6],
            flags: 2u8,
        };
        assert!(!f.check(false, &o_in))
    }
    #[test]
    fn test_wrong_context() {
        let o_in = ObjectIdentifier::new(&ARC_IN).unwrap(); // Checked #[test]
        let txt = "
[[groups]]
name = \"admin\"
level = \"authPriv\"
rules = [ {read = true, write = true, context=\"a\", include=[ \"1.1\" ], exclude = [ \"1.3.6.1.6.3.1.25\"]} ]
";
        let perms = load_from_str(&txt);
        assert_eq!(perms.len(), 1);
        let p = &perms[0];
        let f = FlagPerm {
            perm: p,
            context: &[6],
            flags: 2u8,
        };
        assert!(!f.check(false, &o_in))
    }
}
