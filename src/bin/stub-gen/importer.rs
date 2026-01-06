use crate::parser;
use crate::resolver;
use log::{error, warn};
use std::fs;

pub const MIB_SEARCH_PATH: [&str; 3] = [
    "/var/lib/mibs/ietf/",
    "/var/lib/mibs/iana/",
    "/usr/share/snmp/mibs/",
];

pub fn find_mib_text(mib_name: &str, path: &[String]) -> Option<String> {
    for dirname in path {
        for ext in ["", ".txt"] {
            let path = dirname.to_owned() + mib_name + ext;
            let read_ok = fs::read_to_string(&path);
            if let Ok(item) = read_ok {
                return Some(item);
            }
        }
    }
    None
}

pub fn process_one(
    raw: &str,
    miss: Vec<String>,
    mib_name: &str,
    res: &mut resolver::Resolver,
) -> Vec<parser::MibNode<'static>> {
    //

    let mut nodes = vec![];
    let mut found = vec![];

    let mut extra = vec![];
    let (good, _site) = parser::parse_mib(raw, &mut nodes);
    if !good {
        error!("parse failure processing import of {mib_name}");
        return vec![];
    }
    let missl = miss.len();
    let mut hit = 0;
    for _pass in 0..2 {
        let _res_cnt = res.try_nodes(&nodes);
    }
    for node in nodes {
        let nname = match node {
            parser::MibNode::ModId(ref o) => o.name,
            parser::MibNode::Tc(ref o) => o.name,
            parser::MibNode::ObTy(ref o) => o.name,
            parser::MibNode::ObIdf(ref o) => o.name,
            parser::MibNode::ObIdy(ref o) => o.name,
            parser::MibNode::ObGrp(ref o) => o.name,
            parser::MibNode::NtGrp(ref o) => o.name,
            _ => "",
        };
        for name in &miss {
            if nname == *name {
                hit += 1;
                extra.push(node.copy());
                found.push(name);
                break;
            }
        }
    }
    if hit < missl {
        error!("Not all imports found {hit} {missl}");
        for name in &miss {
            if !found.contains(&name) {
                warn!("Missing import {name} in {mib_name}");
            }
        }
    }
    extra
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_mib_text_none() {
        let res = find_mib_text("ZZZZ-NOT_THERE", &["BadPath".to_string()]);
        assert!(res.is_none());
    }

    #[test]
    fn test_find_mib_text_some() {
        let res = find_mib_text("importer.rs", &["src/bin/stub-gen/".to_string()]);
        assert!(res.is_some());
    }

    #[test]
    fn test_process_one() {
        let mut res = resolver::Resolver::new();
        let miss = vec![
            "wont-find-this".to_string(),
            "snmpUsmAesMIB".to_string(),
            "usmAesCfb128Protocol".to_string(),
        ];
        let mib_name = "TEST";
        let raw = "SNMP-USM-AES-MIB DEFINITIONS ::= BEGIN
    IMPORTS
        MODULE-IDENTITY, OBJECT-IDENTITY,
        snmpModules             FROM SNMPv2-SMI          -- [RFC2578]
        snmpPrivProtocols       FROM SNMP-FRAMEWORK-MIB; -- [RFC3411]

snmpUsmAesMIB  MODULE-IDENTITY
    LAST-UPDATED \"200406140000Z\"
    ORGANIZATION \"IETF\"
    CONTACT-INFO \"Uri Blumenthal\"

    DESCRIPTION  \"Definitions of Object Identities needed for
                  \"

    REVISION     \"200406140000Z\"
    DESCRIPTION  \"Initial version, published as RFC3826\"
    ::= { snmpModules 20 }

usmAesCfb128Protocol OBJECT-IDENTITY
    STATUS        current
    DESCRIPTION  \"The CFB128-AES-128 Privacy Protocol.\"
    REFERENCE    \"- Specification for the ADVANCED ENCRYPTION
                    STANDARD. Federal Information Processing
                    Standard (FIPS) Publication 197.
                    (November 2001).

                  - Dworkin, M., NIST Recommendation for Block
                    Cipher Modes of Operation, Methods and
                    Techniques. NIST Special Publication 800-38A
                    (December 2001).
                 \"
    ::= { snmpPrivProtocols 4 }

END
        ";
        let nodes = process_one(raw, miss, mib_name, &mut res);
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn test_process_one_bad_parse() {
        let mut res = resolver::Resolver::new();
        let miss = vec![];
        let mib_name = "TEST";
        let raw = "Some Garbage
        ";
        let nodes = process_one(raw, miss, mib_name, &mut res);
        assert_eq!(nodes.len(), 0);
    }
}
