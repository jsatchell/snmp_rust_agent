use crate::parser;
use crate::resolver;
use log::{error, warn};
use std::fs;

const MIB_SEARCH_PATH: [&str; 3] = [
    "/var/lib/mibs/ietf/",
    "/var/lib/mibs/iana/",
    "/usr/share/snmp/mibs/",
];

pub fn find_mib_text(mib_name: &str) -> Option<String> {
    for dirname in MIB_SEARCH_PATH {
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
        return vec![];
    }
    let missl = miss.len();
    let mut hit = 0;
    for _pass in 0..1 {
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
