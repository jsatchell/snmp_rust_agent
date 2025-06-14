use crate::parser;
use log::{debug, error};
use std::collections::HashMap;

pub struct Resolver {
    store: HashMap<&'static str, &'static [u32]>,
}

const ARC_INTERNET: [u32; 4] = [1, 3, 6, 1];
const ARC_MGMT: [u32; 5] = [1, 3, 6, 1, 2];
const ARC_MIB_2: [u32; 6] = [1, 3, 6, 1, 2, 1];
const ARC_SYSTEM: [u32; 7] = [1, 3, 6, 1, 2, 1, 1];
const ARC_TRANSMISSION: [u32; 7] = [1, 3, 6, 1, 2, 1, 10];
const ARC_EXPERIMENTAL: [u32; 5] = [1, 3, 6, 1, 3];
const ARC_PRIVATE: [u32; 5] = [1, 3, 6, 1, 4];
const ARC_ENTERPRISES: [u32; 6] = [1, 3, 6, 1, 4, 1];
const ARC_SNMPV2: [u32; 5] = [1, 3, 6, 1, 6];
const ARC_SNMP_DOMAINS: [u32; 6] = [1, 3, 6, 1, 6, 1];
const ARC_SNMP_PROXYS: [u32; 6] = [1, 3, 6, 1, 6, 2];
const ARC_SNMP_MODULES: [u32; 6] = [1, 3, 6, 1, 6, 3];
const ARC_SNMP_MIB: [u32; 7] = [1, 3, 6, 1, 6, 3, 1];
const ARC_SNMP_FRAMEWORK_MIB: [u32; 7] = [1, 3, 6, 1, 6, 3, 10];

impl Resolver {
    pub fn new() -> Self {
        let mut store: HashMap<&str, &[u32]> = HashMap::new();
        store.insert("internet", &ARC_INTERNET);
        store.insert("mgmt", &ARC_MGMT);
        store.insert("mib-2", &ARC_MIB_2);
        store.insert("system", &ARC_SYSTEM);
        store.insert("transmission", &ARC_TRANSMISSION);
        store.insert("internet", &ARC_INTERNET);
        store.insert("private", &ARC_PRIVATE);
        store.insert("experimental", &ARC_EXPERIMENTAL);
        store.insert("enterprises", &ARC_ENTERPRISES);
        store.insert("snmpV2", &ARC_SNMPV2);
        store.insert("snmpDomains", &ARC_SNMP_DOMAINS);
        store.insert("snmpProxys", &ARC_SNMP_PROXYS);
        store.insert("snmpModules", &ARC_SNMP_MODULES);
        store.insert("snmpMIB", &ARC_SNMP_MIB);
        store.insert("snmpFrameworkMIB", &ARC_SNMP_FRAMEWORK_MIB);
        Resolver { store }
    }

    /*   pub fn check_parent(&self, parent: &str) -> bool {
        self.store.contains_key(parent)
    } */

    pub fn lookup(&self, name: &str) -> &[u32] {
        if !self.store.contains_key(name) {
            error!("Unresolvable |{name}|");
        } else {
            debug!("Res {name}");
        }
        self.store[name]
    }

    pub fn try_add(&mut self, name: &str, parent: &str, nums: &[u32]) -> bool {
        let have = self.store.contains_key(parent);
        debug!("try add {name} {parent} {have}");
        if self.store.contains_key(name) {
            debug!("Warning - redefining {name}");
        }
        if have {
            let mut new_arc: Box<Vec<u32>> = Box::default();
            let name_copy: Box<String> = Box::new(name.to_string());
            for num in self.store[parent] {
                new_arc.push(*num)
            }
            for num in nums {
                new_arc.push(*num);
            }
            let arc_ref: &'static mut Vec<u32> = Box::leak(new_arc);
            let name_ref: &'static mut String = Box::leak(name_copy);
            self.store.insert(name_ref, arc_ref);
        }
        have
    }

    pub fn try_nodes(&mut self, nodes: &[parser::MibNode]) -> u32 {
        let mut good = 0u32;
        for node in nodes {
            match node {
                parser::MibNode::ModId(ref o) => {
                    if self.try_add(o.name, o.val.parent, &o.val.num) {
                        good += 1;
                    }
                }
                parser::MibNode::ObTy(ref o) => {
                    if self.try_add(o.name, o.val.parent, &o.val.num) {
                        good += 1;
                    }
                }
                parser::MibNode::ObIdf(ref o) => {
                    if self.try_add(o.name, o.val.parent, &o.val.num) {
                        good += 1;
                    }
                }
                parser::MibNode::ObIdy(ref o) => {
                    if self.try_add(o.name, o.val.parent, &o.val.num) {
                        good += 1;
                    }
                }
                _ => (),
            };
        }
        good
    }
}
