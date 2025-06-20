//! Configuration loader for SNMP Agent
//!
//! Looks for configuration file in some well known places,
//! and loads it. File is a text file of Key Value pairs, separated by a single space.
//! Unrecognized keys will be ignored.
//!
//! The following keys are compulsory, and the loader will panic if they are missing or not parsed:
//! * EngineID - engine_id_from_str in engine_id module for details.
//! * FQDN - Fully qualified hostname to use for system identification.
//! * Listen - the listen address and port. For many systems, this will be 0.0.0.0:161, but you may only want to listen on a trusted interface for devices like firewalls and routers.
//!
//! These keys are optional, and zero length strings will be used if they are absent.
//! * Contact - name and email (or other) address for person responsible for system where Agent is running
//!

use crate::engine_id;
use log::{debug, error};
use rasn::types::OctetString;
use std::fs::{exists, read_to_string};

pub struct Config {
    pub engine_id: OctetString,
    pub fqdn: String,
    pub listen: String,
    pub contact: String,
}

const CONF_FILES: [&str; 3] = [
    "/etc/snmp-agent/snmp-agent.conf",
    "~/.snmp-agent.conf",
    ".snmp-agent.conf",
];

impl Config {
    fn from_file(filename: &str) -> Self {
        let mut eid: OctetString = OctetString::from_static(b"");
        let mut fqdn = "".to_string();
        let mut contact = "".to_string();
        let mut listen = "".to_string();
        let mut got_eid = false;
        let mut got_fqdn = false;
        let mut got_listen = false;
        for line in read_to_string(filename).unwrap().lines() {
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            match parts[0] {
                "EngineID" => {
                    eid = engine_id::engine_id_from_str(parts[1]);
                    got_eid = true;
                }
                "FQDN" => {
                    fqdn = parts[1].to_string();
                    got_fqdn = true;
                }
                "Listen" => {
                    listen = parts[1].to_string();
                    got_listen = true;
                }
                "Contact" => contact = parts[1].to_string(),
                _ => {}
            }
        }
        if got_eid && got_fqdn && got_listen {
            debug!("All compulsory values found");
        } else {
            if !got_eid {
                error!("EngineID not found in config file")
            }
            if !got_listen {
                error!("Listen not found in config file")
            }
            if !got_fqdn {
                error!("FQDN not found in config file")
            }
            panic!("Missing essential keys in config file");
        }
        debug!("Engine ID {0}", engine_id::format_engine_id(eid.clone()));
        Config {
            engine_id: eid,
            fqdn,
            listen,
            contact,
        }
    }

    pub fn load() -> Self {
        for name in CONF_FILES {
            let good = exists(name);
            if good.is_ok() && good.unwrap() {
                return Config::from_file(name);
            }
        }
        panic!("No configuration file found")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load() {
        let _c = Config::load();
    }
}
