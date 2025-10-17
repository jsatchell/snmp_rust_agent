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
//! * StoragePath - path to writeable directory where persistence files will be written.
//!
//! These keys are optional, and zero length strings will be used if they are absent.
//! * Contact - name and email (or other) address for person responsible for system where Agent is running
//! * TrapSink - address and port where Trap PDUs will be sent when the agent has trap support.
//! * SendAuthenticationFailures - if "true" or "t", and TrapSink is defined, send authentication failure traps.
//!
//! These three have built-in defaults, corresponding to the legacy fixed values
//! * PermissionsFile - toml file containing the group permissions data, defaults to groups.toml
//! * UsersFile - username and password data, defaults to users.txt
//! * TrapCommunity - community name for v2 notifications. If not set, defaults to "public".
//!
//! These have built-in defaults and are not used yet, but will be when notifications support Inform messages.
//! * InformTimeout - time in seconds, must be parseable to a positive integer. Default 30, max 2^16 - 1
//! * InformRetries - number of retries of sending Inform if not acknowledged. Must be parseable to a positive integer. Default 2, max 255
//!
//! Panics if the file cannot be found, has missing compulsory keys or on parse errors.
//!

use crate::engine_id;
use log::{debug, error};
use rasn::types::OctetString;
use std::fs::{exists, read_to_string};

/// Search path for config files.
///
/// FIXME *nix centric - put something in for Mac and Windows
const CONF_FILES: [&str; 3] = [
    "/etc/snmp-agent/snmp-agent.conf",
    "~/.snmp-agent.conf",
    ".snmp-agent.conf",
];

/// Config struct gathers parameter values from file, to control
/// agent start-up.
pub struct Config {
    pub engine_id: OctetString,
    pub fqdn: String,
    pub listen: String,
    pub storage_path: String,
    pub contact: String,
    pub trap_sink: String,
    pub trap_community: String,
    pub send_auth_fails: bool,
    pub perms_file: String,
    pub users_file: String,
    pub inform_timeout: u16,
    pub inform_retries: u8,
}

impl Config {
    /// Create a config struct by reading the contents of filename and parseing the contents.
    fn from_file(filename: &str) -> Self {
        let text = read_to_string(filename).unwrap(); // Startup
        Config::from_str(&text)
    }

    /// Create a config struct by parseing the string in text.
    ///
    fn from_str(text: &str) -> Self {
        let mut eid: OctetString = OctetString::from_static(b"");
        let mut fqdn = "".to_string();
        let mut contact = "".to_string();
        let mut storage_path = "".to_string();
        let mut listen = "".to_string();
        let mut trap_sink = "".to_string();
        let mut trap_community = "public".to_string();
        let mut send_auth_fails: bool = false;
        let mut perms_file = "groups.toml".to_string();
        let mut users_file = "users.txt".to_string();
        let mut inform_timeout: u16 = 30;
        let mut inform_retries: u8 = 2;
        let mut got_eid = false;
        let mut got_fqdn = false;
        let mut got_listen = false;
        let mut got_path = false;
        for line in text.lines() {
            // Startup
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
                "StoragePath" => {
                    storage_path = parts[1].to_string();
                    got_path = true;
                }
                "Contact" => contact = parts[1].to_string(),
                "TrapSink" => trap_sink = parts[1].to_string(),
                "TrapCommunity" => trap_community = parts[1].to_string(),
                "SendAuthenticationFailures" => send_auth_fails = parts[1].contains("t"),
                "PermissionsFile" => perms_file = parts[1].to_string(),
                "UsersFile" => users_file = parts[1].to_string(),
                "InformRetries" => inform_retries = parts[1].parse().unwrap(), // Startup
                "InformTimeout" => inform_timeout = parts[1].parse().unwrap(), // Startup
                _ => {
                    debug!("Unexpected keyword in config file {0}", parts[0]);
                }
            }
        }
        if got_eid && got_fqdn && got_listen && got_path {
            debug!("All compulsory values found");
        } else {
            if !got_eid {
                error!("EngineID not found in config file");
            }
            if !got_listen {
                error!("Listen not found in config file");
            }
            if !got_fqdn {
                error!("FQDN not found in config file");
            }
            if !got_path {
                error!("StoragePath not found in config file");
            }
            panic!("Missing essential keys in config file");
        }
        debug!("Engine ID {0}", engine_id::format_engine_id(eid.clone()));
        Config {
            engine_id: eid,
            fqdn,
            listen,
            storage_path,
            contact,
            trap_sink,
            trap_community,
            send_auth_fails,
            perms_file,
            users_file,
            inform_retries,
            inform_timeout,
        }
    }

    /// Create a config struct by searching for file in well known places.
    ///
    ///  Panics if the file cannot be found, does not contain all the compulsory keys or on parse errors.
    pub fn load() -> Self {
        for name in CONF_FILES {
            let good = exists(name);
            if let Ok(is_good) = good {
                if is_good {
                    return Config::from_file(name);
                }
            }
        }
        panic!("No configuration file found");
    }
}

pub struct ComplianceStatements {
    pub claims: Vec<(&'static [u32], &'static str)>,
}

impl ComplianceStatements {
    pub fn new() -> Self {
        ComplianceStatements { claims: vec![] }
    }

    pub fn register_compliance(&mut self, arc: &'static [u32], text: &'static str, doit: bool) {
        if doit {
            self.claims.push((arc, text));
        }
    }
}

impl Default for ComplianceStatements {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARC: [u32; 2] = [1, 1];
    #[test]
    fn test_load() {
        let _c = Config::load();
    }

    #[test]
    fn test_compliance() {
        let mut c = ComplianceStatements::default();

        c.register_compliance(&ARC, "test", false);
        c.register_compliance(&ARC, "test", true);
        assert_eq!(c.claims.len(), 1);
    }

    #[test]
    #[should_panic]
    fn test_missing() {
        let _c = Config::from_str(
            "
SendAuthenticationFailures true
PermissionsFile groups.toml
TrapSink localhost:162
TrapCommunity private
UsersFile users.txt
InformRetries 2
InformTimeout 10
Unexpected Keyword",
        );
    }
}
