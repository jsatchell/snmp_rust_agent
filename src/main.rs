#![warn(missing_docs)]
//! See documentation src/lib.rs
//!
use log::{debug, info};
use snmp_rust_agent::config::{ComplianceStatements, Config};
use snmp_rust_agent::handlers;
use snmp_rust_agent::oidmap::OidMap;
use snmp_rust_agent::perms;
use snmp_rust_agent::snmp_agent::Agent;
use snmp_rust_agent::stubs::load_stubs;
use snmp_rust_agent::usm;
use std::env;
use std::fs::read_to_string;

/// Simplistic example main. Loads configuration from file.
fn main() -> std::io::Result<()> {
    // Replace this if you use some other sort of logger.
    // Set a sane default if the enviroment variable doesn't exist
    if env::var("RUST_LOG").is_err() {
        println!("RUST_LOG environment variable not set, defaulting to warn");
        env::set_var("RUST_LOG", "warn");
    }
    env_logger::init();
    // Load configuration
    let conf = Config::load();
    let users_text = read_to_string(conf.users_file.clone()).expect("Could not read user file");
    let perms_text =
        read_to_string(conf.perms_file.clone()).expect("Could not read permissions file");
    let perms: Vec<perms::Perm> = perms::load_from_str(&perms_text);

    let mut users: usm::Users = usm::Users::new();
    users.load_from_str(&perms, &users_text);

    let mut agent: Agent = Agent::build(conf.engine_id.clone(), &conf.listen, conf.send_auth_fails);
    if conf.trap_sink.is_empty() {
        debug!("No Trapsink defined in config, won't start notifier");
    } else {
        info!("Starting notifier for {0}", conf.trap_sink);
        agent.start_notifier(&conf.trap_sink);
    }
    let mut oid_map: OidMap = OidMap::new();
    let mut comp = ComplianceStatements::new();
    // Populate oid_map for stubs
    load_stubs(&mut oid_map, &mut comp);
    // Some of the handlers use values from the config, users or the agent itself
    handlers::load_stubs(&mut oid_map, &conf, &agent, &users, &mut comp);
    agent.loop_forever(&mut oid_map, &users);
    Ok(())
}
