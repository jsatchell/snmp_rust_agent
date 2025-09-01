#![warn(missing_docs)]
//! See documentation src/lib.rs
//! 
use log::{debug, info};
use snmp_rust_agent::config::{Config, ComplianceStatements};
use snmp_rust_agent::handlers;
use snmp_rust_agent::oidmap::OidMap;
use snmp_rust_agent::perms;
use snmp_rust_agent::snmp_agent::Agent;
use snmp_rust_agent::stubs::load_stubs;
use snmp_rust_agent::usm;


/// Simplistic example main. Loads configuration from file.
fn main() -> std::io::Result<()> {
    // Replace this if you use some other sort of logger.
    env_logger::init();
    let perms: Vec<perms::Perm> = perms::load_perms();
    let mut users: usm::Users<'_> = usm::Users::new();
    let mut comp = ComplianceStatements::new();
    users.load_from_file(&perms);
    let mut oid_map: OidMap = OidMap::new();
    // Load configuration
    let conf = Config::load();
    // Populate oid_map for stubs
    load_stubs(&mut oid_map, &mut comp);
    let mut agent: Agent = Agent::build(conf.engine_id.clone(), &conf.listen);
    if conf.trap_sink.is_empty() {
        debug!("No Trapsink defined in config, won't start notifier");
    } else {
        info!("Starting notifier for {0}", conf.trap_sink);
        agent.start_notifier(&conf.trap_sink);
    }
    // Some of the handlers use values from the config or the agent itself
    handlers::load_stubs(&mut oid_map, &conf, &agent, &users, &mut comp);
    agent.loop_forever(&mut oid_map, users);
    Ok(())
}
