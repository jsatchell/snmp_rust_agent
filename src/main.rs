use snmp_rust_agent::config::Config;
use snmp_rust_agent::handlers;
use snmp_rust_agent::oidmap::OidMap;
use snmp_rust_agent::perms;
use snmp_rust_agent::snmp_agent::Agent;
use snmp_rust_agent::stubs::load_stubs;
use snmp_rust_agent::usm;

/// Simplistic example main. Loads configuration from file.
fn main() -> std::io::Result<()> {
    env_logger::init();
    let perms: Vec<perms::Perm> = perms::load_perms();
    let users: Vec<usm::User> = usm::load_users(&perms);
    let mut oid_map: OidMap = OidMap::new();
    let conf = Config::load();
    load_stubs(&mut oid_map);
    let mut agent: Agent = Agent::build(conf.engine_id.clone(), &conf.listen);
    handlers::load_stubs(&mut oid_map, &conf, &agent);
    agent.loop_forever(&mut oid_map, users);
    Ok(())
}
