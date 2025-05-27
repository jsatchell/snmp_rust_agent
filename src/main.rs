use rasn::types::OctetString;
use snmp_rust_agent::oidmap::OidMap;
use snmp_rust_agent::snmp_agent::Agent;
use snmp_rust_agent::stubs::load_stubs;
use snmp_rust_agent::usm;
use snmp_rust_agent::perms;
//use log::{debug, error, log_enabled, info, Level};
//use env_logger;

static ENGINESTR: &[u8; 11] = b"\x80\x00\x4e\x2c\x03\x34\x48\xed\x2d\xe2\x88";

/// Simplistic example main
fn main() -> std::io::Result<()> {
    env_logger::init();
    let perms: Vec<perms::Perm> = perms::load_perms();
    let users: Vec<usm::User> = usm::load_users(&perms);
    let mut oid_map = OidMap::new();
    load_stubs(&mut oid_map);
    // There are some helper functions in engine_id.rs that you can use
    let eid = OctetString::from_static(ENGINESTR);
    let mut agent: Agent = Agent::build(eid, "127.0.0.1:2161");
    agent.loop_forever(&mut oid_map, users);
    Ok(())
}
