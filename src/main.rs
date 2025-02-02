use rasn::types::{ObjectIdentifier, OctetString};

use snmp_rust_agent::keeper::oid_keep;
use snmp_rust_agent::snmp_agent::{Agent, OidMap};
//Change this to match your organisation's IANA registartion, This example
// uses the "dynamic" MAC address scheme, but many other name systems work.

const ARC: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 4];
const ARC1: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 5];
static ENGINESTR: &[u8; 11] = b"\x80\x00\x4e\x2c\x03\x34\x48\xed\x2d\xe2\x88";

fn main() -> std::io::Result<()> {
    let oid: ObjectIdentifier = ObjectIdentifier::new(&ARC).unwrap();
    let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC1).unwrap();
    let eid = OctetString::from_static(ENGINESTR);
    let mut k4 = oid_keep::ScalarMemOid::new(42);
    let mut k5 = oid_keep::ScalarMemOid::new(5);
    //snmp_engine_id::mac_engine_id(20012, "04:cf:4b:e3:cb:64");
    let mut oid_map = OidMap::new();
    oid_map.push((&oid, &mut k4));
    oid_map.push((&oid2, &mut k5));
    let mut agent: Agent = Agent::build(eid, "127.0.0.1:2161");
    agent.loop_forever(&mut oid_map);
    Ok(())
}
