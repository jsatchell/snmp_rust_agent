use rasn::types::{ObjectIdentifier, OctetString};

use snmp_rust_agent::snmp_agent::{always_42, Agent};

//Change this to match your organisation's IANA registartion, This example
// uses the "dynamic" MAC address scheme, but many other name systems work.
static ENGINESTR: &[u8; 11] = b"\x80\x00\x4e\x2c\x03\x34\x48\xed\x2d\xe2\x88";

fn main() -> std::io::Result<()> {
    let eid = OctetString::from_static(ENGINESTR);
    let mut agent = Agent::build(eid, "127.0.0.1:2161");
    let oid = ObjectIdentifier::new_unchecked(vec![1, 3, 6, 1, 6, 3, 15, 1, 1, 4].into());
    agent.insert(oid, always_42);
    agent.loop_forever();
    Ok(())
}
