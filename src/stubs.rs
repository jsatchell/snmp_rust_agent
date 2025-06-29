//! Stub loader generated by stub-gen.
//!
//! Do not edit - it will be over-written next time you run stub-gen
use crate::oidmap::OidMap;

mod snmp_user_based_sm_stub;
mod snmpv2_stub;

///Generated function to load all stubs
pub fn load_stubs(oid_map: &mut OidMap) {
    snmpv2_stub::load_stub(oid_map);
    snmp_user_based_sm_stub::load_stub(oid_map);
}
