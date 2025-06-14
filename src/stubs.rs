use crate::oidmap::OidMap;

mod snmpv2_stub;
mod snmp_user_based_sm_stub;


pub fn load_stubs(oid_map: &mut OidMap) {
    snmpv2_stub::load_stub(oid_map);
    snmp_user_based_sm_stub::load_stub(oid_map);
}
