use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use crate::keeper::oid_keep::{Access, OidKeeper, ScalarMemOid, TableMemOid};
use crate::oidmap::OidMap;

const ARC_SYS_DESCR: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 1] ;
const ARC_SYS_OBJECT_I_D: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 2] ;
const ARC_SYS_UP_TIME: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 3] ;
const ARC_SYS_CONTACT: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 4] ;
const ARC_SYS_NAME: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 5] ;
const ARC_SYS_LOCATION: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 6] ;
const ARC_SYS_SERVICES: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 7] ;
const ARC_SYS_O_R_LAST_CHANGE: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 8] ;
const ARC_SYS_O_R_TABLE: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 9] ;
const ARC_SNMP_IN_PKTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 1] ;
const ARC_SNMP_IN_BAD_VERSIONS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 3] ;
const ARC_SNMP_IN_BAD_COMMUNITY_NAMES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 4] ;
const ARC_SNMP_IN_BAD_COMMUNITY_USES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 5] ;
const ARC_SNMP_IN_A_S_N_PARSE_ERRS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 6] ;
const ARC_SNMP_ENABLE_AUTHEN_TRAPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 30] ;
const ARC_SNMP_SILENT_DROPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 31] ;
const ARC_SNMP_PROXY_DROPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 32] ;
const ARC_SNMP_TRAP_O_I_D: [u32; 10] = [1, 3, 6, 1, 6, 3, 1, 1, 4, 1] ;
const ARC_SNMP_TRAP_ENTERPRISE: [u32; 10] = [1, 3, 6, 1, 6, 3, 1, 1, 4, 3] ;
const ARC_SNMP_SET_SERIAL_NO: [u32; 10] = [1, 3, 6, 1, 6, 3, 1, 1, 6, 1] ;
const ARC_SNMP_OUT_PKTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 2] ;
const ARC_SNMP_IN_TOO_BIGS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 8] ;
const ARC_SNMP_IN_NO_SUCH_NAMES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 9] ;
const ARC_SNMP_IN_BAD_VALUES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 10] ;
const ARC_SNMP_IN_READ_ONLYS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 11] ;
const ARC_SNMP_IN_GEN_ERRS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 12] ;
const ARC_SNMP_IN_TOTAL_REQ_VARS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 13] ;
const ARC_SNMP_IN_TOTAL_SET_VARS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 14] ;
const ARC_SNMP_IN_GET_REQUESTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 15] ;
const ARC_SNMP_IN_GET_NEXTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 16] ;
const ARC_SNMP_IN_SET_REQUESTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 17] ;
const ARC_SNMP_IN_GET_RESPONSES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 18] ;
const ARC_SNMP_IN_TRAPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 19] ;
const ARC_SNMP_OUT_TOO_BIGS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 20] ;
const ARC_SNMP_OUT_NO_SUCH_NAMES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 21] ;
const ARC_SNMP_OUT_BAD_VALUES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 22] ;
const ARC_SNMP_OUT_GEN_ERRS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 24] ;
const ARC_SNMP_OUT_GET_REQUESTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 25] ;
const ARC_SNMP_OUT_GET_NEXTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 26] ;
const ARC_SNMP_OUT_SET_REQUESTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 27] ;
const ARC_SNMP_OUT_GET_RESPONSES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 28] ;
const ARC_SNMP_OUT_TRAPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 29] ;

fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

fn simple_from_str() -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_static(b"value")))
}

pub fn load_stub(oid_map: &mut OidMap) {
    let s42 = simple_from_int(42);
    let sval = simple_from_str();
    let oid_sys_descr: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_DESCR).unwrap();
    let k_sys_descr: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_sys_descr, k_sys_descr);
    let oid_sys_object_i_d: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_OBJECT_I_D).unwrap();
    let k_sys_object_i_d: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_sys_object_i_d, k_sys_object_i_d);
    let oid_sys_up_time: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_UP_TIME).unwrap();
    let k_sys_up_time: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_sys_up_time, k_sys_up_time);
    let oid_sys_contact: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_CONTACT).unwrap();
    let k_sys_contact: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadWrite));
    oid_map.push(oid_sys_contact, k_sys_contact);
    let oid_sys_name: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_NAME).unwrap();
    let k_sys_name: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadWrite));
    oid_map.push(oid_sys_name, k_sys_name);
    let oid_sys_location: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_LOCATION).unwrap();
    let k_sys_location: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadWrite));
    oid_map.push(oid_sys_location, k_sys_location);
    let oid_sys_services: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_SERVICES).unwrap();
    let k_sys_services: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_sys_services, k_sys_services);
    let oid_sys_o_r_last_change: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_O_R_LAST_CHANGE).unwrap();
    let k_sys_o_r_last_change: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_sys_o_r_last_change, k_sys_o_r_last_change);
    let oid_sys_o_r_table: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_O_R_TABLE).unwrap();
    let k_sys_o_r_table: Box<dyn OidKeeper> = Box::new(TableMemOid::new(
        vec![vec![s42.clone(), s42.clone(), sval.clone(), s42.clone()]],
        4,
        &oid_sys_o_r_table,
        vec!['i', 'o', 's', 't'],
        vec![Access::NoAccess, Access::ReadOnly, Access::ReadOnly, Access::ReadOnly],
        vec![1],
        false
    ));
    oid_map.push(oid_sys_o_r_table, k_sys_o_r_table);
    let oid_snmp_in_pkts: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_PKTS).unwrap();
    let k_snmp_in_pkts: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_pkts, k_snmp_in_pkts);
    let oid_snmp_in_bad_versions: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_BAD_VERSIONS).unwrap();
    let k_snmp_in_bad_versions: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_bad_versions, k_snmp_in_bad_versions);
    let oid_snmp_in_bad_community_names: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_BAD_COMMUNITY_NAMES).unwrap();
    let k_snmp_in_bad_community_names: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_bad_community_names, k_snmp_in_bad_community_names);
    let oid_snmp_in_bad_community_uses: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_BAD_COMMUNITY_USES).unwrap();
    let k_snmp_in_bad_community_uses: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_bad_community_uses, k_snmp_in_bad_community_uses);
    let oid_snmp_in_a_s_n_parse_errs: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_A_S_N_PARSE_ERRS).unwrap();
    let k_snmp_in_a_s_n_parse_errs: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_a_s_n_parse_errs, k_snmp_in_a_s_n_parse_errs);
    let oid_snmp_enable_authen_traps: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_ENABLE_AUTHEN_TRAPS).unwrap();
    let k_snmp_enable_authen_traps: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadWrite));
    oid_map.push(oid_snmp_enable_authen_traps, k_snmp_enable_authen_traps);
    let oid_snmp_silent_drops: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_SILENT_DROPS).unwrap();
    let k_snmp_silent_drops: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_silent_drops, k_snmp_silent_drops);
    let oid_snmp_proxy_drops: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_PROXY_DROPS).unwrap();
    let k_snmp_proxy_drops: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_proxy_drops, k_snmp_proxy_drops);
    let oid_snmp_trap_o_i_d: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_TRAP_O_I_D).unwrap();
    let k_snmp_trap_o_i_d: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::NotificationOnly));
    oid_map.push(oid_snmp_trap_o_i_d, k_snmp_trap_o_i_d);
    let oid_snmp_trap_enterprise: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_TRAP_ENTERPRISE).unwrap();
    let k_snmp_trap_enterprise: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::NotificationOnly));
    oid_map.push(oid_snmp_trap_enterprise, k_snmp_trap_enterprise);
    let oid_snmp_set_serial_no: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_SET_SERIAL_NO).unwrap();
    let k_snmp_set_serial_no: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadWrite));
    oid_map.push(oid_snmp_set_serial_no, k_snmp_set_serial_no);
    let oid_snmp_out_pkts: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_OUT_PKTS).unwrap();
    let k_snmp_out_pkts: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_out_pkts, k_snmp_out_pkts);
    let oid_snmp_in_too_bigs: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_TOO_BIGS).unwrap();
    let k_snmp_in_too_bigs: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_too_bigs, k_snmp_in_too_bigs);
    let oid_snmp_in_no_such_names: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_NO_SUCH_NAMES).unwrap();
    let k_snmp_in_no_such_names: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_no_such_names, k_snmp_in_no_such_names);
    let oid_snmp_in_bad_values: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_BAD_VALUES).unwrap();
    let k_snmp_in_bad_values: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_bad_values, k_snmp_in_bad_values);
    let oid_snmp_in_read_onlys: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_READ_ONLYS).unwrap();
    let k_snmp_in_read_onlys: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_read_onlys, k_snmp_in_read_onlys);
    let oid_snmp_in_gen_errs: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_GEN_ERRS).unwrap();
    let k_snmp_in_gen_errs: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_gen_errs, k_snmp_in_gen_errs);
    let oid_snmp_in_total_req_vars: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_TOTAL_REQ_VARS).unwrap();
    let k_snmp_in_total_req_vars: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_total_req_vars, k_snmp_in_total_req_vars);
    let oid_snmp_in_total_set_vars: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_TOTAL_SET_VARS).unwrap();
    let k_snmp_in_total_set_vars: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_total_set_vars, k_snmp_in_total_set_vars);
    let oid_snmp_in_get_requests: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_GET_REQUESTS).unwrap();
    let k_snmp_in_get_requests: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_get_requests, k_snmp_in_get_requests);
    let oid_snmp_in_get_nexts: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_GET_NEXTS).unwrap();
    let k_snmp_in_get_nexts: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_get_nexts, k_snmp_in_get_nexts);
    let oid_snmp_in_set_requests: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_SET_REQUESTS).unwrap();
    let k_snmp_in_set_requests: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_set_requests, k_snmp_in_set_requests);
    let oid_snmp_in_get_responses: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_GET_RESPONSES).unwrap();
    let k_snmp_in_get_responses: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_get_responses, k_snmp_in_get_responses);
    let oid_snmp_in_traps: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_TRAPS).unwrap();
    let k_snmp_in_traps: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_in_traps, k_snmp_in_traps);
    let oid_snmp_out_too_bigs: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_OUT_TOO_BIGS).unwrap();
    let k_snmp_out_too_bigs: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_out_too_bigs, k_snmp_out_too_bigs);
    let oid_snmp_out_no_such_names: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_OUT_NO_SUCH_NAMES).unwrap();
    let k_snmp_out_no_such_names: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_out_no_such_names, k_snmp_out_no_such_names);
    let oid_snmp_out_bad_values: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_OUT_BAD_VALUES).unwrap();
    let k_snmp_out_bad_values: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_out_bad_values, k_snmp_out_bad_values);
    let oid_snmp_out_gen_errs: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_OUT_GEN_ERRS).unwrap();
    let k_snmp_out_gen_errs: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_out_gen_errs, k_snmp_out_gen_errs);
    let oid_snmp_out_get_requests: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_OUT_GET_REQUESTS).unwrap();
    let k_snmp_out_get_requests: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_out_get_requests, k_snmp_out_get_requests);
    let oid_snmp_out_get_nexts: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_OUT_GET_NEXTS).unwrap();
    let k_snmp_out_get_nexts: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_out_get_nexts, k_snmp_out_get_nexts);
    let oid_snmp_out_set_requests: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_OUT_SET_REQUESTS).unwrap();
    let k_snmp_out_set_requests: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_out_set_requests, k_snmp_out_set_requests);
    let oid_snmp_out_get_responses: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_OUT_GET_RESPONSES).unwrap();
    let k_snmp_out_get_responses: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_out_get_responses, k_snmp_out_get_responses);
    let oid_snmp_out_traps: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_OUT_TRAPS).unwrap();
    let k_snmp_out_traps: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_snmp_out_traps, k_snmp_out_traps);
}