use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use crate::keeper::oid_keep::{Access, OidKeeper, ScalarMemOid, TableMemOid};
use crate::oidmap::OidMap;

const ARC_USM_STATS_UNSUPPORTED_SEC_LEVELS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 1] ;
const ARC_USM_STATS_NOT_IN_TIME_WINDOWS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 2] ;
const ARC_USM_STATS_UNKNOWN_USER_NAMES: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 3] ;
const ARC_USM_STATS_UNKNOWN_ENGINE_I_DS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 4] ;
const ARC_USM_STATS_WRONG_DIGESTS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 5] ;
const ARC_USM_STATS_DECRYPTION_ERRORS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 6] ;
const ARC_USM_USER_SPIN_LOCK: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 2, 1] ;
const ARC_USM_USER_TABLE: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 2, 2] ;

fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

fn simple_from_str() -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_static(b"value")))
}

pub fn load_stub(oid_map: &mut OidMap) {
    let s42 = simple_from_int(42);
    let sval = simple_from_str();
    let oid_usm_stats_unsupported_sec_levels: ObjectIdentifier = ObjectIdentifier::new(&ARC_USM_STATS_UNSUPPORTED_SEC_LEVELS).unwrap();
    let k_usm_stats_unsupported_sec_levels: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_usm_stats_unsupported_sec_levels, k_usm_stats_unsupported_sec_levels);
    let oid_usm_stats_not_in_time_windows: ObjectIdentifier = ObjectIdentifier::new(&ARC_USM_STATS_NOT_IN_TIME_WINDOWS).unwrap();
    let k_usm_stats_not_in_time_windows: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_usm_stats_not_in_time_windows, k_usm_stats_not_in_time_windows);
    let oid_usm_stats_unknown_user_names: ObjectIdentifier = ObjectIdentifier::new(&ARC_USM_STATS_UNKNOWN_USER_NAMES).unwrap();
    let k_usm_stats_unknown_user_names: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_usm_stats_unknown_user_names, k_usm_stats_unknown_user_names);
    let oid_usm_stats_unknown_engine_i_ds: ObjectIdentifier = ObjectIdentifier::new(&ARC_USM_STATS_UNKNOWN_ENGINE_I_DS).unwrap();
    let k_usm_stats_unknown_engine_i_ds: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_usm_stats_unknown_engine_i_ds, k_usm_stats_unknown_engine_i_ds);
    let oid_usm_stats_wrong_digests: ObjectIdentifier = ObjectIdentifier::new(&ARC_USM_STATS_WRONG_DIGESTS).unwrap();
    let k_usm_stats_wrong_digests: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_usm_stats_wrong_digests, k_usm_stats_wrong_digests);
    let oid_usm_stats_decryption_errors: ObjectIdentifier = ObjectIdentifier::new(&ARC_USM_STATS_DECRYPTION_ERRORS).unwrap();
    let k_usm_stats_decryption_errors: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadOnly));
    oid_map.push(oid_usm_stats_decryption_errors, k_usm_stats_decryption_errors);
    let oid_usm_user_spin_lock: ObjectIdentifier = ObjectIdentifier::new(&ARC_USM_USER_SPIN_LOCK).unwrap();
    let k_usm_user_spin_lock: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadWrite));
    oid_map.push(oid_usm_user_spin_lock, k_usm_user_spin_lock);
    let oid_usm_user_table: ObjectIdentifier = ObjectIdentifier::new(&ARC_USM_USER_TABLE).unwrap();
    let k_usm_user_table: Box<dyn OidKeeper> = Box::new(TableMemOid::new(
        vec![vec![sval.clone(), sval.clone(), sval.clone(), s42.clone(), s42.clone(), sval.clone(), sval.clone(), s42.clone(), sval.clone(), sval.clone(), sval.clone(), s42.clone(), s42.clone()]],
        13,
        &oid_usm_user_table,
        vec!['s', 's', 's', 'o', 'o', 's', 's', 'o', 's', 's', 's', 'i', 'i'],
        vec![Access::NoAccess, Access::NoAccess, Access::ReadOnly, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate],
        vec![1, 2],
        false
    ));
    oid_map.push(oid_usm_user_table, k_usm_user_table);
}