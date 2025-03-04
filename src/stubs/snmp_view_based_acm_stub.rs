use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use crate::keeper::oid_keep::{Access, OidKeeper, ScalarMemOid, TableMemOid};
use crate::oidmap::OidMap;

const ARC_VACM_CONTEXT_TABLE: [u32; 9] = [1, 3, 6, 1, 6, 3, 16, 1, 1] ;
const ARC_VACM_SECURITY_TO_GROUP_TABLE: [u32; 9] = [1, 3, 6, 1, 6, 3, 16, 1, 2] ;
const ARC_VACM_ACCESS_TABLE: [u32; 9] = [1, 3, 6, 1, 6, 3, 16, 1, 4] ;
const ARC_VACM_VIEW_SPIN_LOCK: [u32; 10] = [1, 3, 6, 1, 6, 3, 16, 1, 5, 1] ;
const ARC_VACM_VIEW_TREE_FAMILY_TABLE: [u32; 10] = [1, 3, 6, 1, 6, 3, 16, 1, 5, 2] ;

fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

fn simple_from_str() -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_static(b"value")))
}

pub fn load_stub(oid_map: &mut OidMap) {
    let s42 = simple_from_int(42);
    let sval = simple_from_str();
    let oid_vacm_context_table: ObjectIdentifier = ObjectIdentifier::new(&ARC_VACM_CONTEXT_TABLE).unwrap();
    let k_vacm_context_table: Box<dyn OidKeeper> = Box::new(TableMemOid::new(
        vec![vec![sval.clone()]],
        1,
        &oid_vacm_context_table,
        vec!['s'],
        vec![Access::ReadOnly],
        vec![1],
        false
    ));
    oid_map.push(oid_vacm_context_table, k_vacm_context_table);
    let oid_vacm_security_to_group_table: ObjectIdentifier = ObjectIdentifier::new(&ARC_VACM_SECURITY_TO_GROUP_TABLE).unwrap();
    let k_vacm_security_to_group_table: Box<dyn OidKeeper> = Box::new(TableMemOid::new(
        vec![vec![s42.clone(), sval.clone(), sval.clone(), s42.clone(), s42.clone()]],
        5,
        &oid_vacm_security_to_group_table,
        vec!['i', 's', 's', 'i', 'i'],
        vec![Access::NoAccess, Access::NoAccess, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate],
        vec![1, 2],
        false
    ));
    oid_map.push(oid_vacm_security_to_group_table, k_vacm_security_to_group_table);
    let oid_vacm_access_table: ObjectIdentifier = ObjectIdentifier::new(&ARC_VACM_ACCESS_TABLE).unwrap();
    let k_vacm_access_table: Box<dyn OidKeeper> = Box::new(TableMemOid::new(
        vec![vec![sval.clone(), s42.clone(), s42.clone(), s42.clone(), sval.clone(), sval.clone(), sval.clone(), s42.clone(), s42.clone()]],
        9,
        &oid_vacm_access_table,
        vec!['s', 'i', 'i', 'i', 's', 's', 's', 'i', 'i'],
        vec![Access::NoAccess, Access::NoAccess, Access::NoAccess, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate],
        vec![1, 2, 3],
        false
    ));
    oid_map.push(oid_vacm_access_table, k_vacm_access_table);
    let oid_vacm_view_spin_lock: ObjectIdentifier = ObjectIdentifier::new(&ARC_VACM_VIEW_SPIN_LOCK).unwrap();
    let k_vacm_view_spin_lock: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', Access::ReadWrite));
    oid_map.push(oid_vacm_view_spin_lock, k_vacm_view_spin_lock);
    let oid_vacm_view_tree_family_table: ObjectIdentifier = ObjectIdentifier::new(&ARC_VACM_VIEW_TREE_FAMILY_TABLE).unwrap();
    let k_vacm_view_tree_family_table: Box<dyn OidKeeper> = Box::new(TableMemOid::new(
        vec![vec![sval.clone(), s42.clone(), sval.clone(), s42.clone(), s42.clone(), s42.clone()]],
        6,
        &oid_vacm_view_tree_family_table,
        vec!['s', 'o', 's', 'i', 'i', 'i'],
        vec![Access::NoAccess, Access::NoAccess, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate],
        vec![1, 2],
        false
    ));
    oid_map.push(oid_vacm_view_tree_family_table, k_vacm_view_tree_family_table);
}