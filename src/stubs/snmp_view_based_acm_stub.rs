use crate::keeper::oid_keep::{Access, OidErr, OidKeeper, ScalarMemOid, TableMemOid};
use crate::oidmap::OidMap;
use rasn::types::{Integer, ObjectIdentifier, OctetString};

use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use rasn_snmp::v3::{VarBind, VarBindValue};

fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

fn simple_from_str(value: &'static [u8]) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_static(value)))
}

fn simple_from_vec(value: &'static [u32]) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::ObjectId(
        ObjectIdentifier::new(value).unwrap(),
    ))
}

const ARC_VACM_CONTEXT_TABLE: [u32; 9] = [1, 3, 6, 1, 6, 3, 16, 1, 1];
const ARC_VACM_SECURITY_TO_GROUP_TABLE: [u32; 9] = [1, 3, 6, 1, 6, 3, 16, 1, 2];
const ARC_VACM_ACCESS_TABLE: [u32; 9] = [1, 3, 6, 1, 6, 3, 16, 1, 4];
const ARC_VACM_VIEW_SPIN_LOCK: [u32; 10] = [1, 3, 6, 1, 6, 3, 16, 1, 5, 1];
const ARC_VACM_VIEW_TREE_FAMILY_TABLE: [u32; 10] = [1, 3, 6, 1, 6, 3, 16, 1, 5, 2];

// Now the OBJECT-TYPES. These need actual code added to the stubs

// Information about a particular context.
struct KeepVacmcontexttable {
    table: TableMemOid,
}

impl KeepVacmcontexttable {
    fn new() -> Self {
        let base_oid: ObjectIdentifier = ObjectIdentifier::new(&ARC_VACM_CONTEXT_TABLE).unwrap();

        KeepVacmcontexttable {
            table: TableMemOid::new(
                vec![vec![simple_from_str(b"b")]],
                1,
                &base_oid,
                vec!['s'],
                vec![Access::ReadOnly],
                vec![1],
                false,
            ),
        }
    }
}

impl OidKeeper for KeepVacmcontexttable {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {
        false
    }
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
        self.table.get(oid)
    }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
        self.table.get_next(oid)
    }
    fn access(&self, oid: ObjectIdentifier) -> Access {
        self.table.access(oid)
    }
    fn set(&mut self, oid: ObjectIdentifier, value: VarBindValue) -> Result<VarBindValue, OidErr> {
        self.table.set(oid, value)
    }
}

// An entry in this table maps the combination of a
// securityModel and securityName into a groupName.
//
struct KeepVacmsecuritytogrouptable {
    table: TableMemOid,
}

impl KeepVacmsecuritytogrouptable {
    fn new() -> Self {
        let base_oid: ObjectIdentifier =
            ObjectIdentifier::new(&ARC_VACM_SECURITY_TO_GROUP_TABLE).unwrap();

        KeepVacmsecuritytogrouptable {
            table: TableMemOid::new(
                vec![vec![
                    simple_from_int(4),
                    simple_from_str(b"b"),
                    simple_from_str(b"b"),
                    simple_from_int(3),
                    simple_from_int(4),
                ]],
                5,
                &base_oid,
                vec!['i', 's', 's', 'i', 'i'],
                vec![
                    Access::NoAccess,
                    Access::NoAccess,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                ],
                vec![1, 2],
                false,
            ),
        }
    }
}

impl OidKeeper for KeepVacmsecuritytogrouptable {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {
        false
    }
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
        self.table.get(oid)
    }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
        self.table.get_next(oid)
    }
    fn access(&self, oid: ObjectIdentifier) -> Access {
        self.table.access(oid)
    }
    fn set(&mut self, oid: ObjectIdentifier, value: VarBindValue) -> Result<VarBindValue, OidErr> {
        self.table.set(oid, value)
    }
}

// An access right configured in the Local Configuration
// Datastore (LCD) authorizing access to an SNMP context.
//
// Entries in this table can use an instance value for
// object vacmGroupName even if no entry in table
// vacmAccessSecurityToGroupTable has a corresponding
// value for object vacmGroupName.
//
struct KeepVacmaccesstable {
    table: TableMemOid,
}

impl KeepVacmaccesstable {
    fn new() -> Self {
        let base_oid: ObjectIdentifier = ObjectIdentifier::new(&ARC_VACM_ACCESS_TABLE).unwrap();

        KeepVacmaccesstable {
            table: TableMemOid::new(
                vec![vec![
                    simple_from_str(b"b"),
                    simple_from_int(4),
                    simple_from_int(4),
                    simple_from_int(1),
                    simple_from_str(b""),
                    simple_from_str(b""),
                    simple_from_str(b""),
                    simple_from_int(3),
                    simple_from_int(4),
                ]],
                9,
                &base_oid,
                vec!['s', 'i', 'i', 'i', 's', 's', 's', 'i', 'i'],
                vec![
                    Access::NoAccess,
                    Access::NoAccess,
                    Access::NoAccess,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                ],
                vec![1, 2, 3],
                false,
            ),
        }
    }
}

impl OidKeeper for KeepVacmaccesstable {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {
        false
    }
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
        self.table.get(oid)
    }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
        self.table.get_next(oid)
    }
    fn access(&self, oid: ObjectIdentifier) -> Access {
        self.table.access(oid)
    }
    fn set(&mut self, oid: ObjectIdentifier, value: VarBindValue) -> Result<VarBindValue, OidErr> {
        self.table.set(oid, value)
    }
}

// An advisory lock used to allow cooperating SNMP
// Command Generator applications to coordinate their
// use of the Set operation in creating or modifying
// views.
//
// When creating a new view or altering an existing
// view, it is important to understand the potential
// interactions with other uses of the view.  The
// vacmViewSpinLock should be retrieved.  The name of
// the view to be created should be determined to be
// unique by the SNMP Command Generator application by
// consulting the vacmViewTreeFamilyTable.  Finally,
// the named view may be created (Set), including the
// advisory lock.
// If another SNMP Command Generator application has
// altered the views in the meantime, then the spin
// lock's value will have changed, and so this creation
// will fail because it will specify the wrong value for
// the spin lock.
//
// Since this is an advisory lock, the use of this lock
// is not enforced.
//
struct KeepVacmviewspinlock {
    scalar: ScalarMemOid,
}

impl KeepVacmviewspinlock {
    fn new() -> Self {
        KeepVacmviewspinlock {
            scalar: ScalarMemOid::new(simple_from_int(4), 'i', Access::ReadWrite),
        }
    }
}

impl OidKeeper for KeepVacmviewspinlock {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {
        true
    }
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
        self.scalar.get(oid)
    }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
        self.scalar.get_next(oid)
    }
    fn access(&self, oid: ObjectIdentifier) -> Access {
        self.scalar.access(oid)
    }
    fn set(&mut self, oid: ObjectIdentifier, value: VarBindValue) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value)
    }
}

// Information on a particular family of view subtrees
// included in or excluded from a particular SNMP
// context's MIB view.
//
// Implementations must not restrict the number of
// families of view subtrees for a given MIB view,
// except as dictated by resource constraints on the
// overall number of entries in the
// vacmViewTreeFamilyTable.
//
// If no conceptual rows exist in this table for a given
// MIB view (viewName), that view may be thought of as
// consisting of the empty set of view subtrees.
//
struct KeepVacmviewtreefamilytable {
    table: TableMemOid,
}

impl KeepVacmviewtreefamilytable {
    fn new() -> Self {
        let base_oid: ObjectIdentifier =
            ObjectIdentifier::new(&ARC_VACM_VIEW_TREE_FAMILY_TABLE).unwrap();

        KeepVacmviewtreefamilytable {
            table: TableMemOid::new(
                vec![vec![
                    simple_from_str(b"b"),
                    simple_from_vec(&[1, 3, 6, 1]),
                    simple_from_str(b""),
                    simple_from_int(1),
                    simple_from_int(3),
                    simple_from_int(4),
                ]],
                6,
                &base_oid,
                vec!['s', 'o', 's', 'i', 'i', 'i'],
                vec![
                    Access::NoAccess,
                    Access::NoAccess,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                ],
                vec![1, 2],
                false,
            ),
        }
    }
}

impl OidKeeper for KeepVacmviewtreefamilytable {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {
        false
    }
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
        self.table.get(oid)
    }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
        self.table.get_next(oid)
    }
    fn access(&self, oid: ObjectIdentifier) -> Access {
        self.table.access(oid)
    }
    fn set(&mut self, oid: ObjectIdentifier, value: VarBindValue) -> Result<VarBindValue, OidErr> {
        self.table.set(oid, value)
    }
}

pub fn load_stub(oid_map: &mut OidMap) {
    let oid_vacm_context_table: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_VACM_CONTEXT_TABLE).unwrap();
    let k_vacm_context_table: Box<dyn OidKeeper> = Box::new(KeepVacmcontexttable::new());
    oid_map.push(oid_vacm_context_table, k_vacm_context_table);
    let oid_vacm_security_to_group_table: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_VACM_SECURITY_TO_GROUP_TABLE).unwrap();
    let k_vacm_security_to_group_table: Box<dyn OidKeeper> =
        Box::new(KeepVacmsecuritytogrouptable::new());
    oid_map.push(
        oid_vacm_security_to_group_table,
        k_vacm_security_to_group_table,
    );
    let oid_vacm_access_table: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_VACM_ACCESS_TABLE).unwrap();
    let k_vacm_access_table: Box<dyn OidKeeper> = Box::new(KeepVacmaccesstable::new());
    oid_map.push(oid_vacm_access_table, k_vacm_access_table);
    let oid_vacm_view_spin_lock: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_VACM_VIEW_SPIN_LOCK).unwrap();
    let k_vacm_view_spin_lock: Box<dyn OidKeeper> = Box::new(KeepVacmviewspinlock::new());
    oid_map.push(oid_vacm_view_spin_lock, k_vacm_view_spin_lock);
    let oid_vacm_view_tree_family_table: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_VACM_VIEW_TREE_FAMILY_TABLE).unwrap();
    let k_vacm_view_tree_family_table: Box<dyn OidKeeper> =
        Box::new(KeepVacmviewtreefamilytable::new());
    oid_map.push(
        oid_vacm_view_tree_family_table,
        k_vacm_view_tree_family_table,
    );
}
