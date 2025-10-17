use crate::config::ComplianceStatements;
use crate::keeper::{Access, OType, OidErr, OidKeeper};
use crate::oidmap::OidMap;
use crate::scalar::ScalarMemOid;
use crate::snmp_agent::Agent;
use crate::table::TableMemOid;
use crate::usm::User;
use crate::utils::*;
use rasn::types::ObjectIdentifier;

use rasn_snmp::v2::ObjectSyntax;
use rasn_snmp::v3::{VarBind, VarBindValue};
const ARC_SNMP_TARGET_SPIN_LOCK: [u32; 9] = [1, 3, 6, 1, 6, 3, 12, 1, 1];
const ARC_SNMP_TARGET_ADDR_TABLE: [u32; 9] = [1, 3, 6, 1, 6, 3, 12, 1, 2];
const ARC_SNMP_TARGET_PARAMS_TABLE: [u32; 9] = [1, 3, 6, 1, 6, 3, 12, 1, 3];
const ARC_SNMP_UNAVAILABLE_CONTEXTS: [u32; 9] = [1, 3, 6, 1, 6, 3, 12, 1, 4];
const ARC_SNMP_UNKNOWN_CONTEXTS: [u32; 9] = [1, 3, 6, 1, 6, 3, 12, 1, 5];
const COMPLIANCE_SNMP_TARGET_COMMAND_RESPONDER_COMPLIANCE: [u32; 10] =
    [1, 3, 6, 1, 6, 3, 12, 3, 1, 1];

// Now the OBJECT-TYPES. These need actual code added to the stubs

// This object is used to facilitate modification of table
// entries in the SNMP-TARGET-MIB module by multiple
// managers.  In particular, it is useful when modifying
// the value of the snmpTargetAddrTagList object.
//
// The procedure for modifying the snmpTargetAddrTagList
// object is as follows:
//
// 1.  Retrieve the value of snmpTargetSpinLock and
// of snmpTargetAddrTagList.
//
// 2.  Generate a new value for snmpTargetAddrTagList.
//
// 3.  Set the value of snmpTargetSpinLock to the
// retrieved value, and the value of
// snmpTargetAddrTagList to the new value.  If
// the set fails for the snmpTargetSpinLock
// object, go back to step 1.

struct KeepSnmpTargetSpinLock {
    scalar: ScalarMemOid,
}

impl KeepSnmpTargetSpinLock {
    fn new() -> Self {
        KeepSnmpTargetSpinLock {
            scalar: ScalarMemOid::new(simple_from_int(4), OType::TestAndIncr, Access::ReadWrite),
        }
    }
}

impl OidKeeper for KeepSnmpTargetSpinLock {
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
    fn set(
        &mut self,
        oid: ObjectIdentifier,
        value: VarBindValue,
        user: &User,
    ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value, user)
    }
    fn begin_transaction(&mut self) -> Result<(), OidErr> {
        self.scalar.begin_transaction()
    }
    fn commit(&mut self, user: &User) -> Result<(), OidErr> {
        self.scalar.commit(user)
    }
    fn rollback(&mut self) -> Result<(), OidErr> {
        self.scalar.rollback()
    }
}
// A transport address to be used in the generation
// of SNMP operations.
//
// Entries in the snmpTargetAddrTable are created and
// deleted using the snmpTargetAddrRowStatus object.

struct KeepSnmpTargetAddrTable {
    table: TableMemOid,
}

impl KeepSnmpTargetAddrTable {
    fn new() -> Self {
        let base_oid: ObjectIdentifier =
            ObjectIdentifier::new(&ARC_SNMP_TARGET_ADDR_TABLE).unwrap();

        let mut tab = KeepSnmpTargetAddrTable {
            table: TableMemOid::new(
                vec![
                    simple_from_str(b"b"),
                    simple_from_vec(&[1, 3, 6, 1]),
                    simple_from_str(b"b"),
                    simple_from_int(1500),
                    simple_from_int(3),
                    simple_from_str(b"b"),
                    simple_from_str(b"b"),
                    simple_from_int(3),
                    simple_from_int(4),
                ],
                9,
                &base_oid,
                vec![
                    OType::String,
                    OType::ObjectId,
                    OType::String,
                    OType::Integer,
                    OType::Integer,
                    OType::String,
                    OType::String,
                    OType::Integer,
                    OType::Integer,
                ],
                vec![
                    Access::NoAccess,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                ],
                vec![1],
                true,
            ),
        };
        // No initial row
        tab.table.set_data(vec![]);
        tab
    }
}

impl OidKeeper for KeepSnmpTargetAddrTable {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {
        false
    }
    fn is_empty(&self) -> bool {
        self.table.is_empty()
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
    fn set(
        &mut self,
        oid: ObjectIdentifier,
        value: VarBindValue,
        user: &User,
    ) -> Result<VarBindValue, OidErr> {
        self.table.set(oid, value, user)
    }
    fn begin_transaction(&mut self) -> Result<(), OidErr> {
        self.table.begin_transaction()
    }
    fn commit(&mut self, user: &User) -> Result<(), OidErr> {
        self.table.commit(user)
    }
    fn rollback(&mut self) -> Result<(), OidErr> {
        self.table.rollback()
    }
}

// A set of SNMP target information.
//
// Entries in the snmpTargetParamsTable are created and
// deleted using the snmpTargetParamsRowStatus object.

struct KeepSnmpTargetParamsTable {
    table: TableMemOid,
}

impl KeepSnmpTargetParamsTable {
    fn new() -> Self {
        let base_oid: ObjectIdentifier =
            ObjectIdentifier::new(&ARC_SNMP_TARGET_PARAMS_TABLE).unwrap();

        let mut tab = KeepSnmpTargetParamsTable {
            table: TableMemOid::new(
                vec![
                    simple_from_str(b"b"),
                    simple_from_int(4),
                    simple_from_int(4),
                    simple_from_str(b"b"),
                    simple_from_int(4),
                    simple_from_int(3),
                    simple_from_int(4),
                ],
                7,
                &base_oid,
                vec![
                    OType::String,
                    OType::Integer,
                    OType::Integer,
                    OType::String,
                    OType::Integer,
                    OType::Integer,
                    OType::Integer,
                ],
                vec![
                    Access::NoAccess,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                ],
                vec![1],
                true,
            ),
        };
        // Initial row
        tab.table.set_data(vec![]);
        tab
    }
}

impl OidKeeper for KeepSnmpTargetParamsTable {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {
        false
    }
    fn is_empty(&self) -> bool {
        self.table.is_empty()
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
    fn set(
        &mut self,
        oid: ObjectIdentifier,
        value: VarBindValue,
        user: &User,
    ) -> Result<VarBindValue, OidErr> {
        self.table.set(oid, value, user)
    }
    fn begin_transaction(&mut self) -> Result<(), OidErr> {
        self.table.begin_transaction()
    }
    fn commit(&mut self, user: &User) -> Result<(), OidErr> {
        self.table.commit(user)
    }
    fn rollback(&mut self) -> Result<(), OidErr> {
        self.table.rollback()
    }
}

// The total number of packets received by the SNMP
// engine which were dropped because the context
// contained in the message was unavailable.

struct KeepSnmpUnavailableContexts {
    cnt: ObjectSyntax,
}

impl KeepSnmpUnavailableContexts {
    fn new() -> Self {
        KeepSnmpUnavailableContexts {
            cnt: counter_from_int(0),
        }
    }
}

impl OidKeeper for KeepSnmpUnavailableContexts {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {
        true
    }
    fn get(&self, _oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
        Ok(VarBindValue::Value(self.cnt.clone()))
    }
    fn get_next(&self, _oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
        Err(OidErr::OutOfRange)
    }
    fn access(&self, _oid: ObjectIdentifier) -> Access {
        Access::ReadOnly
    }
    fn set(
        &mut self,
        _oid: ObjectIdentifier,
        _value: VarBindValue,
        _user: &User,
    ) -> Result<VarBindValue, OidErr> {
        Err(OidErr::NotWritable)
    }
    fn begin_transaction(&mut self) -> Result<(), OidErr> {
        Ok(())
    }
    fn commit(&mut self, _user: &User) -> Result<(), OidErr> {
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), OidErr> {
        Ok(())
    }
}
// The total number of packets received by the SNMP
// engine which were dropped because the context
// contained in the message was unknown.

struct KeepSnmpUnknownContexts {
    unknown_contexts: u32,
}

impl KeepSnmpUnknownContexts {
    fn new(agent: &Agent) -> Self {
        KeepSnmpUnknownContexts {
            unknown_contexts: agent.unknown_contexts,
        }
    }
}

impl OidKeeper for KeepSnmpUnknownContexts {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {
        true
    }
    fn get(&self, _oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
        Ok(VarBindValue::Value(counter_from_int(self.unknown_contexts)))
    }
    fn get_next(&self, _oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
        Err(OidErr::OutOfRange)
    }
    fn access(&self, _oid: ObjectIdentifier) -> Access {
        Access::ReadOnly
    }
    fn set(
        &mut self,
        _oid: ObjectIdentifier,
        _value: VarBindValue,
        _user: &User,
    ) -> Result<VarBindValue, OidErr> {
        Err(OidErr::NotWritable)
    }
    fn begin_transaction(&mut self) -> Result<(), OidErr> {
        Ok(())
    }
    fn commit(&mut self, _user: &User) -> Result<(), OidErr> {
        Ok(())
    }
    fn rollback(&mut self) -> Result<(), OidErr> {
        Ok(())
    }
}

pub fn load_stub(oid_map: &mut OidMap, agent: &Agent, comp: &mut ComplianceStatements) {
    let oid_snmp_target_spin_lock: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_TARGET_SPIN_LOCK).unwrap();
    let k_snmp_target_spin_lock: Box<dyn OidKeeper> = Box::new(KeepSnmpTargetSpinLock::new());
    oid_map.push(oid_snmp_target_spin_lock, k_snmp_target_spin_lock);
    let oid_snmp_target_addr_table: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_TARGET_ADDR_TABLE).unwrap();
    let k_snmp_target_addr_table: Box<dyn OidKeeper> = Box::new(KeepSnmpTargetAddrTable::new());
    oid_map.push(oid_snmp_target_addr_table, k_snmp_target_addr_table);
    let oid_snmp_target_params_table: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_TARGET_PARAMS_TABLE).unwrap();
    let k_snmp_target_params_table: Box<dyn OidKeeper> = Box::new(KeepSnmpTargetParamsTable::new());
    oid_map.push(oid_snmp_target_params_table, k_snmp_target_params_table);
    let oid_snmp_unavailable_contexts: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_UNAVAILABLE_CONTEXTS).unwrap();
    let k_snmp_unavailable_contexts: Box<dyn OidKeeper> =
        Box::new(KeepSnmpUnavailableContexts::new());
    oid_map.push(oid_snmp_unavailable_contexts, k_snmp_unavailable_contexts);
    let oid_snmp_unknown_contexts: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_UNKNOWN_CONTEXTS).unwrap();
    let k_snmp_unknown_contexts: Box<dyn OidKeeper> = Box::new(KeepSnmpUnknownContexts::new(agent));
    oid_map.push(oid_snmp_unknown_contexts, k_snmp_unknown_contexts);
    // Module Compliance values, change false to true when implemented

    comp.register_compliance(
        &COMPLIANCE_SNMP_TARGET_COMMAND_RESPONDER_COMPLIANCE,
        "snmpTargetCommandResponderCompliance",
        false,
    );
}
