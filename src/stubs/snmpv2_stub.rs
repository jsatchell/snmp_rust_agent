use crate::keeper::{Access, OType, OidErr, OidKeeper};
use crate::oidmap::OidMap;
use crate::scalar::ScalarMemOid;
use crate::table::TableMemOid;
use rasn::types::{Integer, ObjectIdentifier, OctetString};

use rasn_smi::v2::{ApplicationSyntax, Counter32, ObjectSyntax, SimpleSyntax, TimeTicks};

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

fn counter_from_int(value: u32) -> ObjectSyntax {
    ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(Counter32 { 0: value }))
}

fn ticks_from_int(value: u32) -> ObjectSyntax {
    ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(TimeTicks { 0: value }))
}
const ARC_SNMP_IN_GET_NEXTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 16];
const ARC_SNMP_IN_TOTAL_SET_VARS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 14];
const ARC_SNMP_SET_SERIAL_NO: [u32; 10] = [1, 3, 6, 1, 6, 3, 1, 1, 6, 1];
const ARC_SNMP_OUT_GET_RESPONSES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 28];
const ARC_SNMP_OUT_GET_NEXTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 26];
const ARC_SNMP_OUT_PKTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 2];
const ARC_SNMP_TRAP_OID: [u32; 10] = [1, 3, 6, 1, 6, 3, 1, 1, 4, 1];
const ARC_SYS_SERVICES: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 7];
const ARC_SNMP_IN_BAD_VALUES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 10];
const ARC_SYS_UP_TIME: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 3];
const ARC_SNMP_IN_NO_SUCH_NAMES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 9];
const ARC_SNMP_IN_GET_RESPONSES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 18];
const ARC_SNMP_IN_TRAPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 19];
const ARC_SYS_OBJECT_ID: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 2];
const ARC_SYS_OR_TABLE: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 9];
const ARC_SYS_CONTACT: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 4];
const ARC_SNMP_IN_GEN_ERRS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 12];
const ARC_SNMP_IN_BAD_COMMUNITY_USES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 5];
const ARC_SNMP_TRAP_ENTERPRISE: [u32; 10] = [1, 3, 6, 1, 6, 3, 1, 1, 4, 3];
const ARC_SNMP_IN_BAD_COMMUNITY_NAMES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 4];
const ARC_SYS_DESCR: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 1];
const ARC_SNMP_SILENT_DROPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 31];
const ARC_SYS_OR_LAST_CHANGE: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 8];
const ARC_SNMP_IN_ASN_PARSE_ERRS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 6];
const ARC_SNMP_IN_TOO_BIGS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 8];
const ARC_SNMP_IN_PKTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 1];
const ARC_SNMP_IN_GET_REQUESTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 15];
const ARC_SNMP_OUT_NO_SUCH_NAMES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 21];
const ARC_SNMP_OUT_BAD_VALUES: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 22];
const ARC_SNMP_ENABLE_AUTHEN_TRAPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 30];
const ARC_SYS_LOCATION: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 6];
const ARC_SNMP_OUT_TOO_BIGS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 20];
const ARC_SNMP_OUT_GEN_ERRS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 24];
const ARC_SNMP_IN_BAD_VERSIONS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 3];
const ARC_SNMP_IN_READ_ONLYS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 11];
const ARC_SNMP_IN_TOTAL_REQ_VARS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 13];
const ARC_SNMP_OUT_GET_REQUESTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 25];
const ARC_SNMP_OUT_SET_REQUESTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 27];
const ARC_SNMP_IN_SET_REQUESTS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 17];
const ARC_SYS_NAME: [u32; 8] = [1, 3, 6, 1, 2, 1, 1, 5];
const ARC_SNMP_PROXY_DROPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 32];
const ARC_SNMP_OUT_TRAPS: [u32; 8] = [1, 3, 6, 1, 2, 1, 11, 29];

// Now the OBJECT-TYPES. These need actual code added to the stubs

// The total number of SNMP Get-Next PDUs which have been
// accepted and processed by the SNMP protocol entity.

struct KeepSnmpInGetNexts {
    scalar: ScalarMemOid,
}

impl KeepSnmpInGetNexts {
    fn new() -> Self {
        KeepSnmpInGetNexts {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInGetNexts {
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
// The total number of MIB objects which have been
// altered successfully by the SNMP protocol entity as
// the result of receiving valid SNMP Set-Request PDUs.

struct KeepSnmpInTotalSetVars {
    scalar: ScalarMemOid,
}

impl KeepSnmpInTotalSetVars {
    fn new() -> Self {
        KeepSnmpInTotalSetVars {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInTotalSetVars {
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
// An advisory lock used to allow several cooperating
// command generator applications to coordinate their
// use of the SNMP set operation.
//
// This object is used for coarse-grain coordination.
// To achieve fine-grain coordination, one or more similar
// objects might be defined within each MIB group, as
// appropriate.

struct KeepSnmpSetSerialNo {
    scalar: ScalarMemOid,
}

impl KeepSnmpSetSerialNo {
    fn new() -> Self {
        KeepSnmpSetSerialNo {
            scalar: ScalarMemOid::new(simple_from_int(4), OType::Integer, Access::ReadWrite),
        }
    }
}

impl OidKeeper for KeepSnmpSetSerialNo {
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
// The total number of SNMP Get-Response PDUs which
// have been generated by the SNMP protocol entity.

struct KeepSnmpOutGetResponses {
    scalar: ScalarMemOid,
}

impl KeepSnmpOutGetResponses {
    fn new() -> Self {
        KeepSnmpOutGetResponses {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpOutGetResponses {
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
// The total number of SNMP Get-Next PDUs which have
// been generated by the SNMP protocol entity.

struct KeepSnmpOutGetNexts {
    scalar: ScalarMemOid,
}

impl KeepSnmpOutGetNexts {
    fn new() -> Self {
        KeepSnmpOutGetNexts {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpOutGetNexts {
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
// The total number of SNMP Messages which were
// passed from the SNMP protocol entity to the
// transport service.

struct KeepSnmpOutPkts {
    scalar: ScalarMemOid,
}

impl KeepSnmpOutPkts {
    fn new() -> Self {
        KeepSnmpOutPkts {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpOutPkts {
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
// The authoritative identification of the notification
// currently being sent.  This variable occurs as
// the second varbind in every SNMPv2-Trap-PDU and
// InformRequest-PDU.

struct KeepSnmpTrapOID {
    scalar: ScalarMemOid,
}

impl KeepSnmpTrapOID {
    fn new() -> Self {
        KeepSnmpTrapOID {
            scalar: ScalarMemOid::new(
                simple_from_vec(&[1, 3, 6, 1]),
                OType::ObjectId,
                Access::NotificationOnly,
            ),
        }
    }
}

impl OidKeeper for KeepSnmpTrapOID {
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
// A value which indicates the set of services that this
// entity may potentially offer.  The value is a sum.
//
// This sum initially takes the value zero. Then, for
// each layer, L, in the range 1 through 7, that this node
// performs transactions for, 2 raised to (L - 1) is added
// to the sum.  For example, a node which performs only
// routing functions would have a value of 4 (2^(3-1)).
// In contrast, a node which is a host offering application
// services would have a value of 72 (2^(4-1) + 2^(7-1)).
// Note that in the context of the Internet suite of
// protocols, values should be calculated accordingly:
//
// layer      functionality
// 1        physical (e.g., repeaters)
// 2        datalink/subnetwork (e.g., bridges)
// 3        internet (e.g., supports the IP)
// 4        end-to-end  (e.g., supports the TCP)
// 7        applications (e.g., supports the SMTP)
//
// For systems including OSI protocols, layers 5 and 6
// may also be counted.

struct KeepSysServices {
    scalar: ScalarMemOid,
}

impl KeepSysServices {
    fn new() -> Self {
        KeepSysServices {
            scalar: ScalarMemOid::new(simple_from_int(4), OType::Integer, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSysServices {
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
// The total number of SNMP PDUs which were
// delivered to the SNMP protocol entity and for
// which the value of the error-status field was
// `badValue'.

struct KeepSnmpInBadValues {
    scalar: ScalarMemOid,
}

impl KeepSnmpInBadValues {
    fn new() -> Self {
        KeepSnmpInBadValues {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInBadValues {
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
// The time (in hundredths of a second) since the
// network management portion of the system was last
// re-initialized.

struct KeepSysUpTime {
    scalar: ScalarMemOid,
}

impl KeepSysUpTime {
    fn new() -> Self {
        KeepSysUpTime {
            scalar: ScalarMemOid::new(ticks_from_int(0), OType::Ticks, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSysUpTime {
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
// The total number of SNMP PDUs which were
// delivered to the SNMP protocol entity and for
// which the value of the error-status field was
// `noSuchName'.

struct KeepSnmpInNoSuchNames {
    scalar: ScalarMemOid,
}

impl KeepSnmpInNoSuchNames {
    fn new() -> Self {
        KeepSnmpInNoSuchNames {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInNoSuchNames {
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
// The total number of SNMP Get-Response PDUs which
// have been accepted and processed by the SNMP protocol
// entity.

struct KeepSnmpInGetResponses {
    scalar: ScalarMemOid,
}

impl KeepSnmpInGetResponses {
    fn new() -> Self {
        KeepSnmpInGetResponses {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInGetResponses {
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
// The total number of SNMP Trap PDUs which have been
// accepted and processed by the SNMP protocol entity.

struct KeepSnmpInTraps {
    scalar: ScalarMemOid,
}

impl KeepSnmpInTraps {
    fn new() -> Self {
        KeepSnmpInTraps {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInTraps {
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
// The vendor's authoritative identification of the
// network management subsystem contained in the entity.
// This value is allocated within the SMI enterprises
// subtree (1.3.6.1.4.1) and provides an easy and
// unambiguous means for determining `what kind of box' is
// being managed.  For example, if vendor `Flintstones,
// Inc.' was assigned the subtree 1.3.6.1.4.1.424242,
// it could assign the identifier 1.3.6.1.4.1.424242.1.1
// to its `Fred Router'.

struct KeepSysObjectID {
    scalar: ScalarMemOid,
}

impl KeepSysObjectID {
    fn new() -> Self {
        KeepSysObjectID {
            scalar: ScalarMemOid::new(
                simple_from_vec(&[1, 3, 6, 1]),
                OType::ObjectId,
                Access::ReadOnly,
            ),
        }
    }
}

impl OidKeeper for KeepSysObjectID {
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
// An entry (conceptual row) in the sysORTable.

struct KeepSysORTable {
    table: TableMemOid,
}

impl KeepSysORTable {
    fn new() -> Self {
        let base_oid: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_OR_TABLE).unwrap();

        KeepSysORTable {
            table: TableMemOid::new(
                vec![vec![
                    simple_from_int(4),
                    simple_from_vec(&[1, 3, 6, 1]),
                    simple_from_str(b"b"),
                    ticks_from_int(0),
                ]],
                vec![
                    simple_from_int(4),
                    simple_from_vec(&[1, 3, 6, 1]),
                    simple_from_str(b"b"),
                    ticks_from_int(0),
                ],
                4,
                &base_oid,
                vec![OType::Integer, OType::ObjectId, OType::String, OType::Ticks],
                vec![
                    Access::NoAccess,
                    Access::ReadOnly,
                    Access::ReadOnly,
                    Access::ReadOnly,
                ],
                vec![1],
                false,
            ),
        }
    }
}

impl OidKeeper for KeepSysORTable {
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
// The textual identification of the contact person for
// this managed node, together with information on how
// to contact this person.  If no contact information is
// known, the value is the zero-length string.

struct KeepSysContact {
    scalar: ScalarMemOid,
}

impl KeepSysContact {
    fn new() -> Self {
        KeepSysContact {
            scalar: ScalarMemOid::new(simple_from_str(b"b"), OType::String, Access::ReadWrite),
        }
    }
}

impl OidKeeper for KeepSysContact {
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
// The total number of SNMP PDUs which were delivered
// to the SNMP protocol entity and for which the value
// of the error-status field was `genErr'.

struct KeepSnmpInGenErrs {
    scalar: ScalarMemOid,
}

impl KeepSnmpInGenErrs {
    fn new() -> Self {
        KeepSnmpInGenErrs {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInGenErrs {
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
// The total number of community-based SNMP messages (for
// example, SNMPv1) delivered to the SNMP entity which
// represented an SNMP operation that was not allowed for
// the SNMP community named in the message.  The precise
// conditions under which this counter is incremented
// (if at all) depend on how the SNMP entity implements
// its access control mechanism and how its applications
// interact with that access control mechanism.  It is
// strongly RECOMMENDED that the documentation for any
// access control mechanism which is used to control access
// to and visibility of MIB instrumentation specify the
// precise conditions that contribute to this value.

struct KeepSnmpInBadCommunityUses {
    scalar: ScalarMemOid,
}

impl KeepSnmpInBadCommunityUses {
    fn new() -> Self {
        KeepSnmpInBadCommunityUses {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInBadCommunityUses {
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
// The authoritative identification of the enterprise
// associated with the trap currently being sent.  When an
// SNMP proxy agent is mapping an RFC1157 Trap-PDU
// into a SNMPv2-Trap-PDU, this variable occurs as the
// last varbind.

struct KeepSnmpTrapEnterprise {
    scalar: ScalarMemOid,
}

impl KeepSnmpTrapEnterprise {
    fn new() -> Self {
        KeepSnmpTrapEnterprise {
            scalar: ScalarMemOid::new(
                simple_from_vec(&[1, 3, 6, 1]),
                OType::ObjectId,
                Access::NotificationOnly,
            ),
        }
    }
}

impl OidKeeper for KeepSnmpTrapEnterprise {
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
// The total number of community-based SNMP messages (for
// example,  SNMPv1) delivered to the SNMP entity which
// used an SNMP community name not known to said entity.
// Also, implementations which authenticate community-based
// SNMP messages using check(s) in addition to matching
// the community name (for example, by also checking
// whether the message originated from a transport address
// allowed to use a specified community name) MAY include
// in this value the number of messages which failed the
// additional check(s).  It is strongly RECOMMENDED that
//
// the documentation for any security model which is used
// to authenticate community-based SNMP messages specify
// the precise conditions that contribute to this value.

struct KeepSnmpInBadCommunityNames {
    scalar: ScalarMemOid,
}

impl KeepSnmpInBadCommunityNames {
    fn new() -> Self {
        KeepSnmpInBadCommunityNames {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInBadCommunityNames {
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
// A textual description of the entity.  This value should
// include the full name and version identification of
// the system's hardware type, software operating-system,
// and networking software.

struct KeepSysDescr {
    scalar: ScalarMemOid,
}

impl KeepSysDescr {
    fn new() -> Self {
        KeepSysDescr {
            scalar: ScalarMemOid::new(simple_from_str(b"b"), OType::String, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSysDescr {
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
// The total number of Confirmed Class PDUs (such as
// GetRequest-PDUs, GetNextRequest-PDUs,
// GetBulkRequest-PDUs, SetRequest-PDUs, and
// InformRequest-PDUs) delivered to the SNMP entity which
// were silently dropped because the size of a reply
// containing an alternate Response Class PDU (such as a
// Response-PDU) with an empty variable-bindings field
// was greater than either a local constraint or the
// maximum message size associated with the originator of
// the request.

struct KeepSnmpSilentDrops {
    scalar: ScalarMemOid,
}

impl KeepSnmpSilentDrops {
    fn new() -> Self {
        KeepSnmpSilentDrops {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpSilentDrops {
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
// The value of sysUpTime at the time of the most recent
// change in state or value of any instance of sysORID.

struct KeepSysORLastChange {
    scalar: ScalarMemOid,
}

impl KeepSysORLastChange {
    fn new() -> Self {
        KeepSysORLastChange {
            scalar: ScalarMemOid::new(ticks_from_int(0), OType::Ticks, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSysORLastChange {
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
// The total number of ASN.1 or BER errors encountered by
// the SNMP entity when decoding received SNMP messages.

struct KeepSnmpInASNParseErrs {
    scalar: ScalarMemOid,
}

impl KeepSnmpInASNParseErrs {
    fn new() -> Self {
        KeepSnmpInASNParseErrs {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInASNParseErrs {
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
// The total number of SNMP PDUs which were
// delivered to the SNMP protocol entity and for
// which the value of the error-status field was
// `tooBig'.

struct KeepSnmpInTooBigs {
    scalar: ScalarMemOid,
}

impl KeepSnmpInTooBigs {
    fn new() -> Self {
        KeepSnmpInTooBigs {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInTooBigs {
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
// The total number of messages delivered to the SNMP
// entity from the transport service.

struct KeepSnmpInPkts {
    scalar: ScalarMemOid,
}

impl KeepSnmpInPkts {
    fn new() -> Self {
        KeepSnmpInPkts {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInPkts {
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
// The total number of SNMP Get-Request PDUs which
// have been accepted and processed by the SNMP
// protocol entity.

struct KeepSnmpInGetRequests {
    scalar: ScalarMemOid,
}

impl KeepSnmpInGetRequests {
    fn new() -> Self {
        KeepSnmpInGetRequests {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInGetRequests {
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
// The total number of SNMP PDUs which were generated
// by the SNMP protocol entity and for which the value
// of the error-status was `noSuchName'.

struct KeepSnmpOutNoSuchNames {
    scalar: ScalarMemOid,
}

impl KeepSnmpOutNoSuchNames {
    fn new() -> Self {
        KeepSnmpOutNoSuchNames {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpOutNoSuchNames {
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
// The total number of SNMP PDUs which were generated
// by the SNMP protocol entity and for which the value
// of the error-status field was `badValue'.

struct KeepSnmpOutBadValues {
    scalar: ScalarMemOid,
}

impl KeepSnmpOutBadValues {
    fn new() -> Self {
        KeepSnmpOutBadValues {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpOutBadValues {
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
// Indicates whether the SNMP entity is permitted to
// generate authenticationFailure traps.  The value of this
// object overrides any configuration information; as such,
// it provides a means whereby all authenticationFailure
// traps may be disabled.
//
// Note that it is strongly recommended that this object
// be stored in non-volatile memory so that it remains
// constant across re-initializations of the network
// management system.

struct KeepSnmpEnableAuthenTraps {
    scalar: ScalarMemOid,
}

impl KeepSnmpEnableAuthenTraps {
    fn new() -> Self {
        KeepSnmpEnableAuthenTraps {
            scalar: ScalarMemOid::new(simple_from_int(4), OType::Integer, Access::ReadWrite),
        }
    }
}

impl OidKeeper for KeepSnmpEnableAuthenTraps {
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
// The physical location of this node (e.g., 'telephone
// closet, 3rd floor').  If the location is unknown, the
// value is the zero-length string.

struct KeepSysLocation {
    scalar: ScalarMemOid,
}

impl KeepSysLocation {
    fn new() -> Self {
        KeepSysLocation {
            scalar: ScalarMemOid::new(simple_from_str(b"b"), OType::String, Access::ReadWrite),
        }
    }
}

impl OidKeeper for KeepSysLocation {
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
// The total number of SNMP PDUs which were generated
// by the SNMP protocol entity and for which the value
// of the error-status field was `tooBig.'

struct KeepSnmpOutTooBigs {
    scalar: ScalarMemOid,
}

impl KeepSnmpOutTooBigs {
    fn new() -> Self {
        KeepSnmpOutTooBigs {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpOutTooBigs {
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
// The total number of SNMP PDUs which were generated
// by the SNMP protocol entity and for which the value
// of the error-status field was `genErr'.

struct KeepSnmpOutGenErrs {
    scalar: ScalarMemOid,
}

impl KeepSnmpOutGenErrs {
    fn new() -> Self {
        KeepSnmpOutGenErrs {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpOutGenErrs {
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
// The total number of SNMP messages which were delivered
// to the SNMP entity and were for an unsupported SNMP
// version.

struct KeepSnmpInBadVersions {
    scalar: ScalarMemOid,
}

impl KeepSnmpInBadVersions {
    fn new() -> Self {
        KeepSnmpInBadVersions {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInBadVersions {
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
// The total number valid SNMP PDUs which were delivered
// to the SNMP protocol entity and for which the value
// of the error-status field was `readOnly'.  It should
// be noted that it is a protocol error to generate an
// SNMP PDU which contains the value `readOnly' in the
// error-status field, as such this object is provided
// as a means of detecting incorrect implementations of
// the SNMP.

struct KeepSnmpInReadOnlys {
    scalar: ScalarMemOid,
}

impl KeepSnmpInReadOnlys {
    fn new() -> Self {
        KeepSnmpInReadOnlys {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInReadOnlys {
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
// The total number of MIB objects which have been
// retrieved successfully by the SNMP protocol entity
// as the result of receiving valid SNMP Get-Request
// and Get-Next PDUs.

struct KeepSnmpInTotalReqVars {
    scalar: ScalarMemOid,
}

impl KeepSnmpInTotalReqVars {
    fn new() -> Self {
        KeepSnmpInTotalReqVars {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInTotalReqVars {
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
// The total number of SNMP Get-Request PDUs which
// have been generated by the SNMP protocol entity.

struct KeepSnmpOutGetRequests {
    scalar: ScalarMemOid,
}

impl KeepSnmpOutGetRequests {
    fn new() -> Self {
        KeepSnmpOutGetRequests {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpOutGetRequests {
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
// The total number of SNMP Set-Request PDUs which
// have been generated by the SNMP protocol entity.

struct KeepSnmpOutSetRequests {
    scalar: ScalarMemOid,
}

impl KeepSnmpOutSetRequests {
    fn new() -> Self {
        KeepSnmpOutSetRequests {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpOutSetRequests {
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
// The total number of SNMP Set-Request PDUs which
// have been accepted and processed by the SNMP protocol
// entity.

struct KeepSnmpInSetRequests {
    scalar: ScalarMemOid,
}

impl KeepSnmpInSetRequests {
    fn new() -> Self {
        KeepSnmpInSetRequests {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpInSetRequests {
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
// An administratively-assigned name for this managed
// node.  By convention, this is the node's fully-qualified
// domain name.  If the name is unknown, the value is
// the zero-length string.

struct KeepSysName {
    scalar: ScalarMemOid,
}

impl KeepSysName {
    fn new() -> Self {
        KeepSysName {
            scalar: ScalarMemOid::new(simple_from_str(b"b"), OType::String, Access::ReadWrite),
        }
    }
}

impl OidKeeper for KeepSysName {
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
// The total number of Confirmed Class PDUs
// (such as GetRequest-PDUs, GetNextRequest-PDUs,
// GetBulkRequest-PDUs, SetRequest-PDUs, and
// InformRequest-PDUs) delivered to the SNMP entity which
// were silently dropped because the transmission of
// the (possibly translated) message to a proxy target
// failed in a manner (other than a time-out) such that
// no Response Class PDU (such as a Response-PDU) could
// be returned.

struct KeepSnmpProxyDrops {
    scalar: ScalarMemOid,
}

impl KeepSnmpProxyDrops {
    fn new() -> Self {
        KeepSnmpProxyDrops {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpProxyDrops {
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
// The total number of SNMP Trap PDUs which have
// been generated by the SNMP protocol entity.

struct KeepSnmpOutTraps {
    scalar: ScalarMemOid,
}

impl KeepSnmpOutTraps {
    fn new() -> Self {
        KeepSnmpOutTraps {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepSnmpOutTraps {
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

pub fn load_stub(oid_map: &mut OidMap) {
    let oid_snmp_in_get_nexts: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_GET_NEXTS).unwrap();
    let k_snmp_in_get_nexts: Box<dyn OidKeeper> = Box::new(KeepSnmpInGetNexts::new());
    oid_map.push(oid_snmp_in_get_nexts, k_snmp_in_get_nexts);
    let oid_snmp_in_total_set_vars: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_TOTAL_SET_VARS).unwrap();
    let k_snmp_in_total_set_vars: Box<dyn OidKeeper> = Box::new(KeepSnmpInTotalSetVars::new());
    oid_map.push(oid_snmp_in_total_set_vars, k_snmp_in_total_set_vars);
    let oid_snmp_set_serial_no: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_SET_SERIAL_NO).unwrap();
    let k_snmp_set_serial_no: Box<dyn OidKeeper> = Box::new(KeepSnmpSetSerialNo::new());
    oid_map.push(oid_snmp_set_serial_no, k_snmp_set_serial_no);
    let oid_snmp_out_get_responses: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_GET_RESPONSES).unwrap();
    let k_snmp_out_get_responses: Box<dyn OidKeeper> = Box::new(KeepSnmpOutGetResponses::new());
    oid_map.push(oid_snmp_out_get_responses, k_snmp_out_get_responses);
    let oid_snmp_out_get_nexts: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_GET_NEXTS).unwrap();
    let k_snmp_out_get_nexts: Box<dyn OidKeeper> = Box::new(KeepSnmpOutGetNexts::new());
    oid_map.push(oid_snmp_out_get_nexts, k_snmp_out_get_nexts);
    let oid_snmp_out_pkts: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_OUT_PKTS).unwrap();
    let k_snmp_out_pkts: Box<dyn OidKeeper> = Box::new(KeepSnmpOutPkts::new());
    oid_map.push(oid_snmp_out_pkts, k_snmp_out_pkts);
    let oid_snmp_trap_oid: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_TRAP_OID).unwrap();
    let k_snmp_trap_oid: Box<dyn OidKeeper> = Box::new(KeepSnmpTrapOID::new());
    oid_map.push(oid_snmp_trap_oid, k_snmp_trap_oid);
    let oid_sys_services: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_SERVICES).unwrap();
    let k_sys_services: Box<dyn OidKeeper> = Box::new(KeepSysServices::new());
    oid_map.push(oid_sys_services, k_sys_services);
    let oid_snmp_in_bad_values: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_BAD_VALUES).unwrap();
    let k_snmp_in_bad_values: Box<dyn OidKeeper> = Box::new(KeepSnmpInBadValues::new());
    oid_map.push(oid_snmp_in_bad_values, k_snmp_in_bad_values);
    let oid_sys_up_time: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_UP_TIME).unwrap();
    let k_sys_up_time: Box<dyn OidKeeper> = Box::new(KeepSysUpTime::new());
    oid_map.push(oid_sys_up_time, k_sys_up_time);
    let oid_snmp_in_no_such_names: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_NO_SUCH_NAMES).unwrap();
    let k_snmp_in_no_such_names: Box<dyn OidKeeper> = Box::new(KeepSnmpInNoSuchNames::new());
    oid_map.push(oid_snmp_in_no_such_names, k_snmp_in_no_such_names);
    let oid_snmp_in_get_responses: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_GET_RESPONSES).unwrap();
    let k_snmp_in_get_responses: Box<dyn OidKeeper> = Box::new(KeepSnmpInGetResponses::new());
    oid_map.push(oid_snmp_in_get_responses, k_snmp_in_get_responses);
    let oid_snmp_in_traps: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_TRAPS).unwrap();
    let k_snmp_in_traps: Box<dyn OidKeeper> = Box::new(KeepSnmpInTraps::new());
    oid_map.push(oid_snmp_in_traps, k_snmp_in_traps);
    let oid_sys_object_id: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_OBJECT_ID).unwrap();
    let k_sys_object_id: Box<dyn OidKeeper> = Box::new(KeepSysObjectID::new());
    oid_map.push(oid_sys_object_id, k_sys_object_id);
    let oid_sys_or_table: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_OR_TABLE).unwrap();
    let k_sys_or_table: Box<dyn OidKeeper> = Box::new(KeepSysORTable::new());
    oid_map.push(oid_sys_or_table, k_sys_or_table);
    let oid_sys_contact: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_CONTACT).unwrap();
    let k_sys_contact: Box<dyn OidKeeper> = Box::new(KeepSysContact::new());
    oid_map.push(oid_sys_contact, k_sys_contact);
    let oid_snmp_in_gen_errs: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_GEN_ERRS).unwrap();
    let k_snmp_in_gen_errs: Box<dyn OidKeeper> = Box::new(KeepSnmpInGenErrs::new());
    oid_map.push(oid_snmp_in_gen_errs, k_snmp_in_gen_errs);
    let oid_snmp_in_bad_community_uses: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_BAD_COMMUNITY_USES).unwrap();
    let k_snmp_in_bad_community_uses: Box<dyn OidKeeper> =
        Box::new(KeepSnmpInBadCommunityUses::new());
    oid_map.push(oid_snmp_in_bad_community_uses, k_snmp_in_bad_community_uses);
    let oid_snmp_trap_enterprise: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_TRAP_ENTERPRISE).unwrap();
    let k_snmp_trap_enterprise: Box<dyn OidKeeper> = Box::new(KeepSnmpTrapEnterprise::new());
    oid_map.push(oid_snmp_trap_enterprise, k_snmp_trap_enterprise);
    let oid_snmp_in_bad_community_names: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_BAD_COMMUNITY_NAMES).unwrap();
    let k_snmp_in_bad_community_names: Box<dyn OidKeeper> =
        Box::new(KeepSnmpInBadCommunityNames::new());
    oid_map.push(
        oid_snmp_in_bad_community_names,
        k_snmp_in_bad_community_names,
    );
    let oid_sys_descr: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_DESCR).unwrap();
    let k_sys_descr: Box<dyn OidKeeper> = Box::new(KeepSysDescr::new());
    oid_map.push(oid_sys_descr, k_sys_descr);
    let oid_snmp_silent_drops: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_SILENT_DROPS).unwrap();
    let k_snmp_silent_drops: Box<dyn OidKeeper> = Box::new(KeepSnmpSilentDrops::new());
    oid_map.push(oid_snmp_silent_drops, k_snmp_silent_drops);
    let oid_sys_or_last_change: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SYS_OR_LAST_CHANGE).unwrap();
    let k_sys_or_last_change: Box<dyn OidKeeper> = Box::new(KeepSysORLastChange::new());
    oid_map.push(oid_sys_or_last_change, k_sys_or_last_change);
    let oid_snmp_in_asn_parse_errs: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_ASN_PARSE_ERRS).unwrap();
    let k_snmp_in_asn_parse_errs: Box<dyn OidKeeper> = Box::new(KeepSnmpInASNParseErrs::new());
    oid_map.push(oid_snmp_in_asn_parse_errs, k_snmp_in_asn_parse_errs);
    let oid_snmp_in_too_bigs: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_TOO_BIGS).unwrap();
    let k_snmp_in_too_bigs: Box<dyn OidKeeper> = Box::new(KeepSnmpInTooBigs::new());
    oid_map.push(oid_snmp_in_too_bigs, k_snmp_in_too_bigs);
    let oid_snmp_in_pkts: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_IN_PKTS).unwrap();
    let k_snmp_in_pkts: Box<dyn OidKeeper> = Box::new(KeepSnmpInPkts::new());
    oid_map.push(oid_snmp_in_pkts, k_snmp_in_pkts);
    let oid_snmp_in_get_requests: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_GET_REQUESTS).unwrap();
    let k_snmp_in_get_requests: Box<dyn OidKeeper> = Box::new(KeepSnmpInGetRequests::new());
    oid_map.push(oid_snmp_in_get_requests, k_snmp_in_get_requests);
    let oid_snmp_out_no_such_names: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_NO_SUCH_NAMES).unwrap();
    let k_snmp_out_no_such_names: Box<dyn OidKeeper> = Box::new(KeepSnmpOutNoSuchNames::new());
    oid_map.push(oid_snmp_out_no_such_names, k_snmp_out_no_such_names);
    let oid_snmp_out_bad_values: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_BAD_VALUES).unwrap();
    let k_snmp_out_bad_values: Box<dyn OidKeeper> = Box::new(KeepSnmpOutBadValues::new());
    oid_map.push(oid_snmp_out_bad_values, k_snmp_out_bad_values);
    let oid_snmp_enable_authen_traps: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_ENABLE_AUTHEN_TRAPS).unwrap();
    let k_snmp_enable_authen_traps: Box<dyn OidKeeper> = Box::new(KeepSnmpEnableAuthenTraps::new());
    oid_map.push(oid_snmp_enable_authen_traps, k_snmp_enable_authen_traps);
    let oid_sys_location: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_LOCATION).unwrap();
    let k_sys_location: Box<dyn OidKeeper> = Box::new(KeepSysLocation::new());
    oid_map.push(oid_sys_location, k_sys_location);
    let oid_snmp_out_too_bigs: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_TOO_BIGS).unwrap();
    let k_snmp_out_too_bigs: Box<dyn OidKeeper> = Box::new(KeepSnmpOutTooBigs::new());
    oid_map.push(oid_snmp_out_too_bigs, k_snmp_out_too_bigs);
    let oid_snmp_out_gen_errs: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_GEN_ERRS).unwrap();
    let k_snmp_out_gen_errs: Box<dyn OidKeeper> = Box::new(KeepSnmpOutGenErrs::new());
    oid_map.push(oid_snmp_out_gen_errs, k_snmp_out_gen_errs);
    let oid_snmp_in_bad_versions: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_BAD_VERSIONS).unwrap();
    let k_snmp_in_bad_versions: Box<dyn OidKeeper> = Box::new(KeepSnmpInBadVersions::new());
    oid_map.push(oid_snmp_in_bad_versions, k_snmp_in_bad_versions);
    let oid_snmp_in_read_onlys: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_READ_ONLYS).unwrap();
    let k_snmp_in_read_onlys: Box<dyn OidKeeper> = Box::new(KeepSnmpInReadOnlys::new());
    oid_map.push(oid_snmp_in_read_onlys, k_snmp_in_read_onlys);
    let oid_snmp_in_total_req_vars: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_TOTAL_REQ_VARS).unwrap();
    let k_snmp_in_total_req_vars: Box<dyn OidKeeper> = Box::new(KeepSnmpInTotalReqVars::new());
    oid_map.push(oid_snmp_in_total_req_vars, k_snmp_in_total_req_vars);
    let oid_snmp_out_get_requests: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_GET_REQUESTS).unwrap();
    let k_snmp_out_get_requests: Box<dyn OidKeeper> = Box::new(KeepSnmpOutGetRequests::new());
    oid_map.push(oid_snmp_out_get_requests, k_snmp_out_get_requests);
    let oid_snmp_out_set_requests: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_OUT_SET_REQUESTS).unwrap();
    let k_snmp_out_set_requests: Box<dyn OidKeeper> = Box::new(KeepSnmpOutSetRequests::new());
    oid_map.push(oid_snmp_out_set_requests, k_snmp_out_set_requests);
    let oid_snmp_in_set_requests: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_IN_SET_REQUESTS).unwrap();
    let k_snmp_in_set_requests: Box<dyn OidKeeper> = Box::new(KeepSnmpInSetRequests::new());
    oid_map.push(oid_snmp_in_set_requests, k_snmp_in_set_requests);
    let oid_sys_name: ObjectIdentifier = ObjectIdentifier::new(&ARC_SYS_NAME).unwrap();
    let k_sys_name: Box<dyn OidKeeper> = Box::new(KeepSysName::new());
    oid_map.push(oid_sys_name, k_sys_name);
    let oid_snmp_proxy_drops: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_PROXY_DROPS).unwrap();
    let k_snmp_proxy_drops: Box<dyn OidKeeper> = Box::new(KeepSnmpProxyDrops::new());
    oid_map.push(oid_snmp_proxy_drops, k_snmp_proxy_drops);
    let oid_snmp_out_traps: ObjectIdentifier = ObjectIdentifier::new(&ARC_SNMP_OUT_TRAPS).unwrap();
    let k_snmp_out_traps: Box<dyn OidKeeper> = Box::new(KeepSnmpOutTraps::new());
    oid_map.push(oid_snmp_out_traps, k_snmp_out_traps);
}
