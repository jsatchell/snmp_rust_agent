
use crate::keeper::oid_keep::{Access, OidErr, OidKeeper, OType};
use crate::scalar::ScalarMemOid;
use crate::table::TableMemOid;use crate::oidmap::OidMap;
use rasn::types::{Integer, ObjectIdentifier, OctetString};

use rasn_smi::v2::{ObjectSyntax, SimpleSyntax, ApplicationSyntax,
                   Counter32};
use rasn_snmp::v3::{VarBind, VarBindValue};

fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

fn simple_from_str(value: &'static [u8]) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_static(value)))
}

fn simple_from_vec(value: &'static [u32]) -> ObjectSyntax {
  ObjectSyntax::Simple(SimpleSyntax::ObjectId(ObjectIdentifier::new(value).unwrap()))
}


fn counter_from_int(value:u32) -> ObjectSyntax {
  ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(Counter32{0:value}))
}

const ARC_USM_STATS_UNSUPPORTED_SEC_LEVELS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 1];
const ARC_USM_STATS_NOT_IN_TIME_WINDOWS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 2];
const ARC_USM_STATS_UNKNOWN_USER_NAMES: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 3];
const ARC_USM_STATS_UNKNOWN_ENGINE_I_DS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 4];
const ARC_USM_STATS_WRONG_DIGESTS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 5];
const ARC_USM_STATS_DECRYPTION_ERRORS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 6];
const ARC_USM_USER_SPIN_LOCK: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 2, 1];
const ARC_USM_USER_TABLE: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 2, 2];

// OID definitions for OBJECT-IDENTITY

const ARC_USM_NO_AUTH_PROTOCOL: [u32; 10] = [1, 3, 6, 1, 6, 3, 10, 1, 1, 1];
const ARC_USM_H_M_A_C_M_D5_AUTH_PROTOCOL: [u32; 10] = [1, 3, 6, 1, 6, 3, 10, 1, 1, 2];
const ARC_USM_H_M_A_C_S_H_A_AUTH_PROTOCOL: [u32; 10] = [1, 3, 6, 1, 6, 3, 10, 1, 1, 3];
const ARC_USM_NO_PRIV_PROTOCOL: [u32; 10] = [1, 3, 6, 1, 6, 3, 10, 1, 2, 1];
const ARC_USM_D_E_S_PRIV_PROTOCOL: [u32; 10] = [1, 3, 6, 1, 6, 3, 10, 1, 2, 2];

// Now the OBJECT-TYPES. These need actual code added to the stubs


// The total number of packets received by the SNMP
// engine which were dropped because they requested a
// securityLevel that was unknown to the SNMP engine
// or otherwise unavailable.
// 
struct KeepUsmstatsunsupportedseclevels {
    scalar: ScalarMemOid,
  }

impl KeepUsmstatsunsupportedseclevels {
    fn new() -> Self {
       KeepUsmstatsunsupportedseclevels {
           scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepUsmstatsunsupportedseclevels {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}

// The total number of packets received by the SNMP
// engine which were dropped because they appeared
// outside of the authoritative SNMP engine's window.
// 
struct KeepUsmstatsnotintimewindows {
    scalar: ScalarMemOid,
  }

impl KeepUsmstatsnotintimewindows {
    fn new() -> Self {
       KeepUsmstatsnotintimewindows {
           scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepUsmstatsnotintimewindows {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}

// The total number of packets received by the SNMP
// engine which were dropped because they referenced a
// user that was not known to the SNMP engine.
// 
struct KeepUsmstatsunknownusernames {
    scalar: ScalarMemOid,
  }

impl KeepUsmstatsunknownusernames {
    fn new() -> Self {
       KeepUsmstatsunknownusernames {
           scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepUsmstatsunknownusernames {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}

// The total number of packets received by the SNMP
// engine which were dropped because they referenced an
// snmpEngineID that was not known to the SNMP engine.
// 
struct KeepUsmstatsunknownengineids {
    scalar: ScalarMemOid,
  }

impl KeepUsmstatsunknownengineids {
    fn new() -> Self {
       KeepUsmstatsunknownengineids {
           scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepUsmstatsunknownengineids {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}

// The total number of packets received by the SNMP
// engine which were dropped because they didn't
// contain the expected digest value.
// 
struct KeepUsmstatswrongdigests {
    scalar: ScalarMemOid,
  }

impl KeepUsmstatswrongdigests {
    fn new() -> Self {
       KeepUsmstatswrongdigests {
           scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepUsmstatswrongdigests {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}

// The total number of packets received by the SNMP
// engine which were dropped because they could not be
// decrypted.
// 
struct KeepUsmstatsdecryptionerrors {
    scalar: ScalarMemOid,
  }

impl KeepUsmstatsdecryptionerrors {
    fn new() -> Self {
       KeepUsmstatsdecryptionerrors {
           scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
       }
    }
}

impl OidKeeper for KeepUsmstatsdecryptionerrors {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}

// An advisory lock used to allow several cooperating
// Command Generator Applications to coordinate their
// use of facilities to alter secrets in the
// usmUserTable.
// 
struct KeepUsmuserspinlock {
    scalar: ScalarMemOid,
  }

impl KeepUsmuserspinlock {
    fn new() -> Self {
       KeepUsmuserspinlock {
           scalar: ScalarMemOid::new(simple_from_int(4), OType::Integer, Access::ReadWrite),
       }
    }
}

impl OidKeeper for KeepUsmuserspinlock {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {true}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.scalar.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.scalar.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.scalar.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value) }
}

// A user configured in the SNMP engine's Local
// Configuration Datastore (LCD) for the User-based
// Security Model.
// 
struct KeepUsmusertable {
    table: TableMemOid,
  }

impl KeepUsmusertable {
    fn new() -> Self {
       let base_oid: ObjectIdentifier =
           ObjectIdentifier::new(&ARC_USM_USER_TABLE).unwrap();

       KeepUsmusertable {
           table: TableMemOid::new(
             vec![vec![simple_from_str(b"b"), simple_from_str(b"b"), simple_from_str(b"b"), simple_from_vec(&[1, 3, 6, 1]), simple_from_vec(&ARC_USM_NO_AUTH_PROTOCOL), simple_from_str(b""), simple_from_str(b""), simple_from_vec(&ARC_USM_NO_PRIV_PROTOCOL), simple_from_str(b""), simple_from_str(b""), simple_from_str(b""), simple_from_int(3), simple_from_int(4)]],
        vec![simple_from_str(b"b"), simple_from_str(b"b"), simple_from_str(b"b"), simple_from_vec(&[1, 3, 6, 1]), simple_from_vec(&ARC_USM_NO_AUTH_PROTOCOL), simple_from_str(b""), simple_from_str(b""), simple_from_vec(&ARC_USM_NO_PRIV_PROTOCOL), simple_from_str(b""), simple_from_str(b""), simple_from_str(b""), simple_from_int(3), simple_from_int(4)],
        13,
        &base_oid,
        vec![OType::String, OType::String, OType::String, OType::ObjectId, OType::ObjectId, OType::String, OType::String, OType::ObjectId, OType::String, OType::String, OType::String, OType::Integer, OType::Integer],
        vec![Access::NoAccess, Access::NoAccess, Access::ReadOnly, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate, Access::ReadCreate],
        vec![1, 2],
        false,
        )
       }
    }
}

impl OidKeeper for KeepUsmusertable {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {false}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
      self.table.get(oid) }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
      self.table.get_next(oid) }
    fn access(&self, oid: ObjectIdentifier) -> Access {
      self.table.access(oid) }
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
        self.table.set(oid, value) }
}


pub fn load_stub(oid_map: &mut OidMap) {
    
// The next group is for OBJECT-IDENTITY.

// These may be used as values rather than MIB addresses

    let _oid_usm_no_auth_protocol: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_NO_AUTH_PROTOCOL).unwrap();
    let _oid_usm_h_m_a_c_m_d5_auth_protocol: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_H_M_A_C_M_D5_AUTH_PROTOCOL).unwrap();
    let _oid_usm_h_m_a_c_s_h_a_auth_protocol: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_H_M_A_C_S_H_A_AUTH_PROTOCOL).unwrap();
    let _oid_usm_no_priv_protocol: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_NO_PRIV_PROTOCOL).unwrap();
    let _oid_usm_d_e_s_priv_protocol: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_D_E_S_PRIV_PROTOCOL).unwrap();

    let oid_usm_stats_unsupported_sec_levels: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_STATS_UNSUPPORTED_SEC_LEVELS).unwrap();
    let k_usm_stats_unsupported_sec_levels: Box<dyn OidKeeper> = 
       Box::new(KeepUsmstatsunsupportedseclevels::new());
    oid_map.push(oid_usm_stats_unsupported_sec_levels, k_usm_stats_unsupported_sec_levels);
    let oid_usm_stats_not_in_time_windows: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_STATS_NOT_IN_TIME_WINDOWS).unwrap();
    let k_usm_stats_not_in_time_windows: Box<dyn OidKeeper> = 
       Box::new(KeepUsmstatsnotintimewindows::new());
    oid_map.push(oid_usm_stats_not_in_time_windows, k_usm_stats_not_in_time_windows);
    let oid_usm_stats_unknown_user_names: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_STATS_UNKNOWN_USER_NAMES).unwrap();
    let k_usm_stats_unknown_user_names: Box<dyn OidKeeper> = 
       Box::new(KeepUsmstatsunknownusernames::new());
    oid_map.push(oid_usm_stats_unknown_user_names, k_usm_stats_unknown_user_names);
    let oid_usm_stats_unknown_engine_i_ds: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_STATS_UNKNOWN_ENGINE_I_DS).unwrap();
    let k_usm_stats_unknown_engine_i_ds: Box<dyn OidKeeper> = 
       Box::new(KeepUsmstatsunknownengineids::new());
    oid_map.push(oid_usm_stats_unknown_engine_i_ds, k_usm_stats_unknown_engine_i_ds);
    let oid_usm_stats_wrong_digests: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_STATS_WRONG_DIGESTS).unwrap();
    let k_usm_stats_wrong_digests: Box<dyn OidKeeper> = 
       Box::new(KeepUsmstatswrongdigests::new());
    oid_map.push(oid_usm_stats_wrong_digests, k_usm_stats_wrong_digests);
    let oid_usm_stats_decryption_errors: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_STATS_DECRYPTION_ERRORS).unwrap();
    let k_usm_stats_decryption_errors: Box<dyn OidKeeper> = 
       Box::new(KeepUsmstatsdecryptionerrors::new());
    oid_map.push(oid_usm_stats_decryption_errors, k_usm_stats_decryption_errors);
    let oid_usm_user_spin_lock: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_USER_SPIN_LOCK).unwrap();
    let k_usm_user_spin_lock: Box<dyn OidKeeper> = 
       Box::new(KeepUsmuserspinlock::new());
    oid_map.push(oid_usm_user_spin_lock, k_usm_user_spin_lock);
    let oid_usm_user_table: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_USER_TABLE).unwrap();
    let k_usm_user_table: Box<dyn OidKeeper> = 
       Box::new(KeepUsmusertable::new());
    oid_map.push(oid_usm_user_table, k_usm_user_table);
}