use crate::config::Config;
use crate::keeper::{Access, OType, OidErr, OidKeeper};
use crate::oidmap::OidMap;
use crate::scalar::{PersistentScalar, ScalarMemOid};
use crate::snmp_agent::Agent;
use crate::table::TableMemOid;
use crate::usm::Users;
use rasn::types::{Integer, ObjectIdentifier, OctetString};

use rasn_smi::v2::{ApplicationSyntax, Counter32, ObjectSyntax, SimpleSyntax};

use rasn_snmp::v3::{VarBind, VarBindValue};

fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

fn simple_from_str(value: &[u8]) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::String(OctetString::copy_from_slice(value)))
}

fn simple_from_vec(value: &'static [u32]) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::ObjectId(
        ObjectIdentifier::new(value).unwrap(),
    ))
}

fn counter_from_int(value: u32) -> ObjectSyntax {
    ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(Counter32 { 0: value }))
}
const ARC_USM_STATS_UNKNOWN_USER_NAMES: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 3];
const ARC_USM_USER_SPIN_LOCK: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 2, 1];
const ARC_USM_STATS_WRONG_DIGESTS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 5];
const ARC_USM_STATS_DECRYPTION_ERRORS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 6];
const ARC_USM_STATS_UNKNOWN_ENGINE_I_DS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 4];
const ARC_USM_STATS_NOT_IN_TIME_WINDOWS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 2];
const ARC_USM_STATS_UNSUPPORTED_SEC_LEVELS: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 1];
const ARC_USM_USER_TABLE: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 2, 2];

// OID definitions for OBJECT-IDENTITY

const ARC_USM_NO_AUTH_PROTOCOL: [u32; 10] = [1, 3, 6, 1, 6, 3, 10, 1, 1, 1];
const ARC_USM_HMACMD5AUTH_PROTOCOL: [u32; 10] = [1, 3, 6, 1, 6, 3, 10, 1, 1, 2];
const ARC_USM_HMACSHA_AUTH_PROTOCOL: [u32; 10] = [1, 3, 6, 1, 6, 3, 10, 1, 1, 3];
const ARC_USM_NO_PRIV_PROTOCOL: [u32; 10] = [1, 3, 6, 1, 6, 3, 10, 1, 2, 1];
const ARC_USM_DES_PRIV_PROTOCOL: [u32; 10] = [1, 3, 6, 1, 6, 3, 10, 1, 2, 2];
const ARC_SNMP_AUTH_PROTOCOLS: [u32; 9] = [1, 3, 6, 1, 6, 3, 10, 1, 1];
const ARC_SNMP_PRIV_PROTOCOLS: [u32; 9] = [1, 3, 6, 1, 6, 3, 10, 1, 2];

// From RFC 3826
const ARC_USM_AES_CFB_128_PRIV_PROTOCOL: [u32; 10] = [1, 3, 6, 1, 6, 3, 10, 1, 2, 4];

// Now the OBJECT-TYPES. These need actual code added to the stubs

// The total number of packets received by the SNMP
// engine which were dropped because they referenced a
// user that was not known to the SNMP engine.
//

struct KeepUsmStatsUnknownUserNames {
    scalar: ScalarMemOid,
}

impl KeepUsmStatsUnknownUserNames {
    fn new() -> Self {
        KeepUsmStatsUnknownUserNames {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepUsmStatsUnknownUserNames {
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
// Command Generator Applications to coordinate their
// use of facilities to alter secrets in the
// usmUserTable.
//

struct KeepUsmUserSpinLock {
    scalar: PersistentScalar,
}

impl KeepUsmUserSpinLock {
    fn new(config: &Config) -> Self {
        let file_name: String = config.storage_path.clone() + "/usm_user_spin_lock";
        KeepUsmUserSpinLock {
            scalar: PersistentScalar::new(
                simple_from_int(4),
                OType::Integer,
                Access::ReadWrite,
                file_name,
            ),
        }
    }
}

impl OidKeeper for KeepUsmUserSpinLock {
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
// The total number of packets received by the SNMP
// engine which were dropped because they didn't
// contain the expected digest value.
//

struct KeepUsmStatsWrongDigests {
    scalar: ScalarMemOid,
}

impl KeepUsmStatsWrongDigests {
    fn new() -> Self {
        KeepUsmStatsWrongDigests {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepUsmStatsWrongDigests {
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
// The total number of packets received by the SNMP
// engine which were dropped because they could not be
// decrypted.
//

struct KeepUsmStatsDecryptionErrors {
    err_cnt: u32,
}

impl KeepUsmStatsDecryptionErrors {
    fn new(agent: &Agent) -> Self {
        KeepUsmStatsDecryptionErrors {
            err_cnt: agent.decryption_errors,
        }
    }
}

impl OidKeeper for KeepUsmStatsDecryptionErrors {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {
        true
    }
    fn get(&self, _oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
        let value: i32 = self.err_cnt.try_into().unwrap_or(i32::MAX);
        Ok(VarBindValue::Value(simple_from_int(value)))
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
    ) -> Result<VarBindValue, OidErr> {
        Err(OidErr::NotWritable)
    }
}
// The total number of packets received by the SNMP
// engine which were dropped because they referenced an
// snmpEngineID that was not known to the SNMP engine.
//

struct KeepUsmStatsUnknownEngineIDs {
    scalar: ScalarMemOid,
}

impl KeepUsmStatsUnknownEngineIDs {
    fn new() -> Self {
        KeepUsmStatsUnknownEngineIDs {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepUsmStatsUnknownEngineIDs {
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
// The total number of packets received by the SNMP
// engine which were dropped because they appeared
// outside of the authoritative SNMP engine's window.
//

struct KeepUsmStatsNotInTimeWindows {
    scalar: ScalarMemOid,
}

impl KeepUsmStatsNotInTimeWindows {
    fn new() -> Self {
        KeepUsmStatsNotInTimeWindows {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepUsmStatsNotInTimeWindows {
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
// The total number of packets received by the SNMP
// engine which were dropped because they requested a
// securityLevel that was unknown to the SNMP engine
// or otherwise unavailable.
//

struct KeepUsmStatsUnsupportedSecLevels {
    scalar: ScalarMemOid,
}

impl KeepUsmStatsUnsupportedSecLevels {
    fn new() -> Self {
        KeepUsmStatsUnsupportedSecLevels {
            scalar: ScalarMemOid::new(counter_from_int(0), OType::Counter, Access::ReadOnly),
        }
    }
}

impl OidKeeper for KeepUsmStatsUnsupportedSecLevels {
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
// A user configured in the SNMP engine's Local
// Configuration Datastore (LCD) for the User-based
// Security Model.
//

struct KeepUsmUserTable {
    //users: &'a Users<'a>,
    table: TableMemOid,
}

impl  KeepUsmUserTable{
    fn new(users: & Users, engine_id: OctetString) -> Self {
        let base_oid: ObjectIdentifier = ObjectIdentifier::new(&ARC_USM_USER_TABLE).unwrap();
        let mut data = vec![];
        for user in &users.users {
            let mut name = vec![];
            for b in &user.name {
                name.push(*b);
            }
            let row = vec![
                    ObjectSyntax::Simple(SimpleSyntax::String(engine_id.clone())),
                    simple_from_str(& name),
                    simple_from_str(& name),
                    simple_from_vec(&[0, 0]),
                    simple_from_vec(&ARC_USM_HMACSHA_AUTH_PROTOCOL),
                    simple_from_str(b"'"),
                    simple_from_str(b"'"),
                    simple_from_vec(&ARC_USM_AES_CFB_128_PRIV_PROTOCOL),
                    simple_from_str(b"'"),
                    simple_from_str(b"'"),
                    simple_from_str(b"'"),
                    simple_from_int(3),
                    simple_from_vec(&[1, 3, 6, 1]),
                ];
            data.push(row);
        }
        KeepUsmUserTable {
            table: TableMemOid::new(
                data,
                vec![
                    ObjectSyntax::Simple(SimpleSyntax::String(engine_id.clone())),
                    simple_from_str(b"b"),
                    simple_from_str(b"b"),
                    simple_from_vec(&[0, 0]),
                    simple_from_vec(&ARC_USM_NO_AUTH_PROTOCOL),
                    simple_from_str(b"'"),
                    simple_from_str(b"'"),
                    simple_from_vec(&ARC_USM_NO_PRIV_PROTOCOL),
                    simple_from_str(b"'"),
                    simple_from_str(b"'"),
                    simple_from_str(b"'"),
                    simple_from_int(3),
                    simple_from_vec(&[1, 3, 6, 1]),
                ],
                13,
                &base_oid,
                vec![
                    OType::String,
                    OType::String,
                    OType::String,
                    OType::ObjectId,
                    OType::ObjectId,
                    OType::ObjectId,
                    OType::ObjectId,
                    OType::ObjectId,
                    OType::ObjectId,
                    OType::ObjectId,
                    OType::String,
                    OType::ObjectId,
                    OType::ObjectId,
                ],
                vec![
                    Access::NoAccess,
                    Access::NoAccess,
                    Access::ReadOnly,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
                    Access::ReadCreate,
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

impl OidKeeper for KeepUsmUserTable {
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

pub fn load_stub(oid_map: &mut OidMap, config: &Config, agent: &Agent, users: &Users) {
    // The next group is for OBJECT-IDENTITY.

    // These may be used as values rather than MIB addresses

    let _oid_usm_no_auth_protocol: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_NO_AUTH_PROTOCOL).unwrap();

    let _oid_usm_hmacmd5auth_protocol: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_HMACMD5AUTH_PROTOCOL).unwrap();

    let _oid_usm_hmacsha_auth_protocol: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_HMACSHA_AUTH_PROTOCOL).unwrap();

    let _oid_usm_no_priv_protocol: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_NO_PRIV_PROTOCOL).unwrap();

    let _oid_usm_des_priv_protocol: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_DES_PRIV_PROTOCOL).unwrap();

    let _oid_usm_aes_cfb_128_priv_protocol: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_AES_CFB_128_PRIV_PROTOCOL).unwrap();

    let _oid_snmp_auth_protocols: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_AUTH_PROTOCOLS).unwrap();

    let _oid_snmp_priv_protocols: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_SNMP_PRIV_PROTOCOLS).unwrap();

    let oid_usm_stats_unknown_user_names: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_STATS_UNKNOWN_USER_NAMES).unwrap();

    let k_usm_stats_unknown_user_names: Box<dyn OidKeeper> =
        Box::new(KeepUsmStatsUnknownUserNames::new());
    oid_map.push(
        oid_usm_stats_unknown_user_names,
        k_usm_stats_unknown_user_names,
    );
    let oid_usm_user_spin_lock: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_USER_SPIN_LOCK).unwrap();
    let k_usm_user_spin_lock: Box<dyn OidKeeper> = Box::new(KeepUsmUserSpinLock::new(config));
    oid_map.push(oid_usm_user_spin_lock, k_usm_user_spin_lock);
    let oid_usm_stats_wrong_digests: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_STATS_WRONG_DIGESTS).unwrap();
    let k_usm_stats_wrong_digests: Box<dyn OidKeeper> = Box::new(KeepUsmStatsWrongDigests::new());
    oid_map.push(oid_usm_stats_wrong_digests, k_usm_stats_wrong_digests);
    let oid_usm_stats_decryption_errors: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_STATS_DECRYPTION_ERRORS).unwrap();
    let k_usm_stats_decryption_errors: Box<dyn OidKeeper> =
        Box::new(KeepUsmStatsDecryptionErrors::new(agent));
    oid_map.push(
        oid_usm_stats_decryption_errors,
        k_usm_stats_decryption_errors,
    );
    let oid_usm_stats_unknown_engine_i_ds: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_STATS_UNKNOWN_ENGINE_I_DS).unwrap();
    let k_usm_stats_unknown_engine_i_ds: Box<dyn OidKeeper> =
        Box::new(KeepUsmStatsUnknownEngineIDs::new());
    oid_map.push(
        oid_usm_stats_unknown_engine_i_ds,
        k_usm_stats_unknown_engine_i_ds,
    );
    let oid_usm_stats_not_in_time_windows: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_STATS_NOT_IN_TIME_WINDOWS).unwrap();
    let k_usm_stats_not_in_time_windows: Box<dyn OidKeeper> =
        Box::new(KeepUsmStatsNotInTimeWindows::new());
    oid_map.push(
        oid_usm_stats_not_in_time_windows,
        k_usm_stats_not_in_time_windows,
    );
    let oid_usm_stats_unsupported_sec_levels: ObjectIdentifier =
        ObjectIdentifier::new(&ARC_USM_STATS_UNSUPPORTED_SEC_LEVELS).unwrap();
    let k_usm_stats_unsupported_sec_levels: Box<dyn OidKeeper> =
        Box::new(KeepUsmStatsUnsupportedSecLevels::new());
    oid_map.push(
        oid_usm_stats_unsupported_sec_levels,
        k_usm_stats_unsupported_sec_levels,
    );
    let oid_usm_user_table: ObjectIdentifier = ObjectIdentifier::new(&ARC_USM_USER_TABLE).unwrap();
    let k_usm_user_table: Box<dyn OidKeeper> = Box::new(KeepUsmUserTable::new(users, config.engine_id.clone()));
    oid_map.push(oid_usm_user_table, k_usm_user_table);
}
