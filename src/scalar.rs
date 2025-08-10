use crate::keeper::{check_type, Access, OType, OidErr, OidKeeper};
use num_traits::ToPrimitive;
use rasn::ber::{decode, encode};
use rasn::types::{Integer, ObjectIdentifier};
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use rasn_snmp::v3::{VarBind, VarBindValue};
use std::io::Error;

use log::{debug, error};

/// Simplistic scalar stored in memory.
/// Initialized in constructor.
#[derive(PartialEq, Eq, Hash)]
pub struct ScalarMemOid {
    value: ObjectSyntax,
    otype: OType,
    access: Access,
    transaction: bool,
    pending: ObjectSyntax,
}

impl ScalarMemOid {
    /// Initialize with initial value, and enum that selects type checking.
    /// Any variant of ObjectSyntax is OK
    ///
    /// There is a self consistency check that the enum is a sane one,
    /// and that the initial value is consistent with that type.
    ///
    /// The type mapping is in enum OType
    pub fn new(value: ObjectSyntax, otype: OType, access: Access) -> Self {
        if otype == OType::RowStatus {
            panic!("RowStatus not possible type for Scalar object");
        }
        if !check_type(otype, &value) {
            panic!("Initial value is unexpected type {otype:?} {value:?}");
        }
        ScalarMemOid {
            value: value.clone(),
            otype,
            access,
            transaction: false,
            pending: value,
        }
    }
}

impl OidKeeper for ScalarMemOid {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {
        true
    }

    fn get(&self, _oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
        if self.access == Access::NoAccess || self.access == Access::NotificationOnly {
            Err(OidErr::NoAccess)
        } else {
            Ok(VarBindValue::Value(self.value.clone()))
        }
    }

    // Scalar, so next item always lies outside
    fn get_next(&self, _oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
        Err(OidErr::OutOfRange)
    }

    fn access(&self, _oid: ObjectIdentifier) -> Access {
        self.access
    }

    fn begin_transaction(&mut self) -> Result<(), OidErr> {
        if self.transaction {
            self.transaction = false;
            Err(OidErr::WrongType)
        } else {
            self.transaction = true;
            Ok(())
        }
    }

    fn set(&mut self, _oid: ObjectIdentifier, value: VarBindValue) -> Result<VarBindValue, OidErr> {
        if self.access == Access::ReadCreate || self.access == Access::ReadWrite {
            if !self.transaction {
                return Err(OidErr::WrongType);
            }
            if let VarBindValue::Value(new_value) = value.clone() {
                if check_type(self.otype, &new_value) {
                    if self.otype == OType::TestAndIncr {
                        // Then return current value and increment
                        if new_value == self.value {
                            if let ObjectSyntax::Simple(SimpleSyntax::Integer(incr)) = &self.value {
                                let mut incr32: u32 = incr.to_u32().unwrap() + 1;
                                if incr32 > 2147483647u32 {
                                    incr32 = 0u32;
                                }
                                let incr1 = Integer::from(incr32);
                                self.pending = ObjectSyntax::Simple(SimpleSyntax::Integer(incr1));
                            }
                        } else {
                            return Err(OidErr::OutOfRange); // InconsistentValue
                        }
                    }
                    self.pending = new_value;
                } else {
                    return Err(OidErr::WrongType);
                }
            }
            Ok(value)
        } else {
            Err(OidErr::NotWritable)
        }
    }

    fn commit(&mut self) -> Result<(), OidErr> {
        self.value = self.pending.clone();
        self.transaction = false;
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), OidErr> {
        self.transaction = false;
        Ok(())
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct PersistentScalar {
    scalar: ScalarMemOid,
    file_name: String,
}

impl PersistentScalar {
    pub fn new(value: ObjectSyntax, otype: OType, access: Access, file_name: String) -> Self {
        let scalar = ScalarMemOid::new(value, otype, access);
        PersistentScalar { scalar, file_name }
    }

    pub fn load(&mut self) -> Result<(), Error> {
        debug!["file name {0:?}", self.file_name];
        let bytes = std::fs::read(self.file_name.clone())?;
        let value_res = decode::<ObjectSyntax>(&bytes);
        match value_res {
            Ok(value) => {
                self.scalar.value = value;
                Ok(())
            }
            Err(err) => {
                panic!["Decode failure {err:?}"];
            }
        }
    }
}

impl OidKeeper for PersistentScalar {
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {
        true
    }

    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
        self.scalar.get(oid)
    }

    // Scalar, so next item always lies outside
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
        self.scalar.get_next(oid)
    }

    fn access(&self, oid: ObjectIdentifier) -> Access {
        self.scalar.access(oid)
    }

    fn begin_transaction(&mut self) -> Result<(), OidErr> {
        self.scalar.begin_transaction()
    }

    fn set(&mut self, oid: ObjectIdentifier, value: VarBindValue) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value)
    }

    fn rollback(&mut self) -> Result<(), OidErr> {
        self.scalar.rollback()
    }

    fn commit(&mut self) -> Result<(), OidErr> {
        let comm_res = self.scalar.commit();
        let bytes_res = encode::<ObjectSyntax>(&self.scalar.value);
        match bytes_res {
            Ok(bytes) => {
                let outcome = std::fs::write(&self.file_name, bytes);
                if outcome.is_err() {
                    error!["Write failure saving to {0}", self.file_name]
                }
            }
            Err(err) => {
                error!["Persistence failure {err:?}"];
            }
        }
        comm_res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{Access, PersistentScalar};
    use rasn::types::{Integer, ObjectIdentifier};
    use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
    use rasn_snmp::v3::VarBindValue;

    fn simple_from_int(value: i32) -> ObjectSyntax {
        ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
    }

    const ARC2: [u32; 2] = [1, 6];

    #[test]
    fn test_simple_from_int() {
        let x = simple_from_int(21);
        assert_eq!(
            x,
            ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(21)))
        );
    }

    fn pscl_fixture() -> PersistentScalar {
        let s42 = simple_from_int(42);
        PersistentScalar::new(
            s42.clone(),
            OType::Integer,
            Access::ReadWrite,
            "/tmp/snmp-rust-persist".to_string(),
        )
    }

    #[test]
    fn pscl_get_test() {
        let pscl = pscl_fixture();
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap();
        let res = pscl.get(oid2);
        let s42 = simple_from_int(42);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), VarBindValue::Value(s42));
    }

    #[test]
    fn pscl_get_next() {
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap();
        let pscl = pscl_fixture();
        let res = pscl.get_next(oid2.clone());
        assert!(res.is_err());
    }

    #[test]
    fn pscl_persistence() {
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap();
        let mut pscl = pscl_fixture();
        let s17 = simple_from_int(17);
        let vb = VarBindValue::Value(s17.clone());
        let b_res = pscl.begin_transaction();
        assert!(b_res.is_ok());
        let set_rs = pscl.set(oid2.clone(), vb);
        assert!(set_rs.is_ok());
        let c_res = pscl.commit();
        assert!(c_res.is_ok());
        let res = pscl.get(oid2.clone());
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), VarBindValue::Value(s17.clone()));
        let load_res = pscl.load();
        assert!(load_res.is_ok());
        let res = pscl.get(oid2);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), VarBindValue::Value(s17.clone()));
    }
}
