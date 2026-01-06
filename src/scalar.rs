use crate::keeper::{check_type, Access, OType, OidErr, OidKeeper};
use crate::usm::User;
use num_traits::ToPrimitive;
use rasn::ber::{decode, encode};
use rasn::types::{Integer, ObjectIdentifier};
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use rasn_snmp::v3::{VarBind, VarBindValue};
use std::io::Error;
use std::path::PathBuf;

use log::{debug, error};

/// Simplistic scalar stored in memory.
/// Initialized in constructor.
#[derive(PartialEq, Eq)]
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

    fn set(
        &mut self,
        _oid: ObjectIdentifier,
        value: VarBindValue,
        _user: &User,
    ) -> Result<VarBindValue, OidErr> {
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
                                let mut incr32: u32 = incr.to_u32().unwrap() + 1; // Checked, rolls over at 2^31
                                if incr32 > 2147483647u32 {
                                    incr32 = 0u32;
                                }
                                let incr1 = Integer::from(incr32);
                                self.pending = ObjectSyntax::Simple(SimpleSyntax::Integer(incr1));
                            }
                        } else {
                            return Err(OidErr::OutOfRange); // InconsistentValue
                        }
                    } else {
                        self.pending = new_value;
                    }
                } else {
                    return Err(OidErr::WrongType);
                }
            }
            Ok(value)
        } else {
            Err(OidErr::NotWritable)
        }
    }

    fn commit(&mut self, _user: &User) -> Result<(), OidErr> {
        self.value = self.pending.clone();
        self.transaction = false;
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), OidErr> {
        self.transaction = false;
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
pub struct PersistentScalar {
    scalar: ScalarMemOid,
    file_name: PathBuf,
}

impl PersistentScalar {
    pub fn new(value: ObjectSyntax, otype: OType, access: Access, file_name: PathBuf) -> Self {
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

    fn set(
        &mut self,
        oid: ObjectIdentifier,
        value: VarBindValue,
        user: &User,
    ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value, user)
    }

    fn rollback(&mut self) -> Result<(), OidErr> {
        self.scalar.rollback()
    }

    fn commit(&mut self, user: &User) -> Result<(), OidErr> {
        let comm_res = self.scalar.commit(user);
        comm_res?;
        let bytes_res = encode::<ObjectSyntax>(&self.scalar.value);
        match bytes_res {
            Ok(bytes) => {
                let outcome = std::fs::write(&self.file_name, bytes);
                if outcome.is_err() {
                    error!["Write failure saving to {0:?}", self.file_name];
                    return Err(OidErr::CommitFail);
                }
            }
            Err(err) => {
                error!["Persistence failure {err:?}"];
                return Err(OidErr::CommitFail);
            }
        }
        comm_res
    }
    // Just use the default implementation for is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{Access, PersistentScalar};
    use crate::perms::{Perm, Rule};
    use crate::utils::simple_from_int;
    use rasn::types::{Integer, ObjectIdentifier};
    use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
    use rasn_snmp::v3::VarBindValue;

    const ARC2: [u32; 2] = [1, 6];

    #[test]
    fn test_simple_from_int() {
        let x = simple_from_int(21);
        assert_eq!(
            x,
            ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(21)))
        );
    }
    fn perms() -> Vec<Perm> {
        let rules = vec![Rule {
            read: true,
            write: true,
            context: None,
            include: vec![vec![1u32]],
            exclude: vec![],
        }];
        vec![Perm {
            rules,
            security_level: 1u8, // Just flags
            group_name: "test".as_bytes().to_vec(),
        }]
    }

    fn user_fixture<'a>(pv: &'a Vec<Perm>) -> User {
        let s ="test test sha1 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b aes 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
        let u = User::from_str(s, pv).unwrap(); // Checked #test
        u
    }

    fn pscl_fixture() -> PersistentScalar {
        let s42 = simple_from_int(42);
        PersistentScalar::new(
            s42.clone(),
            OType::Integer,
            Access::ReadWrite,
            PathBuf::from("/tmp/snmp-rust-persist"),
        )
    }

    #[test]
    fn pscl_get_test() {
        let pscl = pscl_fixture();
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap(); //Checked #test
        assert!(pscl.is_scalar(oid2.clone()));
        let res = pscl.get(oid2);
        let s42 = simple_from_int(42);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), VarBindValue::Value(s42)); //Checked #test
    }

    #[test]
    fn pscl_get_next() {
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap(); //Checked #test
        let pscl = pscl_fixture();
        let res = pscl.get_next(oid2.clone());
        assert!(res.is_err());
        assert_eq!(pscl.access(oid2), Access::ReadWrite);
    }

    #[test]
    fn pscl_persistence() {
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap(); //Checked #test
        let mut pscl = pscl_fixture();
        let s17 = simple_from_int(17);
        let vb = VarBindValue::Value(s17.clone());
        let b_res = pscl.begin_transaction();
        let pv = perms();
        let user = user_fixture(&pv);
        assert!(b_res.is_ok());
        let set_rs = pscl.set(oid2.clone(), vb, &user);
        assert!(set_rs.is_ok());
        let c_res = pscl.commit(&user);
        assert!(c_res.is_ok());
        let res = pscl.get(oid2.clone());
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), VarBindValue::Value(s17.clone())); //Checked #test
        let load_res = pscl.load();
        assert!(load_res.is_ok());
        let res = pscl.get(oid2);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), VarBindValue::Value(s17.clone())); //Checked #test
    }
    #[test]
    fn pscl_rollback() {
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap(); //Checked #test
        let mut pscl = pscl_fixture();
        let s17 = simple_from_int(17);
        let vb = VarBindValue::Value(s17.clone());
        let b_res = pscl.begin_transaction();
        let pv = perms();
        let user = user_fixture(&pv);
        assert!(b_res.is_ok());
        let set_rs = pscl.set(oid2.clone(), vb, &user);
        assert!(set_rs.is_ok());
        let c_res = pscl.rollback();
        assert!(c_res.is_ok());
        let res = pscl.get(oid2.clone());
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), VarBindValue::Value(simple_from_int(42))); //Checked #test
    }
    #[test]
    fn test_obvious() {
        let value = simple_from_int(7);
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap(); //Checked #test
        let s = ScalarMemOid::new(value, OType::Integer, Access::ReadWrite);
        assert!(s.is_scalar(oid2.clone()));
        assert_eq!(s.access(oid2), Access::ReadWrite);
        assert!(!s.is_empty());
    }

    #[test]
    #[should_panic]
    fn test_row_status_wrong() {
        let value = simple_from_int(7);
        let _s = ScalarMemOid::new(value, OType::RowStatus, Access::ReadWrite);
    }

    #[test]
    #[should_panic]
    fn test_row_type_wrong() {
        let value = simple_from_int(7);
        let _s = ScalarMemOid::new(value, OType::String, Access::ReadWrite);
    }

    #[test]
    fn test_lifecycle() {
        let value = simple_from_int(7);
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap(); //Checked #test
        let mut s = ScalarMemOid::new(value.clone(), OType::Integer, Access::ReadWrite);
        let s8 = simple_from_int(8);
        let vb = VarBindValue::Value(s8);
        let pv = perms();
        let user = user_fixture(&pv);
        let _ = s.rollback();
        assert!(s.set(oid2.clone(), vb.clone(), &user).is_err());
        assert!(s.begin_transaction().is_ok());
        assert!(s.begin_transaction().is_err()); // errors, and resets transaction
        assert!(s.begin_transaction().is_ok());
        assert!(s.set(oid2.clone(), vb.clone(), &user).is_ok());
        // No effect until commit
        assert_eq!(s.get(oid2.clone()).unwrap(), VarBindValue::Value(value)); // Checked #[test]
        assert!(s.commit(&user).is_ok());
        assert_eq!(s.get(oid2.clone()).unwrap(), vb); // Checked #[test]
    }

    #[test]
    fn test_incr() {
        let value = simple_from_int(7);
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap(); //Checked #test
        let mut s = ScalarMemOid::new(value.clone(), OType::TestAndIncr, Access::ReadWrite);
        let vb = VarBindValue::Value(value.clone());
        let s8 = simple_from_int(8);
        let vb8 = VarBindValue::Value(s8.clone());
        let pv = perms();
        let user = user_fixture(&pv);
        let _ = s.rollback();
        assert!(s.begin_transaction().is_ok());
        // Wrong value should be rejected
        assert!(s.set(oid2.clone(), vb8.clone(), &user).is_err());
        assert!(s.set(oid2.clone(), vb.clone(), &user).is_ok());
        // No effect until commit
        assert_eq!(s.get(oid2.clone()).unwrap(), VarBindValue::Value(value)); // Checked #[test]
        assert!(s.commit(&user).is_ok());
        assert_ne!(s.get(oid2.clone()).unwrap(), vb); // Checked #[test]
    }

    #[test]
    fn test_incr_rollover() {
        let value = simple_from_int(2147483647i32);
        let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap(); //Checked #test
        let mut s = ScalarMemOid::new(value.clone(), OType::TestAndIncr, Access::ReadWrite);
        let vb = VarBindValue::Value(value.clone());
        let s8 = simple_from_int(8);
        let vb8 = VarBindValue::Value(s8.clone());
        let pv = perms();
        let user = user_fixture(&pv);
        let _ = s.rollback();
        assert!(s.begin_transaction().is_ok());
        // Wrong value should be rejected
        assert!(s.set(oid2.clone(), vb8.clone(), &user).is_err());
        assert!(s.set(oid2.clone(), vb.clone(), &user).is_ok());
        // No effect until commit
        assert_eq!(s.get(oid2.clone()).unwrap(), VarBindValue::Value(value)); // Checked #[test]
        assert!(s.commit(&user).is_ok());
        let vb0 = s.get(oid2.clone()).unwrap(); // Checked #[test]
        if let VarBindValue::Value(s0) = vb0 {
            assert_eq!(s0, simple_from_int(0));
        }
    }
}
