use crate::keeper::oid_keep::{OidKeeper, OidErr, Access, check_otype, check_type};
use rasn::types::ObjectIdentifier;
use rasn_smi::v2::ObjectSyntax;
use rasn_snmp::v3::{VarBind, VarBindValue};
//use log::debug;

/// Simplistic scalar stored in memory.
/// Initialized in constructor.
pub struct ScalarMemOid {
    value: ObjectSyntax,
    otype: char,
    access: Access,
}

impl ScalarMemOid {
    /// Initialize with initial value, and char that selects type checking.
    /// Any variant of ObjectSyntax is OK
    ///
    /// There is are self consistency checks that the char is a known one,
    /// and that the initial value is consistent with that type.
    ///
    /// The type mapping is:
    /// * Simple(SimpleSyntax::Integer(_)) => 'i' (also 'r' for RowStatus in tables),
    /// * Simple(SimpleSyntax::String(_)) => 's',
    /// * Simple(SimpleSyntax::ObjectId(_)) => 'o',
    /// * ApplicationWide(ApplicationSyntax::Address(_)) => 'a',
    /// * ApplicationWide(ApplicationSyntax::Unsigned(_)) => 'u',
    /// * ApplicationWide(ApplicationSyntax::Arbitrary(_)) => '?',
    /// * ApplicationWide(ApplicationSyntax::Counter(_)) => 'c',
    /// * ApplicationWide(ApplicationSyntax::BigCounter(_)) => 'b',
    /// * ApplicationWide(ApplicationSyntax::Ticks(_)) => 't',
    pub fn new(value: ObjectSyntax, otype: char, access: Access) -> Self {
        if !check_otype(otype) {
            panic!("Unrecognised type char {otype}");
        }
        if !check_type(otype, &value) {
            panic!("Initial value is unexpected type {otype} {value:?}");
        }
        ScalarMemOid {
            value,
            otype,
            access,
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

    fn set(
        &mut self,
        _oid: ObjectIdentifier,
        value: VarBindValue,
    ) -> Result<VarBindValue, OidErr> {
        if self.access == Access::ReadCreate || self.access == Access::ReadWrite {
            if let VarBindValue::Value(new_value) = value.clone() {
                if check_type(self.otype, &new_value) {
                    self.value = new_value;
                } else {
                    return Err(OidErr::WrongType);
                }
            }
            Ok(value)
        } else {
            Err(OidErr::NotWritable)
        }
    }
}

/*
pub struct PersistentScalar {
    scalar: ScalarMemOid,
    file_name: &'static [u8],
}

impl PersistentScalar {
    pub fn new(
        value: ObjectSyntax,
        otype: char,
        access: Access,
        file_name: &'static [u8],
    ) -> Self {
        let scalar = ScalarMemOid::new(value, otype, access);
        PersistentScalar { scalar, file_name }
    }

    pub fn load(self) {
        debug!["file name {0:?}", self.file_name];
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

    fn set(
        &mut self,
        oid: ObjectIdentifier,
        value: VarBindValue,
    ) -> Result<VarBindValue, OidErr> {
        self.scalar.set(oid, value)
    }
}
*/