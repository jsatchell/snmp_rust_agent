pub mod oid_keep {
    use rasn::types::{Integer, ObjectIdentifier};
    use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
    use rasn_snmp::v3::VarBindValue;
    // use rasn_snmp::v2::{Pdu, Report, VarBind};
    //use std::error::Error;

    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    pub struct OidErr;

    pub trait OidKeeper {
        fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr>;
        fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr>;
        // fn get_next(oid: ObjectIdentifier) -> Result<(ObjectIdentifier, VarBindValue), OidErr>;
    }

    pub struct ScalarMemOid {
        value: isize,
    }

    impl ScalarMemOid {
        pub fn new(value: isize) -> Self {
            ScalarMemOid { value }
        }
    }
    impl OidKeeper for ScalarMemOid {
        fn get(&self, _oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
            Ok(VarBindValue::Value(ObjectSyntax::Simple(
                SimpleSyntax::Integer(Integer::from(self.value)),
            )))
        }

        fn set(
            &mut self,
            _oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {
            if let VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::Integer(
                Integer::Primitive(new_value),
            ))) = value
            {
                self.value = new_value;
            }
            Ok(value)
        }
    }
}
