pub mod oid_keep {

    use rasn::types::ObjectIdentifier;
    use rasn_smi::v2::{ApplicationSyntax, ObjectSyntax, SimpleSyntax};
    use rasn_snmp::v3::{VarBind, VarBindValue};
    // Constants for table row management
    /* const ROW_STATUS_ACTIVE: Integer = Integer::Primitive(1);
    const ROW_STATUS_NOT_IN_SERVICE: Integer = Integer::Primitive(2);
    const ROW_STATUS_NOT_READY: Integer = Integer::Primitive(3);
    const ROW_STATUS_CREATE_AND_GO: Integer = Integer::Primitive(4);
    const ROW_STATUS_CREATE_AND_WAIT: Integer = Integer::Primitive(5);
    const ROW_STATUS_DELETE: Integer = Integer::Primitive(6); */

    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    pub enum OidErr {
        OutOfRange,
        WrongType,
        NoSuchInstance,
        NoSuchName,
        NoAccess,
        NotWritable,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
    pub enum Access {
        NoAccess,
        NotificationOnly,
        ReadOnly,
        ReadWrite,
        ReadCreate,
    }

    pub fn check_type(otype: char, val: &ObjectSyntax) -> bool {
        match val {
            ObjectSyntax::Simple(SimpleSyntax::Integer(_)) => otype == 'i' || otype == 'r',
            ObjectSyntax::Simple(SimpleSyntax::String(_)) => otype == 's',
            ObjectSyntax::Simple(SimpleSyntax::ObjectId(_)) => otype == 'o',
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(_)) => otype == 'a',
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Unsigned(_)) => otype == 'u',
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Arbitrary(_)) => otype == '?',
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(_)) => otype == 'c',
            ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(_)) => otype == 'b',
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(_)) => otype == 't',
        }
    }

    pub fn check_otype(otype: char) -> bool {
        ['a', 'b', 'c', 'i', 'o', 's', 't', 'u', '?', 'r'].contains(&otype)
    }

    pub trait OidKeeper {
        fn is_scalar(&self, oid: ObjectIdentifier) -> bool;
        fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr>;
        fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr>;
        fn access(&self, oid: ObjectIdentifier) -> Access;
        fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr>;
    }

    
}

