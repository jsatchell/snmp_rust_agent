//! Typing for handlers
//!
//! Module contains the OidKeep trait and three utility enums.
//!

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

// Defines what types are allowed for scalar or table column
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OType {
    Integer,
    RowStatus,
    TestAndIncr,
    String,
    ObjectId,
    Address,
    Unsigned,
    Arbitrary,
    Counter,
    BigCounter,
    Ticks,
}

// Return true if the type of val is consistent with the enum otype.
pub fn check_type(otype: OType, val: &ObjectSyntax) -> bool {
    match val {
        ObjectSyntax::Simple(SimpleSyntax::Integer(_)) => {
            otype == OType::Integer || otype == OType::RowStatus || otype == OType::TestAndIncr
        }
        ObjectSyntax::Simple(SimpleSyntax::String(_)) => otype == OType::String,
        ObjectSyntax::Simple(SimpleSyntax::ObjectId(_)) => otype == OType::ObjectId,
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(_)) => otype == OType::Address,
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Unsigned(_)) => otype == OType::Unsigned,
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Arbitrary(_)) => otype == OType::Arbitrary,
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(_)) => otype == OType::Counter,
        ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(_)) => {
            otype == OType::BigCounter
        }
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(_)) => otype == OType::Ticks,
    }
}

// Trait for handlers
//
// Sample memory based implementations are in table.rs and scalar.rs.
pub trait OidKeeper {
    // Return true if trait object handles a scalar.
    //
    // SNMP has different semantics for scalars and conceptual tables.
    fn is_scalar(&self, oid: ObjectIdentifier) -> bool;

    // Implement to support the Get PDU
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr>;

    // Implement to support GetNext PDU - also used in GetBulk
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr>;

    // Return the access for the given Oid
    fn access(&self, oid: ObjectIdentifier) -> Access;

    // Set a value, if permitted
    fn set(&mut self, oid: ObjectIdentifier, value: VarBindValue) -> Result<VarBindValue, OidErr>;
}
