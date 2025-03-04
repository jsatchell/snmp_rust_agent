// Minimal interim permissions model
// 
// Radically simpler than the full VACM model!
use crate::keeper::oid_keep::OidKeeper;
use rasn_snmp::v2::Pdu;
use rasn::types::ObjectIdentifier;
use crate::usm;

struct Perm {
    read: bool,
    write: bool,
    security_level: u32,  // Just flags
    name: Vec<u8>,
}

pub struct PermModel {
   perms: Vec<Perm>
}

pub impl PermModel {
    pub fn new(data: Vec<Perm>) -> Self {
        PermModel{perms: data}
    }

    pub fn check(self, _oid: &ObjectIdentifier, op: &Pdu,  )
}