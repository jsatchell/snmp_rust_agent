//! Module of utility functions for generating initial values for filling scalars and tables
//!
//!

use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v1::IpAddress;
use rasn_smi::v2::{
    ApplicationSyntax, Counter32, Counter64, ObjectSyntax, SimpleSyntax, TimeTicks,
};

pub fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

pub fn simple_from_str(value: &'static [u8]) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_static(value)))
}

pub fn simple_from_vec(value: &'static [u32]) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::ObjectId(
        ObjectIdentifier::new(value).unwrap(),
    ))
}

#[allow(dead_code)]
pub fn counter_from_int(value: u32) -> ObjectSyntax {
    ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(Counter32 { 0: value }))
}

#[allow(dead_code)]
pub fn big_counter_from_int(value: u64) -> ObjectSyntax {
    ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(Counter64 { 0: value }))
}

#[allow(dead_code)]
pub fn ticks_from_int(value: u32) -> ObjectSyntax {
    ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(TimeTicks { 0: value }))
}

#[allow(dead_code)]
pub fn address_from_zeros() -> ObjectSyntax {
    ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(IpAddress([0, 0, 0, 0].into())))
}
