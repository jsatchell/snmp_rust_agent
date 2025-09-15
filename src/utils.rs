//! Module of utility functions for generating initial values for filling scalars and tables
//!
//!

use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v1::IpAddress;
use rasn_smi::v2::{
    ApplicationSyntax, Counter32, Counter64, ObjectSyntax, SimpleSyntax, TimeTicks, Unsigned32,
};

pub fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

pub fn simple_from_str(value: &'static [u8]) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_static(value)))
}

pub fn simple_from_vec(value: &'static [u32]) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::ObjectId(
        ObjectIdentifier::new(value).unwrap(), //Checked panics if value too long or value[0] > 2.
    ))
}

#[allow(dead_code)]
pub fn counter_from_int(value: u32) -> ObjectSyntax {
    ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(Counter32 { 0: value }))
}

#[allow(dead_code)]
pub fn big_counter_from_int(value: u64) -> ObjectSyntax {
    ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(Counter64(value)))
}

#[allow(dead_code)]
pub fn ticks_from_int(value: u32) -> ObjectSyntax {
    ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(TimeTicks { 0: value }))
}

#[allow(dead_code)]
pub fn address_from_zeros() -> ObjectSyntax {
    ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(IpAddress([0, 0, 0, 0].into())))
}

#[allow(dead_code)]
pub fn unsigned_from_value(value: u32) -> ObjectSyntax {
    ObjectSyntax::ApplicationWide(ApplicationSyntax::Unsigned(Unsigned32 { 0: value }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use rasn::types::{Integer, ObjectIdentifier};
    use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};

    const ARC2: [u32; 2] = [1, 6];

    #[test]
    fn test_simple_from_int() {
        let x = simple_from_int(21);
        assert_eq!(
            x,
            ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(21)))
        );
    }

    #[test]
    fn test_simple_from_str() {
        let x = simple_from_str(b"test");
        assert_eq!(
            x,
            ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_static(b"test")))
        );
    }

    #[test]
    fn test_simple_from_vec() {
        let x = simple_from_vec(&ARC2);
        assert_eq!(
            x,
            ObjectSyntax::Simple(SimpleSyntax::ObjectId(
                ObjectIdentifier::new(&ARC2).unwrap()
            ))
        );
    }

    #[test]
    fn test_counter_from_int() {
        let x = counter_from_int(21);
        assert_eq!(
            x,
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(Counter32 { 0: 21 }))
        );
    }

    #[test]
    fn test_big_from_int() {
        let x = big_counter_from_int(21);
        assert_eq!(
            x,
            ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(Counter64(21)))
        );
    }

    #[test]
    fn test_ticks_from_int() {
        let x = ticks_from_int(21);
        assert_eq!(
            x,
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(TimeTicks { 0: 21 }))
        )
    }

    #[test]
    fn test_address_from_zeros() {
        let x = address_from_zeros();
        assert_eq!(
            x,
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(IpAddress(
                [0, 0, 0, 0].into()
            )))
        );
    }

    #[test]
    fn test_unsigned() {
        let x = unsigned_from_value(73);
        assert_eq!(
            x,
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Unsigned(Unsigned32 { 0: 73 }))
        );
    }
}
