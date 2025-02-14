use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v1::InvalidVariant;
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use rasn_snmp::v3::{VarBind, VarBindValue};
use snmp_rust_agent::keeper::oid_keep::{OidErr, OidKeeper, ScalarMemOid, TableMemOid};
use snmp_rust_agent::snmp_agent::{Agent, OidMap};
//Change this to match your organisation's IANA registration, This example
// uses the "dynamic" MAC address scheme, but many other name systems work.

const ARC: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 4];
const ARC1: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 5];
const ARC2: [u32; 10] = [1, 3, 6, 1, 6, 3, 15, 1, 1, 6];
static ENGINESTR: &[u8; 11] = b"\x80\x00\x4e\x2c\x03\x34\x48\xed\x2d\xe2\x88";

fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

/// This enum has to include all the different structs that are used
/// It is in main so other struct type can be used as well as the two
/// volatile memory based ones.
enum OT {
    Scalar(ScalarMemOid),
    Table(TableMemOid),
    // More types go here.
}

/// You need to implement this trait for every member of the enum.
/// There is a request in to make this automatic if we declare
/// a trait bound on the enum.
impl OidKeeper for OT {
    fn is_scalar(&self) -> bool {
        match self {
            OT::Scalar(_) => true,
            OT::Table(_) => false,
        }
    }
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {
        match self {
            OT::Scalar(sc) => sc.get(oid),
            OT::Table(ta) => ta.get(oid),
        }
    }
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {
        match self {
            OT::Scalar(sc) => sc.get_next(oid),
            OT::Table(ta) => ta.get_next(oid),
        }
    }
    fn set(&mut self, oid: ObjectIdentifier, value: VarBindValue) -> Result<VarBindValue, OidErr> {
        match self {
            OT::Scalar(sc) => sc.set(oid, value),
            OT::Table(ta) => ta.set(oid, value),
        }
    }
}

fn col1(row: &[ObjectSyntax]) -> Vec<u32> {
    let ind_res: Result<u32, InvalidVariant> = row[0].clone().try_into();
    match ind_res {
        Ok(ind) => {
            vec![ind]
        }
        Err(_) => {
            panic!("Wanted integer in index")
        }
    }
}

/// Simplistic example main
fn main() -> std::io::Result<()> {
    let oid: ObjectIdentifier = ObjectIdentifier::new(&ARC).unwrap();
    let oid1: ObjectIdentifier = ObjectIdentifier::new(&ARC1).unwrap();
    let oid2: ObjectIdentifier = ObjectIdentifier::new(&ARC2).unwrap();
    let eid = OctetString::from_static(ENGINESTR);
    let s42 = simple_from_int(42);
    let s5 = simple_from_int(5);
    let mut k4 = OT::Scalar(ScalarMemOid::new(s42.clone(), 'i'));
    let mut k5 = OT::Scalar(ScalarMemOid::new(s5.clone(), 'i'));
    let mut k6 = OT::Table(TableMemOid::new(
        vec![vec![s5, s42]],
        2,
        &oid1,
        vec!['i', 'i'],
        col1,
    ));
    //snmp_engine_id::mac_engine_id(20012, "04:cf:4b:e3:cb:64");
    let mut oid_map = OidMap::<OT>::new();
    oid_map.push((&oid, &mut k4));
    oid_map.push((&oid1, &mut k6));
    oid_map.push((&oid2, &mut k5));
    let mut agent: Agent = Agent::build(eid, "127.0.0.1:2161");
    agent.loop_forever(&mut oid_map);
    Ok(())
}
