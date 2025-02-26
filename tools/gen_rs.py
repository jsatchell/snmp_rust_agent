# Copyright Julian Satchell 2025
import logging
import sys

LOGGER = logging.getLogger(__file__)
NAME_CHAR = {"INTEGER": 'i',
             "TimeStamp": 's',
             "DateAndTime": 's',
             "TimeTicks": 't',
             "TimeInterval": 'i',
             "UUIDorZero": 's',
             "Counter64": 'b',
             "Counter": 'c',
             "AutonomousType": "o",
             "IANAStorageMediaType": "i",
             "SnmpAdminString": 's',
             "DisplayString": 's',
             "InterfaceIndexOrZero": 'i',
             "PhysAddress": 'a',
             "Integer32": 'i',
             "Unsigned32": 'i',
             "Gauge32": 'c',
             "OCTET": 's',
             "BITS": 's',
             "Opaque": 's',
             "OBJECT": 'o',
             "Counter32": 'c',
             "IpAddress": 'a',
             }


def gen_rs(otypes, resolve, tcs, ents, play: bool = True, out=sys.stdout, listen="127.0.0.1:2161"):
    if not play:
        LOGGER.warning("Generating play code anyway - stub generation not ready")

    start = r"""use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v1::InvalidVariant;
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use rasn_snmp::v3::{VarBind, VarBindValue};
use snmp_rust_agent::keeper::oid_keep::{OidErr, OidKeeper, ScalarMemOid, TableMemOid};
use snmp_rust_agent::oidmap::OidMap;
use snmp_rust_agent::snmp_agent::Agent;

static ENGINESTR: &[u8; 11] = b"\x80\x00\x4e\x2c\x03\x34\x48\xed\x2d\xe2\x88";

"""
    out.write(start)
    for name, data in otypes.items():
        if data["col"] or "index" in data:
            continue
        arc = resolve[name]
        out.write(f"const ARC_{name}: [u32; {len(arc)}] = {arc} ;\n")

    ot = r"""
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
/// a trait on the enum.
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

/// Simplistic example main
fn main() -> std::io::Result<()> {
    let mut oid_map = OidMap::<OT>::new();
    // There are some helper functions in engine_id.rs that you can use
    let eid = OctetString::from_static(ENGINESTR);
    let s42 = simple_from_int(42);
"""
    out.write(ot)
    for name, data in otypes.items():
        if data["col"] or "index" in data:
            continue
        arc = resolve[name]
        out.write( 
       f"    let oid_{name}: ObjectIdentifier = ObjectIdentifier::new(&ARC_{name}).unwrap();\n")
        if data["table"]:
            ename = data["entry"]
            entry = [(e[0], tcs.get(e[1], {"syntax": e[1]})["syntax"]) for e in ents[data["entry"]]]
            child_name = ename[0].lower() + ename[1:]
            if child_name in otypes:
                child = otypes[child_name]
                index_list = child["index"]
                LOGGER.info("entry %s", entry)
                LOGGER.info("index %s", index_list)
                implied = "IMPLIED" in index_list[-1]
                if implied:
                    index_list[-1] = index_list[-1].split()[-1]
                cols = [NAME_CHAR[_[1].split()[0]] for _ in entry]
                icols = [i for i, e in enumerate(entry) for _ in index_list if e[0] == _  ]
            out.write(f"""    let mut k_{name} = OT::Table(TableMemOid::new(
        vec![],
        2,
        &oid_{name},
        vec!{cols},
        vec!{icols},
        {"true" if implied else "false"}
    ));\n""")
        else:
            out.write(f"    let mut k_{name} = OT::Scalar(ScalarMemOid::new(s42.clone(), 'i'));\n")
        out.write(f"    oid_map.push((&oid_{name}, &mut k_{name}));\n")

    last = f"""
    let mut agent: Agent = Agent::build(eid, "{listen}");
    agent.loop_forever(&mut oid_map);
    Ok(())
{"}"}"""
    out.write(last)
