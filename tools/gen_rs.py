# Copyright Julian Satchell 2025
import logging
import sys

LOGGER = logging.getLogger(__file__)
NAME_CHAR = {"INTEGER": 'i',
             "TimeStamp": 't',
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

ACCESS = {
    "not-accessible": "Access::NoAccess",
    "accessible-for-notify":  "Access::NotificationOnly",
    "read-only":  "Access::ReadOnly",
    "read-write": "Access::ReadWrite",
    "read-create": "Access::ReadCreate"
}


def gen_rs(object_types, resolve, tcs, entries,
           out=sys.stdout, listen="127.0.0.1:2161"):

    start = r"""use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v1::InvalidVariant;
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use snmp_rust_agent::keeper::oid_keep::{Access, OidKeeper, ScalarMemOid, TableMemOid};
use snmp_rust_agent::oidmap::OidMap;
use snmp_rust_agent::snmp_agent::Agent;

static ENGINESTR: &[u8; 11] = b"\x80\x00\x4e\x2c\x03\x34\x48\xed\x2d\xe2\x88";

"""
    out.write(start)
    for name, data in object_types.items():
        if data["col"] or "index" in data:
            continue
        arc = resolve[name]
        out.write(f"const ARC_{name}: [u32; {len(arc)}] = {arc} ;\n")

    ot = r"""
fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

/// Simplistic example main
fn main() -> std::io::Result<()> {
    let mut oid_map = OidMap::new();
    // There are some helper functions in engine_id.rs that you can use
    let eid = OctetString::from_static(ENGINESTR);
    let s42 = simple_from_int(42);
"""
    out.write(ot)
    for name, data in object_types.items():
        if data["col"] or "index" in data:
            continue
        arc = resolve[name]
        out.write( 
       f"    let oid_{name}: ObjectIdentifier = ObjectIdentifier::new(&ARC_{name}).unwrap();\n")
        if data["table"]:
            ename = data["entry"]
            entry = [(e[0], tcs.get(e[1], {"syntax": e[1]})["syntax"])
                     for e in entries[data["entry"]]]
            child_name = ename[0].lower() + ename[1:]
            if child_name in object_types:
                child = object_types[child_name]
                index_list = child["index"]
                entry = [(a, " ( ".join(b.split("("))) for (a, b) in entry]
                LOGGER.debug("entry %s", entry)
                LOGGER.debug("index %s", index_list)
                implied = "IMPLIED" in index_list[-1]
                if implied:
                    index_list[-1] = index_list[-1].split()[-1]
                cols = [NAME_CHAR[_[1].split()[0]] for _ in entry]
                acols = [ACCESS[_[1].split()[0]] for _ in entry]
                icols = [i for i, e in enumerate(entry) for _ in index_list if e[0] == _  ]
            out.write(f"""    let mut k_{name}: Box<dyn OidKeeper> = Box::New(TableMemOid::new(
        vec![],
        2,
        &oid_{name},
        vec!{cols},
        vec!{acols},
        vec!{icols},
        {"true" if implied else "false"}
    ));\n""")
        else:
            acc = ACCESS[data["access"]]
            out.write(f"    let mut k_{name}: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', {acc}));\n")
        out.write(f"    oid_map.push(&oid_{name}, &mut k_{name});\n")

    last = f"""
    let mut agent: Agent = Agent::build(eid, "{listen}");
    agent.loop_forever(&mut oid_map);
    Ok(())
{"}"}"""
    out.write(last)
