import logging
import re
from gen_rs import NAME_CHAR, ACCESS
LOGGER = logging.getLogger(__file__)

SNAKE_PATTERN = re.compile(r'(?<!^)(?=[A-Z])')


def usnake(text: str) -> str:
    return SNAKE_PATTERN.sub('_', text).upper()


def lsnake(text: str) -> str:
    return SNAKE_PATTERN.sub('_', text).lower()


def gen_stub(object_types, resolve, tcs, entries,
             mibname=None, listen="127.0.0.1:2161"):

    base_name = mibname.split("-MIB")[0].lower()
    base_name = "_".join(base_name.split("-"))
    stub_name = base_name + "_stub"
   
    LOGGER.info("Writing stub to %s", stub_name + ".rs")
   
    out = open("src/stubs/" + stub_name + ".rs", "w")
    
    stub_start = r"""use crate::keeper::oid_keep::{Access, OidKeeper, ScalarMemOid, TableMemOid};
use crate::oidmap::OidMap;
use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};


"""
    

    out.write(stub_start)
    for name, data in object_types.items():
        if data["col"] or "index" in data:
            continue
        arc = resolve[name]
        out.write(f"const ARC_{usnake(name)}: [u32; {len(arc)}] = {arc};\n")

    ot = r"""
fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

fn simple_from_str() -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_static(b"value")))
}

pub fn load_stub(oid_map: &mut OidMap) {
    let s42 = simple_from_int(42);
    let sval = simple_from_str();
"""
    out.write(ot)
    for name, data in object_types.items():
        if data["col"] or "index" in data:
            continue
        arc = resolve[name]
        out.write( 
       f"    let oid_{lsnake(name)}: ObjectIdentifier = ObjectIdentifier::new(&ARC_{usnake(name)}).unwrap();\n")
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
                acols = ", ".join([ACCESS[object_types[name]["access"]] for name, _ in entry])
                cols = [NAME_CHAR[_[1].split()[0]] for _ in entry]
                idat = ", ".join(["sval.clone()"if _ == 's' else 's42.clone()' for _ in cols])
                icols = [i + 1 for i, e in enumerate(entry) for _ in index_list if e[0] == _  ]
            out.write(f"""    let k_{lsnake(name)}: Box<dyn OidKeeper> = Box::new(TableMemOid::new(
        vec![vec![{idat}]],
        {len(cols)},
        &oid_{lsnake(name)},
        vec!{cols},
        vec![{acols}],
        vec!{icols},
        {"true" if implied else "false"},
    ));\n""")
        else:
            acc = ACCESS[data["access"]]
            out.write(f"    let k_{lsnake(name)}: Box<dyn OidKeeper> = Box::new(ScalarMemOid::new(s42.clone(), 'i', {acc}));\n")
        out.write(f"    oid_map.push(oid_{lsnake(name)}, k_{lsnake(name)});\n")
    out.write(r"}")
    out.close()

def loader(mibfiles):
    LOGGER.info("Writing loader to src/stubs.rs")
    with open("src/stubs.rs", "w") as src:
        src.write("use crate::oidmap::OidMap;\n\n")
        stubs = []
        for mibfile in mibfiles:
            base_name = mibfile.split("-MIB")[0].lower()
            base_name = "_".join(base_name.split("-"))
            stub_name = base_name + "_stub"
            stubs.append(stub_name)
        for stub in stubs:
            src.write(f"mod {stub};\n")
        src.write("\n\npub fn load_stubs(oid_map: &mut OidMap) {\n")
        for stub in stubs:
            src.write(f"    {stub}::load_stub(oid_map);\n")
        src.write("}\n")