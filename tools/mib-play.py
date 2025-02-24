"""Comedy MIB compiler

Usage:
  mib-play.py  [-d] [-p] <mibfile>
  mib-play.py -h

Options:
  -h --help     Show this screen.
  -d, --debug   Increase log spew.
  -p, --play    Generate self-contained "play" code using memory based
                classes, rather than stubs that must be completed

<mibfile> can be an absolute path, or if it is a short name the code will try
looking it up in a built-in search path.

Copyright Julian Satchell 2025
"""
import os
import logging
import docopt

# Selection to try in development
mib_files =  ["UDP-MIB",
"UDPLITE-MIB",
"UPS-MIB",
"WWW-MIB",
#"VDSL-LINE-EXT-MCM-MIB"
]

LOGGER = logging.getLogger(__file__)

MIB_PATH = [
    "/var/lib/mibs/ietf/",
    "/var/lib/mibs/iana/",
    "/usr/share/snmp/mibs/"
]

NAME_CHAR = {"INTEGER": 'i',
             "TimeStamp": 's',
             "TimeTicks": 't',
             "UUIDorZero": 's',
             "Counter64": 'b',
             "Counter": 'c',
             "AutonomousType": "o",
             "IANAStorageMediaType": "i",
             "SnmpAdminString": 's',
             "InterfaceIndexOrZero": 'i',
             "PhysAddress": 'a',
             "Integer32": 'i'}


def find_mib_file(name: str) -> str:
    """Return absolute file name of MIB file

    If name can't be found,return empty string.
    """
    if name.startswith("/"):
        return name
    for dirname in MIB_PATH:
        for fname in os.listdir(dirname):
            if name == fname or name + ".txt" == fname:
                return os.path.join(dirname, fname)
    LOGGER.error("Couldn't find MIB named %s", name)
    return ""


def dedent_description(raw: str) -> str:
    lines = ["// " + _.strip() for _ in raw.split("\n")]
    return "\n".join(lines)


def parse_table_entries(text: str) -> dict:
    ents = {}
    parts = text.split("SEQUENCE")
    for i, part in enumerate(parts[1:]):
        previous = parts[i]
        if "::=" not in previous:
            #print(previous[-20:], part[:20])
            continue
        x, y = previous.rsplit("::=", 1)
        #print(x[-20:], "Y", y)
        if y.isspace():
            ent_name = x.strip().rsplit()[-1]
            # print(ent_name)
            x, y = part.split("{", 1)
            if x.isspace():
                data = [_.strip().split() for _ in y.split("}", 1)[0].split(",")]
                ents[ent_name] = data
    return ents

def parse_text_conventions(text: str):
    tcs = {}
    parts = text.split("TEXTUAL-CONVENTION")
    for i, part in enumerate(parts[1:]):
        previous = parts[i]
        if "::=" not in previous:
            #print(previous[-20:], part[:20])
            continue
        x, y = previous.rsplit("::=", 1)
        if y.isspace():
            tc_name = x.strip().rsplit()[-1]
            data = {}
            if "DISPLAY-HINT" in part:
                data["hint"] = part.split("DISPLAY-HINT", 1)[1].split('"', 2)[1]
            if "SYNTAX" in part:
                data["syntax"] = part.split("SYNTAX", 1)[1].split("\n")[0].strip()
            tcs[tc_name] = data
    return tcs


def print_tables(otypes, resolve, tcs, ents):
    for name, data in otypes.items():

        if not data["table"]:
            continue
        print()
        if data["syntax"] in tcs:
            syntax = tcs[data["syntax"]]["syntax"]
        else:
            syntax = data["syntax"]
        print(name, syntax, data["access"])
        print(resolve[name])
        entry = [(e[0], tcs.get(e[1], {"syntax": e[1]})["syntax"]) for e in ents[data["entry"]]]
        print(entry)
        #if "description" in data:
        #    print(data["description"])
        if "index" in data:
            print(data["index"])
        else:
            ename = data["entry"]
            child_name = ename[0].lower() + ename[1:]
            if child_name in otypes:
                child = otypes[child_name]
                print("INDEX", child["index"])


def parse_oids(text: str, oids: dict):
    parts = text.split("OBJECT IDENTIFIER")
    for i, part in enumerate(parts[1:]):           
        if "::=" in part: 
            x, y = part.split("::=", 1)
            previous = parts[i]
            if x.isspace():
                frags = previous.split("\n")
                oname = frags[-2] if frags[-1].isspace() else frags[-1]
                val = y.split("}")[0].strip() + " }"
                oids[oname.strip()] = val


def gen_rs(otypes, resolve, tcs, ents, play: bool = True):
    
    start = r"""use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v1::InvalidVariant;
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use rasn_snmp::v3::{VarBind, VarBindValue};
use snmp_rust_agent::keeper::oid_keep::{OidErr, OidKeeper, ScalarMemOid, TableMemOid};
use snmp_rust_agent::snmp_agent::{Agent, OidMap};

static ENGINESTR: &[u8; 11] = b"\x80\x00\x4e\x2c\x03\x34\x48\xed\x2d\xe2\x88";

"""
    print(start)
    for name, data in otypes.items():
        if data["col"] or "index" in data:
            continue
        arc = resolve[name]
        print(f"const ARC_{name}: [u32; {len(arc)}] = {arc} ;")

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

/// Simplistic example main
fn main() -> std::io::Result<()> {
    let mut oid_map = OidMap::<OT>::new();
    // There are some helper functions in engine_id.rs that you can use
    let eid = OctetString::from_static(ENGINESTR);
    let s42 = simple_from_int(42);
"""
    print(ot)
    for name, data in otypes.items():
        if data["col"] or "index" in data:
            continue
        arc = resolve[name]
        print( 
       f"    let oid_{name}: ObjectIdentifier = ObjectIdentifier::new(&ARC_{name}).unwrap();")
        if data["table"]:
            ename = data["entry"]
            entry = [(e[0], tcs.get(e[1], {"syntax": e[1]})["syntax"]) for e in ents[data["entry"]]]
            child_name = ename[0].lower() + ename[1:]
            if child_name in otypes:
                child = otypes[child_name]
                index_list = child["index"]
                cols = [NAME_CHAR[_[1].split()[0]] for _ in entry]
                icols = [i for i, e in enumerate(entry) for _ in index_list if e[0] == _  ]
            print(f"""    let mut k_{name} = OT::Table(TableMemOid::new(
        vec![],
        2,
        &oid_{name},
        vec!{cols},
        vec!{icols}
    ));""")
        else:
            print(f"    let mut k_{name} = OT::Scalar(ScalarMemOid::new(s42.clone(), 'i'));")
        print(f"    oid_map.push((&oid_{name}, &mut k_{name}));")

    last = """
    let mut agent: Agent = Agent::build(eid, "127.0.0.1:2161");
    agent.loop_forever(&mut oid_map);
    Ok(())
}"""
    print(last)

def parse_mib(mib_file: str, depth=0):
    resolve = {"mib-2": [1, 3, 6, 1, 2, 1]}
    mib_file = find_mib_file(mib_file)
    with open(mib_file, "r") as stream:
        tree = {}
        oids = {} 
        otypes = {}
        text = stream.read()
        ents = parse_table_entries(text)
        tcs = parse_text_conventions(text)
        #lines = text.split("\n")
        mod_name, rest = text.split("DEFINITIONS", 1)
        _, rest = rest.split("IMPORTS", 1)
        #print(rest[:100])
        if "MODULE-IDENTITY\n" in rest:
            # Some of the core bootstrap files do not have this
            imp_id, rest = rest.split("MODULE-IDENTITY\n", 1)
            imps, mod_id = imp_id.rsplit("\n", 1)

            _, rest = rest.split("::=", 1)
            top_def, rest = rest.split("}", 1)
            top_def += "}"  
            oids[mod_id.strip()] = top_def

        if depth == 0:
           imparts = imps.split("FROM")
           for impart in imparts[1:]:
               imp_mib = impart.split()[0].strip()
               imp_path = find_mib_file(imp_mib)
               if imp_path:
                   with open(imp_path, "r") as nest:
                       itext = nest.read()
                       parse_oids(itext, oids)
                       tcs.update(parse_text_conventions(itext))
        # Just ignore compliance stuff for now 
        #if "MODULE-COMPLIANCE" in rest:
        #    rest, _ = rest.split("MODULE-COMPLIANCE", 1)
        # Find all the OBJECT IDENTIFIERs
        parse_oids(text, oids)

        parts = rest.split(" OBJECT-TYPE")
        for i, part in enumerate(parts[1:]):
            _, oname = parts[i].rsplit("\n", 1)
            data = {}
            if "INDEX" in part:
                itext = part.split("INDEX", 1)[1].split("}", 1)[0].strip() + "}"
                data["index"] = [_.strip() for _ in itext[1:-1].split(",")]
            if "DESCRIPTION" in part:
                data["description"] = dedent_description(part.split("DESCRIPTION")[1].split('"')[1])
            if "MAX-ACCESS" in part:
                data["access"] = part.split("MAX-ACCESS")[1].split("\n")[0].strip()
            data["def"] = part.split("::=")[1].split("}", 1)[0] + "}"
            parent = data["def"].split()[1]
            if parent in otypes and "index" in otypes[parent]:
                data["col"] = True
            else:
                data["col"] = False
            data["syntax"] = part.split(" SYNTAX ", 1)[1].split("\n")[0].strip()
            data["table"] = "SEQUENCE" in data["syntax"]
            if data["table"]:
                entry = data["syntax"].split("OF")[1].strip()
                data["entry"] = entry
            otypes[oname.strip()] = data
        # Make two passes resolving stuff
        for name, data in oids.items():
            content = data.split("{", 1)[1].split("}")[0].strip()
            parent, snum = content.split(" ", 1)
            num = int(snum.strip())
            if parent in resolve:
                pval = resolve[parent].copy() + [num]
                resolve[name] = pval
    
        for name, data_obj in otypes.items():
            data = data_obj["def"]
            content = data.split("{", 1)[1].split("}")[0].strip()
            parent, snum = content.split(" ", 1)
            num = int(snum.strip())
            if parent in resolve:
                pval = resolve[parent].copy() + [num]
                resolve[name] = pval
        # Now warning about missing definitions in these passes
        for name, data in oids.items():
            content = data.split("{", 1)[1].split("}")[0].strip()
            parent, snum = content.split(" ", 1)
            num = int(snum.strip())
            if parent in resolve:
                pval = resolve[parent].copy() + [num]
                resolve[name] = pval
            else:
                print("not found oid parent", parent)
        for name, data_obj in otypes.items():
            data = data_obj["def"]
            content = data.split("{", 1)[1].split("}")[0].strip()
            #print(content)
            parent, snum = content.split(" ", 1)
            num = int(snum.strip())
            if parent in resolve:
                pval = resolve[parent].copy() + [num]
                resolve[name] = pval
            else:
                print("Unable to find", parent)
        
        return otypes, resolve, tcs, ents


if __name__ == '__main__':
    arguments = docopt.docopt(__doc__, version='mib-play 0.0.1')
    llevel = logging.DEBUG if arguments["--debug"] else logging.INFO
    logging.basicConfig(level=llevel)

    otypes, resolve, tcs, ents = parse_mib(arguments["<mibfile>"])

    gen_rs(otypes, resolve, tcs, ents, arguments["--play"])