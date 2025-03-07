"""Code generation"""
import logging
import re
LOGGER = logging.getLogger(__file__)

SNAKE_PATTERN = re.compile(r'(?<!^)(?=[A-Z])')

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


def usnake(text: str) -> str:
    """Convert text to UPPER_CASE_SNAKE name"""
    return SNAKE_PATTERN.sub('_', text).upper()


def lsnake(text: str) -> str:
    """Convert text to lower_case_snake name"""
    return SNAKE_PATTERN.sub('_', text).lower()


def write_arcs(out, object_types: dict, object_ids: dict, resolve: dict):
    """Write out the constants for Oids"""
    for name, data in object_types.items():
        if data["col"] or "index" in data:
            continue
        arc = resolve[name]
        out.write(f"const ARC_{usnake(name)}: [u32; {len(arc)}] = {arc};\n")

    if object_ids:
        out.write("\n// OID definitions for OBJECT-IDENTITY\n\n")
        for name, data in object_ids.items():
            arc = resolve[name]
            out.write(f"const ARC_{usnake(name)}: [u32; {len(arc)}] = {arc};\n")


def write_object_ids(out, object_ids: dict):
    """Write OBJECT-IDENTITY constants"""
    if object_ids:
        out.write("\n   // The next group is for OBJECT-IDENTITY\n\n")
        for name in object_ids:
            uname = usnake(name)
            out.write(f"    let oid_{lsnake(name)}: ObjectIdentifier =\n")
            out.write(f"        ObjectIdentifier::new(&ARC_{uname}).unwrap();\n")
        out.write("\n")


def write_table_struct(out, name, object_types, child, entry):
    """Write struct for single table"""
    index_list = child["index"]
    struct_name = f"Keep{name.title()}"
    entry = [(a, " ( ".join(b.split("("))) for (a, b) in entry]
    LOGGER.debug("entry %s", entry)
    LOGGER.debug("index %s", index_list)
    implied = "IMPLIED" in index_list[-1]
    if implied:
        index_list[-1] = index_list[-1].split()[-1]
    acols = ", ".join([ACCESS[object_types[name]["access"]]
                       for name, _ in entry])
    cols = [NAME_CHAR[_[1].split()[0]] for _ in entry]
    idat = ", ".join(["simple_from_str()"if _ == 's'
                      else 'simple_from_int(42)' for _ in cols])
    icols = [i + 1 for i, e in enumerate(entry)
             for _ in index_list if e[0] == _]

    if "description" in child:
        out.write(child["description"])
    out.write(f"""
struct {struct_name} {"{"}
    table: TableMemOid,
  {"}"}

impl {struct_name} {"{"}
    fn new() -> Self {"{"}
       let base_oid: ObjectIdentifier =
           ObjectIdentifier::new(&ARC_{usnake(name)}).unwrap();

       {struct_name} {"{"}
           table: TableMemOid::new(
             vec![vec![{idat}]],
        {len(cols)},
        &base_oid,
        vec!{cols},
        vec![{acols}],
        vec!{icols},
        {"true" if implied else "false"},
        )
       {"}"}
    {"}"}
{"}"}

impl OidKeeper for {struct_name} {"{"}
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {"{"}false{"}"}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {"{"}
      self.table.get(oid) {"}"}
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {"{"}
      self.table.get_next(oid) {"}"}
    fn access(&self, oid: ObjectIdentifier) -> Access {"{"}
      self.table.access(oid) {"}"}
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {"{"}
        self.table.set(oid, value) {"}"}
{"}"}
""")


def write_scalar_struct(out, name, data):
    """Write struct for scalar"""
    acc = ACCESS[data["access"]]
    struct_name = f"Keep{name.title()}"
    if "description" in data:
        out.write(data["description"])
    out.write(f"""
struct {struct_name} {"{"}
    scalar: ScalarMemOid,
  {"}"}

impl {struct_name} {"{"}
    fn new() -> Self {"{"}
       {struct_name} {"{"}
           scalar: ScalarMemOid::new(simple_from_int(42), 'i', {acc}),
       {"}"}
    {"}"}
{"}"}

impl OidKeeper for {struct_name} {"{"}
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {"{"}true{"}"}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {"{"}
      self.scalar.get(oid) {"}"}
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {"{"}
      self.scalar.get_next(oid) {"}"}
    fn access(&self, oid: ObjectIdentifier) -> Access {"{"}
      self.scalar.access(oid) {"}"}
    fn set(
            &mut self,
            oid: ObjectIdentifier,
            value: VarBindValue,
        ) -> Result<VarBindValue, OidErr> {"{"}
        self.scalar.set(oid, value) {"}"}
{"}"}
""")


def write_ot_structs(out, object_types, tcs, entries):
    """Heavy lifting"""
    out.write("\n   // Now the OBJECT-TYPES. These need actual code\n\n")
    for name, data in object_types.items():
        if data["col"] or "index" in data:
            continue
        if data["table"]:
            ename = data["entry"]
            entry = [(e[0], tcs.get(e[1], {"syntax": e[1]})["syntax"])
                     for e in entries[data["entry"]]]
            child_name = ename[0].lower() + ename[1:]
            if child_name in object_types:
                child = object_types[child_name]
                write_table_struct(out, name, object_types, child, entry)
            else:
                LOGGER.error("Table definition not found %s", ename)
        else:
            write_scalar_struct(out, name, data)


def write_object_types(out, object_types):
    """Invoke the types defined earlier"""

    for name, data in object_types.items():
        if data["col"] or "index" in data:
            continue
        out.write(f"    let oid_{lsnake(name)}: ObjectIdentifier =\n")
        out.write(f"        ObjectIdentifier::new(&ARC_{usnake(name)}).unwrap();\n")
        out.write(f"    let k_{lsnake(name)}: Box<dyn OidKeeper> = \n")
        out.write(f"       Box::new(Keep{name.title()}::new());\n")
        out.write(f"    oid_map.push(oid_{lsnake(name)}, k_{lsnake(name)});\n")


def gen_stub(object_types, resolve, tcs, entries, object_ids,
             mibname=None):
    """Actual code generation"""
    base_name = mibname.split("-MIB")[0].lower()
    base_name = "_".join(base_name.split("-"))
    stub_name = base_name + "_stub"

    LOGGER.info("Writing stub to %s", stub_name + ".rs")

    with open("src/stubs/" + stub_name + ".rs", "w", encoding="ascii") as out:

        stub_start = r"""
use crate::keeper::oid_keep::{Access, OidErr, OidKeeper, ScalarMemOid, TableMemOid};
use crate::oidmap::OidMap;
use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
use rasn_snmp::v3::{VarBind, VarBindValue};

fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

fn simple_from_str() -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_static(b"value")))
}
"""
        out.write(stub_start)
        write_arcs(out, object_types, object_ids, resolve)
        write_ot_structs(out, object_types, tcs, entries)
        ot = r"""

pub fn load_stub(oid_map: &mut OidMap) {
    let s42 = simple_from_int(42);
    let sval = simple_from_str();
"""
        out.write(ot)
        write_object_ids(out, object_ids)
        write_object_types(out, object_types)
        out.write(r"}")


def loader(mibfiles):
    """Write master loader to src/stubs.rs"""
    LOGGER.info("Writing loader to src/stubs.rs %s", mibfiles)
    with open("src/stubs.rs", "w", encoding="ascii") as src:
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
