"""Code generation"""
import logging
import re
import os
import sys

LOGGER = logging.getLogger(__file__)

SNAKE_PATTERN = re.compile(r'(?<!^)(?=[A-Z])')

NAME_CHAR = {"INTEGER": 'i',
             "TruthValue": 'i',
             "TimeStamp": 't',
             "DateAndTime": 's',
             "TimeTicks": 't',
             "TimeInterval": 'i',
             "TestAndIncr": 'i',
             "UUIDorZero": 's',
             "Counter64": 'b',
             "Counter": 'c',
             "AutonomousType": "o",
             "IANAStorageMediaType": "i",
             "SnmpAdminString": 's',
             "DisplayString": 's',
             "OwnerString": 's',
             "EntryStatus": 'i',
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
        out.write("\n// The next group is for OBJECT-IDENTITY.\n")
        out.write("\n// These may be used as values rather than MIB addresses\n\n")
        for name in object_ids:
            uname = usnake(name)
            out.write(f"    let _oid_{lsnake(name)}: ObjectIdentifier =\n")
            out.write(f"        ObjectIdentifier::new(&ARC_{uname}).unwrap();\n")
        out.write("\n")


def value_from_syntax(syntax):
    """Use syntax char to choose an appropriate initial value"""
    if syntax == 's':
        val = 'simple_from_str(b"b")'
    elif syntax == 'o':
        val = "simple_from_vec(&[1, 3, 6, 1])"
    elif syntax == 'c':
        val = "counter_from_int(0)"
    elif syntax == 't':
        val = "ticks_from_int(0)"
    else:
        val = "simple_from_int(4)"
    return val


def fix_def(arg: str, syntax, tcs) -> str:
    """Generate default value"""
    if arg[-2:] == "'H":
        txt = arg[1:-2]
        return f'simple_from_str(b"{txt}")'
    if syntax in tcs:
        tc = tcs[syntax]
        LOGGER.info("syntax %s tc %s", syntax, tc)
        parts = tc["syntax"].split()
        if parts[0] == "INTEGER":
            body = tc["syntax"].split("{")[1].split("}")[0]
            parts = body.split(",")
            for part in parts:
                name, val = part.split("(")
                if arg == name.strip():
                    val = val.split(")")[0]
                    return f"simple_from_int({val})"
        if tc["syntax"] == "OBJECT IDENTIFIER":
            return f"simple_from_vec(&ARC_{usnake(arg)})"
        LOGGER.error("Unsupported TC type for DEFVAL %s", tc)
        sys.exit(2)
    if syntax.split()[0] == "INTEGER" and "{" in syntax:
        body = syntax.split("{")[1].split("}")[0]
        parts = body.split(",")
        for part in parts:
            name, val = part.split("(")
            if arg == name.strip():
                val = val.split(")")[0]
                return f"simple_from_int({val})"
    LOGGER.warning("Return DEFVAL as literal")
    return arg


def write_table_struct(out, name, object_types, child, entry, tcs):
    """Write struct for single table"""
    index_list = child["index"]
    if "augments" in child:
        LOGGER.info("Augments, processing %s", child["augments"])
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
    icol_data = []
    for ent in entry:
        if "defval" in object_types[ent[0]]:
            icol_data.append(fix_def(object_types[ent[0]]["defval"],
                                     object_types[ent[0]]["syntax"],
                                     tcs))
        else:
            icol_data.append(value_from_syntax(NAME_CHAR[ent[1].split()[0]]))
    idat = ", ".join(icol_data)
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


def write_scalar_struct(out, name, data, tcs):
    """Write struct for scalar"""
    acc = ACCESS[data["access"]]
    syntax = data["syntax"]
    if syntax in tcs:
        syntax = tcs[syntax]["syntax"]
    syntax_char = NAME_CHAR[syntax.split()[0]]
    val = value_from_syntax(syntax_char)
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
           scalar: ScalarMemOid::new({val}, '{syntax_char}', {acc}),
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
    out.write("\n// Now the OBJECT-TYPES.")
    out.write(" These need actual code added to the stubs\n\n")
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
                if "augments" in child:
                    LOGGER.warning("Buggy AUGMENTS behaviour, needs fixing")
                    # FIXME - this is wrong - we should
                    # somehow tie just the added columns back to a row in
                    # the master table
                    master_name = child["augments"].strip()[1:-1].strip()
                    master = object_types[master_name]
                    master_raw = entries[master_name[0].upper() + master_name[1:]]
                    master_e = [(e[0], tcs.get(e[1], {"syntax": e[1]})["syntax"])
                                for e in master_raw]
                    master_e += entry
                    new_child = master.copy()
                    new_child.update(child)
                    write_table_struct(out, name, object_types,
                                       new_child, master_e, tcs)
                else:
                    write_table_struct(out, name, object_types, child, entry, tcs)
            else:
                LOGGER.error("Table definition not found %s", ename)
        else:
            write_scalar_struct(out, name, data, tcs)


def write_object_types(out, object_types):
    """Invoke the types defined earlier"""

    for name, data in object_types.items():
        if data["col"] or "index" in data:
            continue
        uname = usnake(name)
        out.write(f"    let oid_{lsnake(name)}: ObjectIdentifier =\n")
        out.write(f"        ObjectIdentifier::new(&ARC_{uname}).unwrap();\n")
        out.write(f"    let k_{lsnake(name)}: Box<dyn OidKeeper> = \n")
        out.write(f"       Box::new(Keep{name.title()}::new());\n")
        out.write(f"    oid_map.push(oid_{lsnake(name)}, k_{lsnake(name)});\n")


def cnt_ticks(object_types, tcs, entries):
    """See if Counter or TimeTicks data types are in use"""
    cnts = False
    tcks = False
    for data in object_types.values():
        if data["col"] or "index" in data:
            continue
        if data["table"]:
            syntaxes = [tcs.get(e[1], {"syntax": e[1]})["syntax"]
                        for e in entries[data["entry"]]]

            syntaxes = [_.split("(")[0] for _ in syntaxes]
            print(syntaxes)
            chars = [NAME_CHAR[syntax.split()[0]] for syntax in syntaxes]
            if "t" in chars:
                tcks = True
            if "c" in chars:
                cnts = True
        else:
            syntax = data["syntax"]
            if syntax in tcs:
                syntax = tcs[syntax]["syntax"]
            syntax_char = NAME_CHAR[syntax.split()[0]]
            if syntax_char == 't':
                tcks = True
            if syntax_char == 'c':
                cnts = True
        if cnts and tcks:  # Early exit if both are true
            break
    return cnts, tcks


def gen_stub(object_types, resolve, tcs, entries, object_ids,
             mibname=None, force=False):
    """Actual code generation"""
    base_name = mibname.split("-MIB")[0].lower()
    base_name = "_".join(base_name.split("-"))
    stub_name = base_name + "_stub.rs"

    if os.access("src/stubs/" + stub_name, os.R_OK):
        if force:
            LOGGER.info("Overwriting stub %s", stub_name)
        else:
            LOGGER.info("Not overwriting stub %s", stub_name)
            return
    else:
        LOGGER.info("Writing new stub to %s", stub_name)
    with open("src/stubs/" + stub_name, "w", encoding="ascii") as out:
        cnts, tcks = cnt_ticks(object_types, tcs, entries)
        stub_start = r"""
use crate::keeper::oid_keep::{Access, OidErr, OidKeeper};
use crate::scalar::ScalarMemOid;
use crate::table::TableMemOid;use crate::oidmap::OidMap;
use rasn::types::{Integer, ObjectIdentifier, OctetString};
"""
        if cnts:
            if tcks:
                stub_1 = r"""
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax, ApplicationSyntax,
                   Counter32, TimeTicks};
"""
            else:
                stub_1 = r"""
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax, ApplicationSyntax,
                   Counter32};
"""
        else:
            if tcks:
                stub_1 = r"""
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax, ApplicationSyntax,
                   TimeTicks};
"""
            else:
                stub_1 = r"""
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
"""
        stub_2 = r"""use rasn_snmp::v3::{VarBind, VarBindValue};

fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

fn simple_from_str(value: &'static [u8]) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_static(value)))
}

fn simple_from_vec(value: &'static [u32]) -> ObjectSyntax {
  ObjectSyntax::Simple(SimpleSyntax::ObjectId(ObjectIdentifier::new(value).unwrap()))
}

"""
        out.write(stub_start)
        out.write(stub_1)
        out.write(stub_2)
        cnt_from_int = r"""
fn counter_from_int(value:u32) -> ObjectSyntax {
  ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(Counter32{0:value}))
}

"""
        tcks_frm_int = r"""
fn ticks_from_int(value:u32) -> ObjectSyntax {
  ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(TimeTicks{0:value}))
}

"""
        if cnts:
            out.write(cnt_from_int)
        if tcks:
            out.write(tcks_frm_int)
        write_arcs(out, object_types, object_ids, resolve)
        write_ot_structs(out, object_types, tcs, entries)
        ot = r"""

pub fn load_stub(oid_map: &mut OidMap) {
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
