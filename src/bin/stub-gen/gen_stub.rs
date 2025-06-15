use crate::parser::{Entry, ObjectIdentity, ObjectType, TextConvention};
use crate::resolver;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::fs;
use std::io::{Error, Write};

fn cnt_ticks(
    object_types: &HashMap<&str, ObjectType>,
    tcs: &HashMap<&str, TextConvention>,
    _entries: &HashMap<&str, Entry>,
) -> (bool, bool) {
    let mut cnts = false;
    let mut ticks = false;
    for ot in object_types.values() {
        if ot.col || ot.index.len() > 2 {
            continue;
        }
        let mut syntax = ot.syntax;
        if tcs.contains_key(syntax) {
            syntax = tcs[syntax].syntax;
        }
        // FIXME do table case
        //FIXME look up via
        if syntax.contains("TimeTicks") {
            ticks = true;
        }
        if syntax.contains("Counter") {
            cnts = true;
        }
        if ticks && cnts {
            break;
        }
    }
    (cnts, ticks)
}

fn usnake(name: &str) -> String {
    lsnake(name).to_uppercase()
}

fn lsnake(text: &str) -> String {
    let mut buffer = String::with_capacity(text.len() + text.len() / 2);
    let mut text = text.chars();
    if let Some(first) = text.next() {
        let mut n2: Option<(bool, char)> = None;
        let mut n1: (bool, char) = (first.is_lowercase(), first);

        for c in text {
            let prev_n1 = n1;

            let n3 = n2;

            n2 = Some(n1);
            n1 = (c.is_lowercase(), c);

            // insert underscore if acronym at beginning
            // ABc -> a_bc

            if let Some((false, c3)) = n3 {
                if let Some((false, c2)) = n2 {
                    if n1.0 && c3.is_uppercase() && c2.is_uppercase() {
                        buffer.push('_');
                    }
                }
            }

            buffer.push_str(&prev_n1.1.to_lowercase().to_string());

            // insert underscore before next word
            // abC -> ab_c

            if let Some((true, _)) = n2 {
                if n1.1.is_uppercase() {
                    buffer.push('_');
                }
            }
        }
        buffer.push_str(&n1.1.to_lowercase().to_string());
    }
    buffer
}

fn title(name: &str) -> String {
    let mut c = name.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

fn untitle(name: &str) -> String {
    let mut c = name.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
    }
}

/// Put // at start of every line
fn slashb(descr: &str) -> String {
    let lines = descr.lines();
    let ret: String = lines.map(|l| "// ".to_owned() + l.trim() + "\n").collect();
    ret
}

static NAME_OTYPES: [(&str, &str); 27] = [
    ("INTEGER", "OType::Integer"),
    ("TruthValue", "OType::Integer"),
    ("TimeStamp", "OType::Ticks"),
    ("DateAndTime", "OType::String"),
    ("TimeTicks", "OType::Ticks"),
    ("TimeInterval", "OType::Integer"),
    ("TestAndIncr", "OType::Integer"),
    ("UUIDorZero", "OType::String"),
    ("Counter64", "OType::BigCounter"),
    ("Counter", "OType::Counter"),
    ("AutonomousType", "OType::ObjectId"),
    ("IANAStorageMediaType", "OType::Integer"),
    ("SnmpAdminString", "OType::String"),
    ("DisplayString", "OType::String"),
    ("OwnerString", "OType::String"),
    ("EntryStatus", "OType::Integer"),
    ("InterfaceIndexOrZero", "OType::Integer"),
    ("PhysAddress", "OType::Address"),
    ("Integer32", "OType::Integer"),
    ("Unsigned32", "OType::Integer"),
    ("Gauge32", "OType::Counter"),
    ("OCTET", "OType::String"),
    ("BITS", "OType::String"),
    ("Opaque", "OType::String"),
    ("OBJECT", "OType::ObjectId"),
    ("Counter32", "OType::Counter"),
    ("IpAddress", "OType::Address"),
];

fn name_otype(text: &str) -> &str {
    let mut parts = text.split(" ");
    let val = parts.next().unwrap();
    for (key, value) in NAME_OTYPES.iter() {
        if val == *key {
            return value;
        }
    }
    "OType::ObjectId"
}

static ACCESS: [(&str, &str); 5] = [
    ("not-accessible", "Access::NoAccess"),
    ("accessible-for-notify", "Access::NotificationOnly"),
    ("read-only", "Access::ReadOnly"),
    ("read-write", "Access::ReadWrite"),
    ("read-create", "Access::ReadCreate"),
];

fn access_lookup(text: &str) -> &str {
    for (key, value) in ACCESS.iter() {
        if text == *key {
            return value;
        }
    }
    ACCESS[0].1
}

fn write_arcs(
    out: &mut fs::File,
    object_types: &HashMap<&str, ObjectType>,
    object_ids: &[ObjectIdentity],
    resolve: resolver::Resolver,
) -> Result<(), Error> {
    //Write out the constants for Oids"""
    for (name, data) in object_types.iter() {
        if data.col || !data.index.is_empty() {
            continue;
        }
        let arc = resolve.lookup(name);
        let uname = usnake(name);
        let larc = arc.len();
        out.write_all(format!("const ARC_{uname}: [u32; {larc}] = {arc:?};\n").as_bytes())?;
    }
    if !object_ids.is_empty() {
        out.write_all(b"\n// OID definitions for OBJECT-IDENTITY\n\n")?;
        for data in object_ids {
            let uname = usnake(data.name);
            let arc = resolve.lookup(data.name);
            let larc = arc.len();
            out.write_all(format!("const ARC_{uname}: [u32; {larc}] = {arc:?};\n").as_bytes())?;
        }
    }
    Ok(())
}

fn write_object_ids(out: &mut fs::File, object_ids: &[ObjectIdentity]) -> Result<(), Error> {
    //Write OBJECT-IDENTITY constants"""
    if !object_ids.is_empty() {
        out.write_all(b"\n// The next group is for OBJECT-IDENTITY.\n")?;
        out.write_all(b"\n// These may be used as values rather than MIB addresses\n\n")?;
        for oid in object_ids {
            let uname = usnake(oid.name);
            let uname_tr = uname.trim();
            let lname = lsnake(oid.name);
            out.write_all(format!("    let _oid_{lname}: ObjectIdentifier =\n").as_bytes())?;
            out.write_all(
                format!("        ObjectIdentifier::new(&ARC_{uname_tr}).unwrap();\n").as_bytes(),
            )?;
            out.write_all(b"\n")?;
        }
    }
    Ok(())
}

fn value_from_syntax(syntax: &str) -> String {
    //Use syntax char to choose an appropriate initial value"""
    match syntax {
        "OType::String" => "simple_from_str(b\"b\")",
        "OType::ObjectId" => "simple_from_vec(&[1, 3, 6, 1])",
        "OType::Counter" => "counter_from_int(0)",
        "OType::Ticks" => "ticks_from_int(0)",
        _ => "simple_from_int(4)",
    }
    .to_string()
}

fn fix_def(arg: &str, syntax: &str, tcs: &HashMap<&str, TextConvention>) -> String {
    //Generate default value"""
    if arg.trim().ends_with("'H") {
        let tend = arg.len() - 3;
        let txt = &arg[1..tend];
        return format!("simple_from_str(b\"{txt}\")").to_string();
    }
    if tcs.contains_key(syntax) {
        let tc = tcs[syntax].clone();
        debug!("arg {} syntax {} tc {:?}", arg, syntax, tc);
        let tcsyn = tc.syntax.trim();
        if tcsyn.starts_with("INTEGER") || tcsyn.starts_with("Integer32") {
            if tcsyn.contains("{") {
                let mut tc_bits = tcsyn.split("{");
                tc_bits.next();
                let body = tc_bits.next().unwrap().split("}").next().unwrap();
                let parts = body.split(",");
                for part in parts {
                    let mut part_itr = part.split("(");
                    let name = part_itr.next().unwrap().trim();
                    if arg.trim() == name {
                        let valb = part_itr.next().unwrap();
                        let val = valb.split(")").next().unwrap();
                        return format!("simple_from_int({val})").to_string();
                    }
                }
                warn!("Not found name match for TC syntax, {arg}");
            } else {
                return format!("simple_from_int({arg})").to_string();
            }
        }
        if tc.syntax.starts_with("Unsigned") {
            return format!("simple_from_int({arg})").to_string();
            /*let mut tc_bits = tc.syntax.split("{");
            tc_bits.next();
            let body = tc_bits.next().unwrap().split("}").next().unwrap();
            let parts = body.split(",");
            for part in parts {
                let mut part_itr = part.split("(");
                let name = part_itr.next().unwrap();
                if arg == name.trim() {
                    let valb = part_itr.next().unwrap();
                    let val = valb.split(")").next().unwrap();
                    return format!("simple_from_int(0)").to_string();
                }
            }*/
        }
        if tc.syntax == "OBJECT IDENTIFIER" {
            let uarg = usnake(arg);
            let uarg_tr = uarg.trim();
            return format!("simple_from_vec(&ARC_{uarg_tr})");
        }
        if tc.syntax.starts_with("OCTET STRING") {
            let tend = arg.len() - 3;
            let txt = &arg[1..tend];
            return format!("simple_from_str(b\"{txt}\")");
        }
        panic!("Unsupported TC type for DEFVAL {tc:?}");
    }
    if syntax.starts_with("INTEGER") && syntax.contains("{") {
        let mut syn_itr = syntax.split("{");
        syn_itr.next();
        let body = syn_itr.next().unwrap().split("}").next().unwrap();
        let parts = body.split(",");
        for part in parts {
            let mut splits = part.split("(");
            let name = splits.next().unwrap();
            let val = splits.next().unwrap();
            if arg == name.trim() {
                let val = val.split(")").next().unwrap();
                return format!("simple_from_int({val})");
            }
        }
    }
    if syntax.starts_with("Integer32")
        || syntax.starts_with("Unsigned32")
        || syntax.starts_with("INTEGER")
    {
        return format!("simple_from_int({arg})");
    }
    if syntax == "OBJECT IDENTIFIER" {
        let uarg_t = usnake(arg);
        let uarg = uarg_t.trim();
        return "simple_from_vec(&ARC_".to_owned() + uarg + ")";
    }
    warn!("Return DEFVAL {arg} {syntax} literal");
    arg.to_string()
}

fn write_table_struct(
    out: &mut fs::File,
    name: &str,
    object_types: &HashMap<&str, ObjectType>,
    child: ObjectType,
    entry: Vec<(&str, &str)>,
    tcs: &HashMap<&str, TextConvention>,
) -> Result<(), Error> {
    //Write struct for single table"""
    let index_list = child.index;
    if child.augments.len() > 2 {
        info!("Augments, processing {}", child.augments)
    }
    let ntitle = title(name);
    let struct_name = format!("Keep{ntitle}");
    // entry = [(a, " ( ".join(b.split("("))) for (a, b) in entry];
    debug!("entry {:?}", entry);
    debug!("index {:?}", index_list);
    let implied = index_list.contains("IMPLIED");
    if implied {
        // index_list[-1] = index_list[-1].split()[-1];
    }
    let acols_vec: Vec<&str> = entry
        .iter()
        .map(|(name, _)| access_lookup(object_types[name].access))
        .collect();
    let acols = acols_vec.join(", ");
    //", ".join([ACCESS[object_types[name].access]  for (name, _) in entry.syntax]);
    let cols: Vec<&str> = entry.iter().map(|(_, x)| name_otype(x)).collect();
    let cols_txt = cols.join(", ");
    //cols = [NAME_OTYPE[_[1].split()[0]] for _ in entry]
    let mut icol_data = vec![];
    for ent in &entry {
        if object_types[ent.0].defval.len() > 2 {
            icol_data.push(fix_def(
                object_types[ent.0].defval,
                object_types[ent.0].syntax,
                tcs,
            ))
        } else {
            icol_data.push(value_from_syntax(name_otype(ent.1)));
        }
    }
    let idat = icol_data.join(", ");
    let icols: Vec<usize> = entry
        .iter()
        .enumerate()
        .filter(|(_i, (name, _))| index_list.contains(name))
        .map(|(i, _)| i + 1)
        .collect();
    //[i + 1 for i, e in enumerate(entry)
    //       for _ in index_list if e[0] == _]
    let lcols = cols.len();
    let uname = usnake(name);
    let uname_tr = uname.trim();
    if child.descr.len() > 2 {
        out.write_all(slashb(child.descr).as_bytes())?;
    }
    out.write_all(
        format!(
            "
struct {struct_name} {{
table: TableMemOid,
}}

impl {struct_name} {{
fn new() -> Self {{
   let base_oid: ObjectIdentifier =
       ObjectIdentifier::new(&ARC_{uname_tr}).unwrap();

   {struct_name} {{
       table: TableMemOid::new(
         vec![vec![{idat}]],
    vec![{idat}],
    {lcols},
    &base_oid,
    vec![{cols_txt}],
    vec![{acols}],
    vec!{icols:?},
    {implied},
    )
   }}
}}
}}

impl OidKeeper for {struct_name} {{
fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {{false}}
fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {{
  self.table.get(oid) }}
fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {{
  self.table.get_next(oid) }}
fn access(&self, oid: ObjectIdentifier) -> Access {{
  self.table.access(oid) }}
fn set(
        &mut self,
        oid: ObjectIdentifier,
        value: VarBindValue,
    ) -> Result<VarBindValue, OidErr> {{
    self.table.set(oid, value) }}
}}
"
        )
        .as_bytes(),
    )?;
    Ok(())
}

fn write_scalar_struct(
    out: &mut fs::File,
    name: &str,
    data: &ObjectType,
    tcs: &HashMap<&str, TextConvention>,
) -> Result<(), Error> {
    //Write struct for scalar"""
    let acc = access_lookup(data.access);
    let mut syntax = data.syntax;
    if tcs.contains_key(syntax) {
        syntax = tcs[syntax].syntax;
    }
    let otype = name_otype(syntax);
    let val = value_from_syntax(otype);
    let tname = title(name);
    let struct_name = format!("Keep{tname}");
    if data.descr.len() > 2 {
        out.write_all(slashb(data.descr).as_bytes())?;
    }
    out.write_all(
        format!(
            "
struct {struct_name} {{
scalar: ScalarMemOid,
}}

impl {struct_name} {{
fn new() -> Self {{
   {struct_name} {{
       scalar: ScalarMemOid::new({val}, {otype}, {acc}),
}}
}}
}}

impl OidKeeper for {struct_name} {{
    fn is_scalar(&self, _oid: ObjectIdentifier) -> bool {{
        true
    }}
    fn get(&self, oid: ObjectIdentifier) -> Result<VarBindValue, OidErr> {{
        self.scalar.get(oid)
    }}
    fn get_next(&self, oid: ObjectIdentifier) -> Result<VarBind, OidErr> {{
        self.scalar.get_next(oid)
    }}
    fn access(&self, oid: ObjectIdentifier) -> Access {{
        self.scalar.access(oid)
    }}
    fn set(&mut self, oid: ObjectIdentifier, value: VarBindValue) -> Result<VarBindValue, OidErr> {{
        self.scalar.set(oid, value)
    }}
}}
"
        )
        .as_bytes(),
    )?;
    Ok(())
}

fn write_ot_structs(
    out: &mut fs::File,
    object_types: &HashMap<&str, ObjectType>,
    tcs: &HashMap<&str, TextConvention>,
    entries: &HashMap<&str, Entry>,
) -> Result<(), Error> {
    // Heavy lifting
    out.write_all(b"\n// Now the OBJECT-TYPES.")?;
    out.write_all(b" These need actual code added to the stubs\n\n")?;
    for (name, data) in object_types.iter() {
        if data.col || !data.index.is_empty() {
            continue;
        }
        if data.table {
            let en_itr = data.syntax.split(" ");
            let ename = en_itr.last().unwrap();
            debug!("ename is |{ename}|");
            let entry = entries[ename].syntax.clone();
            let child_name = untitle(ename);
            if object_types.contains_key(&child_name[..]) {
                let child = object_types[&child_name[..]].clone();
                if child.augments.len() > 2 {
                    warn!("Buggy AUGMENTS behavior, needs fixing");
                    panic!("Don't support AUGMENTS yet")
                    //# FIXME - this is wrong - we should
                    //# somehow tie just the added columns back to a row in
                    //# the master table
                    /*   let master_name = child.augments;
                    let master = object_types[master_name];
                    let ent_title = title(master_name);
                    let master_raw = entries[&ent_title[..]];
                    let master_e = master_raw.syntax;
                    master_e.extend(entry);
                    let new_child = master.copy();
                    new_child.update(child);
                    write_table_struct(out, name, object_types, new_child, master_e, tcs); */
                } else {
                    write_table_struct(out, name, object_types, child, entry, tcs)?;
                }
            } else {
                error!("Table definition not found {}", ename);
            }
        } else {
            write_scalar_struct(out, name, data, tcs)?;
        }
    }
    Ok(())
}

fn write_object_types(
    out: &mut fs::File,
    object_types: &HashMap<&str, ObjectType>,
) -> Result<(), Error> {
    //Invoke the types defined earlier"""

    for (name, data) in object_types.iter() {
        if data.col || !data.index.is_empty() {
            continue;
        }
        let uname = usnake(name);
        let uname_tr = uname.trim();
        let lname = lsnake(name);
        let tname = title(name);
        out.write_all(format!("    let oid_{lname}: ObjectIdentifier =\n").as_bytes())?;
        out.write_all(
            format!("        ObjectIdentifier::new(&ARC_{uname_tr}).unwrap();\n").as_bytes(),
        )?;
        out.write_all(format!("    let k_{lname}: Box<dyn OidKeeper> = \n").as_bytes())?;
        out.write_all(format!("       Box::new(Keep{tname}::new());\n").as_bytes())?;
        out.write_all(format!("    oid_map.push(oid_{lname}, k_{lname});\n").as_bytes())?;
    }
    Ok(())
}

pub fn gen_stub(
    object_types: &HashMap<&str, ObjectType>,
    resolve: resolver::Resolver,
    tcs: &HashMap<&str, TextConvention>,
    entries: &HashMap<&str, Entry>,
    object_ids: &[ObjectIdentity],
    mibname: &str,
    out_dir: &str,
) -> Result<(), Error> {
    //"""Actual code generation"""
    info!("MIB name is {mibname}");
    let mut base_name = mibname.split("-MIB").next().unwrap().to_lowercase();

    base_name = base_name.replace("-", "_");
    let stub_name = out_dir.to_owned() + &base_name + "_stub.rs";
    info!("Generated output would be in {stub_name}");
    let stub_ref = &stub_name;
    if fs::exists(stub_ref).is_ok() {
        info!("Overwriting stub {stub_ref}");
        //return Ok(());
    } else {
        info!("Writing new stub to {stub_ref}");
    }
    let mut out = fs::File::create(stub_name)?;
    let (cnts, tcks) = cnt_ticks(object_types, tcs, entries);
    //let cnts = true;
    //let tcks = true;
    let stub_start = r"
use crate::keeper::oid_keep::{Access, OidErr, OidKeeper, OType};
use crate::scalar::ScalarMemOid;
use crate::table::TableMemOid;
use crate::oidmap::OidMap;
use rasn::types::{Integer, ObjectIdentifier, OctetString};
";

    let stub_1;

    if cnts {
        if tcks {
            stub_1 = r"
use rasn_smi::v2::{ObjectSyntax, SimpleSyntax, ApplicationSyntax,
          Counter32, TimeTicks};
";
        } else {
            stub_1 = r"
use rasn_smi::v2::{ApplicationSyntax, Counter32, ObjectSyntax, SimpleSyntax};
";
        }
    } else if tcks {
        stub_1 = r"
    use rasn_smi::v2::{ObjectSyntax, SimpleSyntax, ApplicationSyntax,
              TimeTicks};
    ";
    } else {
        stub_1 = r"
    use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
    ";
    }
    let stub_2 = r"
use rasn_snmp::v3::{VarBind, VarBindValue};

fn simple_from_int(value: i32) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::Integer(Integer::from(value)))
}

fn simple_from_str(value: &'static [u8]) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::String(OctetString::from_static(value)))
}

fn simple_from_vec(value: &'static [u32]) -> ObjectSyntax {
    ObjectSyntax::Simple(SimpleSyntax::ObjectId(
        ObjectIdentifier::new(value).unwrap(),
    ))
}

";
    out.write_all(stub_start.as_bytes())?;
    out.write_all(stub_1.as_bytes())?;
    out.write_all(stub_2.as_bytes())?;
    if cnts {
        let cnts_stub = r"

fn counter_from_int(value:u32) -> ObjectSyntax {
  ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(Counter32{0:value}))
}
";
        out.write_all(cnts_stub.as_bytes())?;
    }
    if tcks {
        let tcks_stub = r"

fn ticks_from_int(value:u32) -> ObjectSyntax {
  ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(TimeTicks { 0: value }))
}
";
        out.write_all(tcks_stub.as_bytes())?;
    }
    write_arcs(&mut out, object_types, object_ids, resolve)?;
    write_ot_structs(&mut out, object_types, tcs, entries)?;
    let ot = r"

pub fn load_stub(oid_map: &mut OidMap) {
";
    out.write_all(ot.as_bytes())?;
    write_object_ids(&mut out, object_ids)?;
    write_object_types(&mut out, object_types)?;
    out.write_all(r"}".as_bytes())?;
    out.flush()?;
    Ok(())
}

pub fn loader(mibfiles: Vec<String>) -> Result<(), Error> {
    //"""Write master loader to src/stubs.rs"""
    info!("Writing loader to src/stubs.rs {0:?}", mibfiles);
    let mut src = fs::File::create("src/stubs.rs")?;
    src.write_all(b"use crate::oidmap::OidMap;\n\n")?;
    let mut stubs = vec![];
    for mibname in mibfiles {
        let mut base_name = mibname.split("-MIB").next().unwrap().to_lowercase();

        base_name = base_name.replace("-", "_");
        let stub_name = base_name + "_stub";
        stubs.push(stub_name);
    }
    for stub in &stubs {
        src.write_all(format!("mod {stub};\n").as_bytes())?;
    }
    src.write_all(b"\n\npub fn load_stubs(oid_map: &mut OidMap) {\n")?;
    for stub in &stubs {
        src.write_all(format!("    {stub}::load_stub(oid_map);\n").as_bytes())?;
    }
    src.write_all(b"}\n")?;
    Ok(())
}
