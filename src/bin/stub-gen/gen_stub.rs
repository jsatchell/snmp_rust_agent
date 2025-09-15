use crate::parser::{Entry, ModuleCompliance, ObjectIdentity, ObjectType, TextConvention};
use crate::resolver::{self, Resolver};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::fs;
use std::io::{Error, Write};

fn upper_snake(name: &str) -> String {
    lower_snake(name).to_uppercase()
}

fn lower_snake(text: &str) -> String {
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

/// Put // at start of every line
fn slash_b(description: &str) -> String {
    let lines = description.lines();
    let ret: String = lines.map(|l| "// ".to_owned() + l.trim() + "\n").collect();
    ret
}

static NAME_OTYPES: [(&str, &str); 34] = [
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
    ("MacAddress", "OType::String"),
    ("EntryStatus", "OType::Integer"),
    ("InterfaceIndexOrZero", "OType::Integer"),
    ("PhysAddress", "OType::String"),
    ("Integer32", "OType::Integer"),
    ("Unsigned32", "OType::Integer"),
    ("TimeInterval", "OType::Integer"),
    ("RowStatus", "OType::Integer"),
    ("Gauge32", "OType::Counter"),
    ("OCTET", "OType::String"),
    ("BITS", "OType::String"),
    ("Opaque", "OType::String"),
    ("OBJECT", "OType::ObjectId"),
    ("Counter32", "OType::Counter"),
    ("IpAddress", "OType::Address"),
    ("InetAddress", "OType::Address"),
    ("InetAddressType", "OType::Integer"),
    ("InetPortNumber", "OType::Integer"),
    ("InterfaceIndexOrZero", "OType::Integer"),
];

fn name_otype(text: &str) -> &str {
    let text = text.trim();
    for (key, value) in NAME_OTYPES.iter() {
        if text.starts_with(*key) {
            return value;
        }
    }
    warn!("Otype lookup failed for {text}");
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

fn ordered_names<'a>(
    object_types: &HashMap<&'a str, ObjectType>,
    resolve: &resolver::Resolver,
) -> Vec<&'a str> {
    let mut arcs = vec![];
    for (name, data) in object_types.iter() {
        if data.col || !data.index.is_empty() {
            continue;
        }
        let arc = resolve.lookup(name);
        arcs.push((arc, name));
    }
    arcs.sort_by(|a, b| a.0.cmp(b.0));
    let mut names = vec![];
    for arc in arcs {
        names.push(*arc.1)
    }
    names
}

fn write_arcs(
    out: &mut fs::File,
    object_ids: &[ObjectIdentity],
    resolve: &resolver::Resolver,
    names: &Vec<&str>,
    mod_comps: &[ModuleCompliance],
) -> Result<(), Error> {
    //Write out the constants for Oids"""
    for name in names {
        let uname = upper_snake(name);
        let arc = resolve.lookup(name);
        let larc = arc.len();
        out.write_all(format!("const ARC_{uname}: [u32; {larc}] = {arc:?};\n").as_bytes())?;
    }

    if !object_ids.is_empty() {
        let mut arcs = vec![];
        out.write_all(b"\n// OID definitions for OBJECT-IDENTITY\n\n")?;
        for data in object_ids {
            let uname = upper_snake(data.name);
            let arc = resolve.lookup(data.name);
            arcs.push((arc, uname));
        }
        arcs.sort_by(|a, b| a.0.cmp(b.0));
        for (arc, uname) in arcs {
            let larc = arc.len();
            out.write_all(format!("const ARC_{uname}: [u32; {larc}] = {arc:?};\n").as_bytes())?;
        }
    }

    for mod_comp in mod_comps {
        let name = mod_comp.name;
        let uname = upper_snake(name);
        let arc = resolve.lookup(name);
        let larc = arc.len();
        out.write_all(format!("const COMPLIANCE_{uname}: [u32; {larc}] = {arc:?};\n").as_bytes())?;
    }
    Ok(())
}

fn write_object_ids(out: &mut fs::File, object_ids: &[ObjectIdentity]) -> Result<(), Error> {
    //Write OBJECT-IDENTITY constants"""
    if !object_ids.is_empty() {
        out.write_all(b"\n// The next group is for OBJECT-IDENTITY.\n")?;
        out.write_all(b"\n// These may be used as values rather than MIB addresses\n\n")?;
        for oid in object_ids {
            let uname = upper_snake(oid.name);
            let uname_tr = uname.trim();
            let lname = lower_snake(oid.name);
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
        "OType::BigCounter" => "big_counter_from_int(0)",
        "OType::Ticks" => "ticks_from_int(0)",
        "OType::Address" => "address_from_zeros()",
        _ => "simple_from_int(4)",
    }
    .to_string()
}

fn lookup_int_syntax(arg: &str, syntax: &str) -> String {
    if arg.parse::<i32>().is_ok() {
        return format!("simple_from_int({arg})");
    }
    if syntax.contains("{") {
        let mut syn_bits = syntax.split("{");
        syn_bits.next();
        let body = syn_bits.next().unwrap().split("}").next().unwrap();
        let parts = body.split(",");
        for part in parts {
            let mut part_itr = part.split("(");
            let name = part_itr.next().unwrap().trim();
            let new_name = if name.starts_with("--") && name.contains("\n") {
                let mut nsplit = name.split("\n");
                let _ = nsplit.next();
                nsplit.next().unwrap().trim()
            } else {
                name
            };
            if arg.trim() == new_name {
                let valb = part_itr.next().unwrap();
                let val = valb.split(")").next().unwrap();
                return format!("simple_from_int({val})").to_string();
            }
        }
    }
    warn!("Not found name match for syntax, {arg}, returning 0");
    "simple_from_int(0)".to_string()
}

fn fix_def(
    arg: &str,
    syntax: &str,
    tcs: &HashMap<&str, TextConvention>,
    resolver: &Resolver,
) -> String {
    //Generate default value"""
    let arg = arg.trim();
    if syntax.trim() == "RowPointer" || syntax.trim() == "VariablePointer" {
        if resolver.check_name(arg) {
            let arc = resolver.lookup(arg);
            return format!("simple_from_vec(&{arc:?})").to_string();
        }
        if arg.trim() == "zeroDotZero" {
            return "simple_from_vec(&[0, 0])".to_string();
        }
    }
    if arg.ends_with("'H") || arg.ends_with("'h") {
        let tend = arg.len() - 3;
        let txt = if tend > 1 { &arg[1..tend] } else { "" };
        return format!("simple_from_str(b\"{txt}\")").to_string();
    }

    if let Some(tcsyn) = tc_find_syntax(syntax, tcs) {
        if tcsyn.starts_with("INTEGER")
            || tcsyn.starts_with("Integer32")
            || tcsyn.starts_with("Unsigned")
            || tcsyn.starts_with("Gauge")
            || tcsyn.starts_with("TimeInterval")
        {
            return lookup_int_syntax(arg, tcsyn);
        }
        if tcsyn == "OBJECT IDENTIFIER" {
            if resolver.check_name(arg) {
                let arc = resolver.lookup(arg);
                return format!("simple_from_vec(&{arc:?})").to_string();
            }
            if arg == "zeroDotZero" {
                return "simple_from_vec(&[0, 0])".to_string();
            }
            let uarg = upper_snake(arg);
            return format!("simple_from_vec(&ARC_{uarg})");
        }
        if tcsyn.starts_with("OCTET STRING") {
            let txt = if arg.len() > 3 {
                let tend = arg.len() - 3;
                &arg[1..tend]
            } else {
                ""
            };
            return format!("simple_from_str(b\"{txt}\")");
        }
        if tcsyn.starts_with("BITS") {
            // FIXME should look at args, but setting to a byte of zero should be OK for now
            let txt = "\x00";
            return format!("simple_from_str(b\"{txt}\")");
        }
        if tcsyn.starts_with("TimeTicks") {
            // FIXME should look at args, but setting to value of zero should be OK for now
            return "simple_from_int(0)".to_string();
        }
        panic!("Unsupported TC type for DEFVAL {tcsyn:?} {syntax}");
    }
    if syntax.starts_with("Integer32")
        || syntax.starts_with("Unsigned32")
        || syntax.starts_with("Gauge")
        || syntax.starts_with("INTEGER")
        || syntax.starts_with("TimeInterval")
        || syntax.starts_with("TimeTicks")
    {
        return lookup_int_syntax(arg, syntax);
    }
    if syntax == "OBJECT IDENTIFIER" {
        if resolver.check_name(arg) {
            let arc = resolver.lookup(arg);
            return format!("simple_from_vec(&{arc:?})").to_string();
        }
        if arg == "zeroDotZero" {
            return "simple_from_vec(&[0, 0])".to_string();
        }
        let uarg = upper_snake(arg);
        return "simple_from_vec(&ARC_".to_owned() + &uarg + ")";
    }
    if syntax.starts_with("BITS") {
        let txt = "\x00";
        return format!("simple_from_str(b\"{txt}\")");
    }
    if syntax.starts_with("DisplayString")
        || syntax.starts_with("SnmpAdminString")
        || syntax.starts_with("OCTET STRING")
        || syntax.starts_with("OwnerString")
    {
        let txt = if arg.len() > 3 {
            let tend = arg.len() - 3;
            &arg[1..tend]
        } else {
            ""
        };
        return format!("simple_from_str(b\"{txt}\")");
    }
    warn!("Return DEFVAL {arg} {syntax} literal");
    arg.to_string()
}

fn tc_find_syntax<'a>(text: &str, tcs: &HashMap<&str, TextConvention<'a>>) -> Option<&'a str> {
    if tcs.contains_key(text) {
        return Some(tcs[text].syntax.trim());
    }
    if text.contains(" ") {
        let key = text.split_once(" ").unwrap().0;
        if tcs.contains_key(key) {
            return Some(tcs[key].syntax.trim());
        }
    }
    None
}

fn write_table_struct(
    out: &mut fs::File,
    name: &str,
    object_types: &HashMap<&str, ObjectType>,
    child: ObjectType,
    raw_entry: Vec<(&str, &str)>,
    tcs: &HashMap<&str, TextConvention>,
    resolver: &Resolver,
) -> Result<(), Error> {
    //Write struct for single table"""
    let index_list = child.index;
    // Dodgy, but best guess. If some columns are deprecated or obsolete, they
    // won't be in object_types, so remove them here.
    let entry: Vec<(&str, &str)> = raw_entry
        .into_iter()
        .filter(|(name, _)| object_types.contains_key(name))
        .collect();
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
        .map(|(name, _)| {
            if !object_types.contains_key(name) {
                warn!("Unknown object name {name}");
            }
            access_lookup(object_types[name].access)
        })
        .collect();
    let acols = acols_vec.join(", ");
    //", ".join([ACCESS[object_types[name].access]  for (name, _) in entry.syntax]);
    let cols: Vec<&str> = entry
        .iter()
        .map(|(_, x)| {
            let y = tc_find_syntax(x, tcs).unwrap_or(x);
            name_otype(y)
        })
        .collect();
    let cols_txt = cols.join(", ");
    //cols = [NAME_OTYPE[_[1].split()[0]] for _ in entry]
    let mut icol_data = vec![];
    for ent in &entry {
        if object_types[ent.0].defval.len() > 2 {
            icol_data.push(fix_def(
                object_types[ent.0].defval,
                object_types[ent.0].syntax,
                tcs,
                resolver,
            ))
        } else {
            let syn = tc_find_syntax(ent.1, tcs).unwrap_or(ent.1);
            icol_data.push(value_from_syntax(name_otype(syn)));
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
    let uname = upper_snake(name);
    let uname_tr = uname.trim();
    if child.description.len() > 2 {
        out.write_all(slash_b(child.description).as_bytes())?;
    }
    let set_data = if icols.is_empty() {
        format!("  tab.table.set_indexed_data(vec![(vec![1], vec![{idat}])]);")
    } else {
        format!("  tab.table.set_data(vec![vec![{idat}]]);")
    };
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

   let mut tab = {struct_name} {{
       table: TableMemOid::new(
    vec![{idat}],
    {lcols},
    &base_oid,
    vec![{cols_txt}],
    vec![{acols}],
    vec!{icols:?},
    {implied},
    )
   }};

   {set_data}
   tab
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
fn begin_transaction(&mut self) -> Result<(), OidErr> {{
        self.table.begin_transaction()
    }}
fn commit(&mut self) -> Result<(), OidErr> {{
        self.table.commit()
    }}
fn rollback(&mut self) -> Result<(), OidErr> {{
        self.table.rollback()
    }}
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
    let syntax = data.syntax;
    let syntax = tc_find_syntax(syntax, tcs).unwrap_or(syntax);
    let otype = name_otype(syntax);
    let val = value_from_syntax(otype);
    let tname = title(name);
    let struct_name = format!("Keep{tname}");
    if data.description.len() > 2 {
        out.write_all(slash_b(data.description).as_bytes())?;
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
    fn begin_transaction(&mut self) -> Result<(), OidErr> {{
        self.scalar.begin_transaction()
    }}
    fn commit(&mut self) -> Result<(), OidErr> {{
        self.scalar.commit()
    }}
    fn rollback(&mut self) -> Result<(), OidErr> {{
        self.scalar.rollback()
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
    names: &Vec<&str>,
    resolver: &Resolver,
) -> Result<(), Error> {
    // Heavy lifting
    out.write_all(b"\n// Now the OBJECT-TYPES.")?;
    out.write_all(b" These need actual code added to the stubs\n\n")?;
    for name in names {
        let data = &object_types[name];
        // for (name, data) in object_types.iter() {
        if data.col || !data.index.is_empty() {
            continue;
        }
        if data.table {
            let en_itr = data.syntax.split(" ");
            let entry_name = en_itr.last().unwrap();
            debug!("entry_name is |{entry_name}|");
            let entry = entries[entry_name].syntax.clone();
            let child_opt = object_types
                .values()
                .find(|o| o.syntax.trim() == entry_name);
            if let Some(child) = child_opt {
                if child.augments.len() > 2 {
                    warn!("Buggy AUGMENTS behavior, needs fixing");
                    //panic!("Don't support AUGMENTS yet")
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
                    new_child.update(child);*/
                    write_table_struct(
                        out,
                        name,
                        object_types,
                        child.clone(),
                        entry,
                        tcs,
                        resolver,
                    )?;
                } else {
                    write_table_struct(
                        out,
                        name,
                        object_types,
                        child.clone(),
                        entry,
                        tcs,
                        resolver,
                    )?;
                }
            } else {
                error!("Table definition not found {}", entry_name);
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
    names: &Vec<&str>,
) -> Result<(), Error> {
    //Invoke the types defined earlier"""
    for name in names {
        let data = &object_types[name];
        if data.col || !data.index.is_empty() {
            continue;
        }
        let uname = upper_snake(name);
        let uname_tr = uname.trim();
        let lname = lower_snake(name);
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

fn write_module_compliances(
    out: &mut fs::File,
    mod_comps: &[ModuleCompliance],
) -> Result<(), Error> {
    out.write_all(b"   // Module Compliance values, change false to true when implemented\n\n")?;

    for mod_c in mod_comps {
        let name = mod_c.name;
        let uname = upper_snake(name);
        out.write_all(
            format!("    comp.register_compliance(&COMPLIANCE_{uname}, \"{name}\", false);\n")
                .as_bytes(),
        )?;
    }

    Ok(())
}

pub fn open_output(mib_name: &str, out_dir: &str) -> Result<fs::File, Error> {
    info!("MIB name is {mib_name}");
    let mut base_name = mib_name.split("-MIB").next().unwrap().to_lowercase();

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
    fs::File::create(stub_name)
}

pub fn gen_stub(
    object_types: &HashMap<&str, ObjectType>,
    resolve: resolver::Resolver,
    tcs: &HashMap<&str, TextConvention>,
    entries: &HashMap<&str, Entry>,
    object_ids: &[ObjectIdentity],
    mod_comps: &[ModuleCompliance],
    mut out: fs::File,
) -> Result<(), Error> {
    let stub_start = r"
use crate::config::ComplianceStatements;
use crate::keeper::{Access, OidErr, OidKeeper, OType};
use crate::scalar::ScalarMemOid;
use crate::table::TableMemOid;
use crate::oidmap::OidMap;
use crate::utils::*;
use rasn::types::ObjectIdentifier;

use rasn_snmp::v3::{VarBind, VarBindValue};
";

    out.write_all(stub_start.as_bytes())?;

    let names = ordered_names(object_types, &resolve);
    write_arcs(&mut out, object_ids, &resolve, &names, mod_comps)?;
    write_ot_structs(&mut out, object_types, tcs, entries, &names, &resolve)?;
    let ot = r"

pub fn load_stub(oid_map: &mut OidMap, comp: &mut ComplianceStatements) {
";
    out.write_all(ot.as_bytes())?;
    write_object_ids(&mut out, object_ids)?;
    write_object_types(&mut out, object_types, &names)?;
    write_module_compliances(&mut out, mod_comps)?;
    out.write_all(r"}".as_bytes())?;
    out.flush()?;
    Ok(())
}

pub fn loader(mib_files: Vec<String>) -> Result<(), Error> {
    //"""Write master loader to src/stubs.rs"""
    info!("Writing loader to src/stubs.rs {0:?}", mib_files);
    let mut src = fs::File::create("src/stubs.rs")?;
    let doc = b"//! Stub loader generated by stub-gen.
//!
//! Do not edit - it will be over-written next time you run stub-gen
";
    src.write_all(doc)?;
    src.write_all(b"use crate::oidmap::OidMap;\nuse crate::config::ComplianceStatements;\n\n")?;
    let mut stubs = vec![];
    for mib_name in mib_files {
        let mut base_name = mib_name.split("-MIB").next().unwrap().to_lowercase();

        base_name = base_name.replace("-", "_");
        let stub_name = base_name + "_stub";
        stubs.push(stub_name);
    }
    for stub in &stubs {
        src.write_all(format!("mod {stub};\n").as_bytes())?;
    }
    src.write_all(
        b"\n\n///Generated function to load all stubs\npub fn load_stubs(oid_map: &mut OidMap, comp: &mut ComplianceStatements) {\n",
    )?;
    for stub in &stubs {
        src.write_all(format!("    {stub}::load_stub(oid_map, comp);\n").as_bytes())?;
    }
    src.write_all(b"}\n")?;
    Ok(())
}
