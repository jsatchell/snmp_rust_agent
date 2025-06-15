mod gen_stub;
mod importer;
mod parser;
mod resolver;

use argh::FromArgs;
use log::{error, info, warn};
use std::collections::{HashMap, HashSet};
use std::error::Error;

#[derive(FromArgs)]
/// Generate stubs for use with snmp-rust-agent
struct Cli {
    /// output directory
    #[argh(
        option,
        short = 'o',
        default = "String::from(\"../snmp-rust/src/stubs/\")"
    )]
    out_dir: String,

    /// names of MIBs to process
    #[argh(positional)]
    mib_names: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let cli: Cli = argh::from_env();
    let mut total = 0;
    let mut success = 0;
    let builtins: HashSet<&str> = vec![
        "TimeTicks",
        "OBJECT-TYPE",
        "Counter32",
        "Gauge32",
        "NOTIFICATION-TYPE",
        "Unsigned32",
        "Counter64",
        "mib-2",
        "transmission",
        "IpAddress",
        "OBJECT-IDENTITY",
        "internet",
        "Counter",
        "snmpModules",
        "snmpProxys",
        "snmpDomains",
        "Integer32",
        "MODULE-IDENTITY",
        "TEXTUAL-CONVENTION",
        "NOTIFICATION-GROUP",
        "OBJECT-GROUP",
        "MODULE-COMPLIANCE",
        "DisplayString",
        "EntryStatus",
        "OwnerString",
    ]
    .into_iter()
    .collect();

    /*let mib_path = Path::new("/var/lib/mibs/ietf/");

    for entry in fs::read_dir(mib_path)? {
       let entry = entry?;
       let path = entry.path();
       //if !path.ends_with("UDPF-MIB") {continue;}
       let text = //fs::read_to_string(&path).unwrap(); */
    for argument in &cli.mib_names {
        if argument.ends_with("mib-compiler-rs") {
            continue;
        }
        let text_opt = importer::find_mib_text(argument);
        if text_opt.is_none() {
            warn!("Not found MIB {argument}, skipping, will try rest");
            continue;
        }
        let text = text_opt.unwrap();
        let mib_name = argument;
        let mut iraw: String; // Will be used below for import text
        let mut res = resolver::Resolver::new();
        let mut nodes = vec![];
        total += 1;
        let (good_parse, site) = parser::parse_mib(&text, &mut nodes);

        if good_parse {
            let imp_nodes: Vec<&parser::MibNode> = nodes
                .iter()
                .filter(|node| matches!(**node, parser::MibNode::Imp(_)))
                .collect();
            if imp_nodes.len() != 1 {
                warn!("Expected one import block");
                continue;
            }
            let imp_node = imp_nodes[0];
            let val = match imp_node {
                parser::MibNode::Imp(istruct) => istruct.imp_list.clone(),
                _ => {
                    panic!("Weird! expected ImpNode here");
                }
            };
            for (names, mib_name) in val {
                let miss: Vec<String> = names
                    .iter()
                    .filter(|x| !builtins.contains(*x))
                    .map(|x| x.to_string())
                    .collect();
                if !miss.is_empty() {
                    let txt_opt = importer::find_mib_text(mib_name);
                    if txt_opt.is_some() {
                        iraw = txt_opt.unwrap().clone();
                        let extra = importer::process_one(&iraw, miss, mib_name, &mut res);
                        nodes.extend(extra);
                    } else {
                        error!("Import failed for {mib_name}, file not found");
                    }
                }
            }

            let mut good_parent = false;
            let inodes = nodes.clone();
            for pass in 0..2 {
                for node in &inodes {
                    match node {
                        parser::MibNode::ModId(o) => {
                            let v = &o.val;
                            let parent = v.parent;
                            let added = res.try_add(o.name, parent, &v.num);
                            good_parent = added;
                            if !added && pass > 1 {
                                error!("Unknown module parent {parent} {mib_name}")
                            }
                        }
                        parser::MibNode::ObTy(o) => {
                            let v = &o.val;
                            let parent = v.parent;
                            let added = res.try_add(o.name, parent, &v.num);
                            if good_parent && !added && pass > 1 {
                                error!("Unknown type parent {parent} {mib_name}")
                            }
                        }
                        parser::MibNode::ObIdy(o) => {
                            let v = &o.val;
                            let parent = v.parent;
                            let added = res.try_add(o.name, v.parent, &v.num);
                            if good_parent && !added && pass > 1 {
                                error!("Unknown identity parent {parent}")
                            }
                        }
                        parser::MibNode::ObIdf(o) => {
                            let v = &o.val;
                            let parent = v.parent;
                            let added = res.try_add(o.name, v.parent, &v.num);
                            if good_parent && !added && pass > 1 {
                                error!("Unknown identifier parent {parent}")
                            }
                        }
                        _ => (),
                    }
                }
            }
            let mut object_types: HashMap<&str, parser::ObjectType> = HashMap::new();
            let mut tcs: HashMap<&str, parser::TextConvention> = HashMap::new();
            let mut entries: HashMap<&str, parser::Entry<'_>> = HashMap::new();
            let mut object_ids: Vec<parser::ObjectIdentity<'_>> = vec![];
            let gnodes = nodes.clone();
            for node in gnodes {
                match node {
                    parser::MibNode::ObTy(x) => {
                        object_types.insert(x.name, x);
                    }
                    parser::MibNode::Tc(x) => {
                        tcs.insert(x.name, x);
                    }
                    parser::MibNode::Ent(x) => {
                        entries.insert(x.name, x);
                    }
                    parser::MibNode::ObIdy(x) => object_ids.push(x),
                    _ => {}
                }
            }
            // Now mark the table columns, so we don't generate scalar code for them
            for entry in entries.values() {
                for ent in entry.syntax.clone() {
                    let col_obj_res = object_types.get_mut(ent.0);
                    if let Some(c) = col_obj_res {
                        c.col = true
                    }
                }
            }
            let compile_res = gen_stub::gen_stub(
                &object_types,
                res,
                &tcs,
                &entries,
                &object_ids,
                mib_name,
                &cli.out_dir,
            );
            if compile_res.is_ok() {
                success += 1;
            }
        } else {
            error!("{mib_name}  {site}");
        }
    }
    info!("{success} read out of {total}");
    if gen_stub::loader(cli.mib_names).is_ok() {
        info!("Wrote stub loader");
    }
    Ok(())
}
