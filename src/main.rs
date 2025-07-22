#![warn(missing_docs)]
//!# SNMP v3 Agent framework
//! This is preliminary work towards a framework for developing SNMP v3 agents, using the rasn ASN-1 library for
//! decoding the on the wire data. While a manager (effectively a client) has to support a range of legacy agents,
//! an agent (e.g. server) can offer a subset of features and still be useful.
//!
//! This agent only support SNMP v3.
//!
//! The standards define the use of horrible old crypto types like single DES for privacy, and MD5 in the authentication.
//! The code currently supports HMAC-SHA-1-96 and AES-128; stronger hashes from RFC7630 are planned for the future.
//! There is no agreed standard for stronger ciphers. It is not clear that using stronger hash functions or ciphers
//! will deliver significant advantages in practice. The well known collision weakness of SHA-1 is not a problem in
//! an HMAC application.
//!
//! The agent server loop is a single threaded blocking design. I would argue that this is appropriate for almost all
//! agents, as typically a single manager will interact with multiple agents. Managers may well want to support high
//! levels of concurrency. The single threaded design avoids many issues with concurrency and locking. Of course,
//! there is nothing to stop handlers for specific long running operations using a thread, and this might be a good
//! option for the CreateAndWait model of table row creation. Good luck with that!
//!
//! At present, there is a simplistic permissions model, and some real world applications will need more than that.
//! Coming real soon. It may not be RFC view action model, as that seems complex, and the facility to dynamically
//! change the permissions model remotely is not often implemented. Instead, some sort of compile time model seems
//! more appropriate to the sort of boxes that run agents.
//!
//! The Engine ID is loaded from a configuration file.
//!
//! There is no support for notifications so far.
//!
//! There is no explicit support for Module Compliance.
//!
//!## Users and passwords
//! There is a small python tool for generating a username and password file under tools/usekey.py. If you change the Engine ID in the agent source, you will need to make a matching change here.
//!
//! Changing passwords on the wire is not yet implemented, and would be a really good project - an issue is open for it!

//!## Tools for stub generation
//! At present, there is only rough tooling to help implement an useful agent, but it is just about possible with enough
//! patience. There are two stub generators, one in Python and one in Rust.
//!
//! The ugliest bit of python I have ever written is in tools/mib_play.py. For some MIBs, it can generate Rust code that
//!  compiles, and gives a dummy implementation. It ignores MODULE-COMPLIANCE and does not carry range constraints
//!  through to the generated Rust code. It does the wrong thing with AUGMENTS. There is no support for legacy v1 MIBS,
//!  which occasionally get pulled in as imports. Something goes wrong with import processing on a few files.
//!  This is tool is effectively deprecated, but there are a few things it can do that the Rust one cannot.
//!  Once the Rust one reaches feature parity, the Python one will be removed.
//!
//! The source files for the Rust stub generator are under src/bin/stub-gen. It uses the nom parser combinator library
//! for parsing. It has a reasonably complete parser implementation, which can parse almost all the MIBs on my machine
//! except for legacy MIBS in Smi v1 and a few bootstrap definition files. The code generator in this version ignores
//! everything to do with notifications and compliance.  It also does the wrong thing with AUGMENTS.
//!
//!## Workflow
//! First build the stub generator with:
//! ```shell
//! cargo build --bin stub-gen
//! ```
//!
//! then generate the stubs for the mibs you want with:
//!
//! ```shell
//! target/debug/stub-gen -o src/stubs/ MIB1 MIB2 ...
//! ```
//! where MIB1 and MIB2 and so on are the names of the MIB files to generate stubs from.
//!
//! The generator searches /var/lib/mibs/ietf, /var/lib/mibs/iana and /usr/share/snmp/mibs to find the files,
//! and tries adding .txt extension as well. If your system has the files somewhere different, or you wish to include
//!  vendor mibs, edit src/bin/stub-gen/importer.rs and change the SEARCH_PATH constant. Arguably, this should be
//!  settable by the command line and / or an environment variable.
//!
//! The generated stubs will be placed under src/stubs/.
//!
//! If you want the agent to do something useful, you need to write your own back-end implementations.The generated
//! stubs are placed in the src/stubs/ directory. The basic idea is to associate instances that support the OidKeeper
//! trait with the OID value or values that they support in the OidMap. This is populated and then the
//! agent loop_forever() runs.
//!
//! Two toy implementations of the OidKeeper trait are provided by way of example, both purely memory based.
//! One is for scalars, and the other is a limited table mode. Set can change cell values in existing rows.
//! New rows can be created by the CreateAndWait mechanism if there is a RowStatus column in the table, and destroyed
//! by Destroy. If you change the value of index cells, the results may be puzzling. If the MIB is correctly structured,
//! the permissions checks should stop you making that mistake. The generated stub implementations
//! just wrap the toy struct types, and need to be replaced by real actions.
use snmp_rust_agent::config::Config;
use snmp_rust_agent::handlers;
use snmp_rust_agent::oidmap::OidMap;
use snmp_rust_agent::perms;
use snmp_rust_agent::snmp_agent::Agent;
use snmp_rust_agent::stubs::load_stubs;
use snmp_rust_agent::usm;

/// Simplistic example main. Loads configuration from file.
fn main() -> std::io::Result<()> {
    env_logger::init();
    let perms: Vec<perms::Perm> = perms::load_perms();
    let mut users = usm::Users::new();
    users.load_from_file(&perms);
    let mut oid_map: OidMap = OidMap::new();
    let conf = Config::load();
    load_stubs(&mut oid_map);
    let mut agent: Agent = Agent::build(conf.engine_id.clone(), &conf.listen);
    handlers::load_stubs(&mut oid_map, &conf, &agent, &users);
    agent.loop_forever(&mut oid_map, users);
    Ok(())
}
