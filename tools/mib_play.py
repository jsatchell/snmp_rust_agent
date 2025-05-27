"""Comedy MIB compiler

Usage:
  mib_play.py [-d] [-f] <mibfile> ...
  mib_play.py -h
  mib_play.py -b

Options:
  -h --help      Show this screen
  -v, --version  Show version
  -b, --bugs     Print list of known bugs and limitations
  -d, --debug    Increase log spew
  -f, --force    Overwrite existing stub files

<mibfile> can be an absolute path, or if it is a short name the code will try
looking it up in a built-in search path. The search path is set by the constant
MIB_PATH in mib_imp.py.

For each MIB name on the command line, a stub is generated and placed in
src/stubs/. The stub name is based on the lower case version of the MIB name,
with the MIB suffix removed (and .txt if it has that too).

In addition to a stub per MIB file, a loader is written in src/stubs.rs. This
imports all the stubs, and loads the definitions from each one. The main agent
code is unaltered.

Copyright Julian Satchell 2025
"""
import logging
import sys
import docopt
from gen_stub import gen_stub, loader
from mib_imp import mib_import, find_mib_file, strip_comments, \
       parse_module_id, parse_object_types, parse_oids, \
       parse_text_conventions, parse_table_entries, parse_obj_ident

LOGGER = logging.getLogger(__file__)


def print_tables(pobject_types, ptcs, pentries, presolve):
    """Debugging aid to print out table data"""
    for name, data in pobject_types.items():

        if not data["table"]:
            continue
        print()
        if data["syntax"] in ptcs:
            syntax = ptcs[data["syntax"]]["syntax"]
        else:
            syntax = data["syntax"]
        print(name, syntax, data["access"])
        print(presolve[name])
        entry = [(e[0], ptcs.get(e[1], {"syntax": e[1]})["syntax"])
                 for e in pentries[data["entry"]]]
        print(entry)
        # if "description" in data:
        #    print(data["description"])
        if "index" in data:
            print(data["index"])
        else:
            ename = data["entry"]
            child_name = ename[0].lower() + ename[1:]
            if child_name in pobject_types:
                child = pobject_types[child_name]
                print("INDEX", child["index"])


def process_imports(itext, ioids, itcs, iobject_types, iresolve):
    """Do all the imports, uadating variables as we go"""
    _, rest = itext.split("IMPORTS", 1)

    imparts = rest.split("FROM")
    for i, impart in enumerate(imparts[1:]):
        previous = imparts[i]
        names = [_.strip() for _ in previous.split(",")]
        if i > 0:
            names[0] = names[0].split()[-1]
        LOGGER.debug("Import names %s", names)
        name_set = set(names)
        imp_mib = impart.split()[0].strip()
        mib_import(imp_mib, name_set, ioids, itcs, iobject_types, iresolve)


def resolve_stuff(resolve, oids, object_ids, object_types):
    """Make two passes resolving stuff"""
    for i in range(2):
        for name, data in oids.items():
            parent, num = data
            if parent in resolve:
                resolve[name] = resolve[parent].copy() + [num]
            else:
                if i > 0:
                    LOGGER.warning("Unable to find oid parent %s", parent)
        for name, data in object_ids.items():
            parent, num = data
            if parent in resolve:
                resolve[name] = resolve[parent].copy() + [num]
            else:
                LOGGER.warning("Unable to find object id parent %s", parent)

        for name, data_obj in object_types.items():
            parent, num = data_obj["def"]
            if parent in resolve:
                resolve[name] = resolve[parent].copy() + [num]
            else:
                LOGGER.warning("Unable to find %s", parent)


def parse_mib(mib_name: str):
    """Parse mib file"""
    # Bootstrap list of OIDs to get started
    # Can probably manage with a lot less than these!
    resolve = {"0": [0],
               "iso": [1],
               "org": [1, 3],
               "dod": [1, 3, 6],
               "internet": [1, 3, 6, 1],
               "mib-2": [1, 3, 6, 1, 2, 1],
               "system": [1, 3, 6, 1, 2, 1, 1],
               "interfaces": [1, 3, 6, 1, 2, 1, 2],
               "mgmt": [1, 3, 6, 1, 2],
               "transmission": [1, 3, 6, 1, 2, 1, 10],
               "snmp": [1, 3, 6, 1, 2, 1, 11],
               "snmpV2": [1, 3, 6, 1, 6],
               "snmpModules": [1, 3, 6, 1, 6, 3],
               "snmpMIB": [1, 3, 6, 1, 6, 3, 1],
               "snmpFrameworkMIB": [1, 3, 6, 1, 6, 3, 10],
               "private": [1, 3, 6, 1, 4],
               "enterprises": [1, 3, 6, 1, 4, 1],
               }

    mib_file_name = find_mib_file(mib_name)
    if not mib_file_name:
        sys.exit(99)
    with open(mib_file_name, "r", encoding="ascii") as stream:
        text = strip_comments(stream.read())
        object_types = {}
        # These are OIDs that are defined for use as values,
        # like system states, rather than as paths in the MIB
        object_ids = {}
        entries = parse_table_entries(text)
        tcs = parse_text_conventions(text)
        oids = parse_module_id(text)
        if "IMPORTS" in text:
            process_imports(text, oids, tcs, object_types, resolve)

        # Just ignore compliance stuff for now
        # if "MODULE-COMPLIANCE" in rest:
        #    rest, _ = rest.split("MODULE-COMPLIANCE", 1)
        # Find all the OBJECT IDENTIFIERs
        parse_oids(text, oids)
        parse_obj_ident(text, object_ids)

        object_types.update(parse_object_types(text))

        resolve_stuff(resolve, oids, object_ids, object_types)
        return object_types, resolve, tcs, entries, object_ids


def write_bugs():
    """Write bugs and exit"""
    print("""
          MODULE-COMPLIANCE is ignored, but maybe hand coded stubs are OK
          DEFVAL is ignored
          BITS types cause trouble, and result in invalid RUST
          constraints in SYNTAX are ignored
           - at least should appear in a comment
          constraints in TEXTUAL-CONVENTIONS are ignored
           - at least should appear in a comment
          imports code only lightly tested. Sometimes
             you will need to add bootstrap definitions to resolve.
          OIDs are defined in the code that are never referenced.
          Should use classes, rather than dicts of dicts.
          Overwrites without warning.
        """)
    sys.exit()


if __name__ == '__main__':
    arguments = docopt.docopt(__doc__, version='mib_play 0.0.2',
                              options_first=True)

    if arguments["--bugs"]:
        write_bugs()
    LOG_LEVEL = logging.DEBUG if arguments["--debug"] else logging.INFO
    logging.basicConfig(level=LOG_LEVEL)

    for mib_file in arguments["<mibfile>"]:
        mobject_types, mresolve, mtcs, mentries, mobject_ids = parse_mib(mib_file)

        gen_stub(mobject_types, mresolve, mtcs, mentries, mobject_ids,
                 mibname=mib_file, force=arguments["--force"])
    loader(arguments["<mibfile>"])
