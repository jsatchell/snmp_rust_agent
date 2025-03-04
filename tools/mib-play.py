"""Comedy MIB compiler

Usage:
  mib-play.py [-d] [-l <listen>] <mibfile> ...
  mib-play.py -h
  mib-play.py -b

Options:
  -h --help      Show this screen.
  -v, --version  Show version
  -b, --bugs     Print list of known bugs and limitations
  -d, --debug    Increase log spew.
  -l <listen>, --listen <listen>   Listen address [default: 127.0.0.1:2161]

<mibfile> can be an absolute path, or if it is a short name the code will try
looking it up in a built-in search path. The search path is set by the constant MIB_PATH
in mib_imp.py.

For many production cases, a good listen address is 0.0.0.0:161. If you system has
multiple interfaces, like a firewall, you may only want to listen on one address.

In the stub case, two files are generated, with names based on the lower case
version of the mib name, with the MIB suffix removed (and .txt if it has that too)

One contains the stub code, and one a simplistic main that invokes it, and 
pulls in a loader from the stub. You will need to edit the stub.
If you want to include multiple MIBs, which is needed for many applications, modify 
a single main to pull in all the loaders.

Copyright Julian Satchell 2025
"""
import logging
import docopt
from gen_rs import gen_rs
from gen_stub import gen_stub, loader
from mib_imp import mib_import, find_mib_file, strip_comments,\
       parse_module_id, parse_object_types, parse_oids, parse_text_conventions,\
       parse_table_entries

LOGGER = logging.getLogger(__file__)



def print_tables(object_types, resolve, tcs, entries):
    for name, data in object_types.items():

        if not data["table"]:
            continue
        print()
        if data["syntax"] in tcs:
            syntax = tcs[data["syntax"]]["syntax"]
        else:
            syntax = data["syntax"]
        print(name, syntax, data["access"])
        print(resolve[name])
        entry = [(e[0], tcs.get(e[1], {"syntax": e[1]})["syntax"])
                 for e in entries[data["entry"]]]
        print(entry)
        #if "description" in data:
        #    print(data["description"])
        if "index" in data:
            print(data["index"])
        else:
            ename = data["entry"]
            child_name = ename[0].lower() + ename[1:]
            if child_name in object_types:
                child = object_types[child_name]
                print("INDEX", child["index"])



def parse_mib(mib_file: str):
    # Bootstrap list of OIDs to get started
    resolve = {"0": [0],
               "iso": [1],
               "org": [1, 3],
               "dod": [1, 3, 6],
               "internet": [1, 3, 6, 1 ],
               "mib-2": [1, 3, 6, 1, 2, 1],
               "system": [1, 3, 6, 1, 2, 1, 1],
               "interfaces": [1, 3, 6, 1, 2, 1, 2],
               "mgmt": [1, 3, 6, 1, 2 ],
               "transmission": [1, 3, 6, 1, 2, 1, 10],
               "snmp": [1, 3, 6, 1, 2, 1, 11],
               "snmpV2": [1, 3, 6, 1, 6],
               "snmpModules": [1, 3, 6, 1, 6, 3],
               "snmpMIB": [1, 3, 6, 1, 6, 3, 1],
               "snmpFrameworkMIB": [1, 3, 6, 1, 6, 3, 10],
               "private": [1, 3, 6, 1, 4],
               "enterprises": [1, 3, 6, 1, 4, 1],
               }
    
    mib_file = find_mib_file(mib_file)
    if not mib_file:
        exit(99)
    with open(mib_file, "r") as stream:
       
        object_types = {}
        text = strip_comments(stream.read())
        entries = parse_table_entries(text)
        tcs = parse_text_conventions(text)
        oids = parse_module_id(text)
        if "IMPORTS" in text:
            _, rest = text.split("IMPORTS", 1)
            
            imparts = rest.split("FROM")
            for i, impart in enumerate(imparts[1:]):
                previous = imparts[i]
                names = [_.strip() for _ in previous.split(",")]
                if i>0:
                    names[0] = names[0].split()[-1]
                LOGGER.debug("Import names %s", names)
                name_set = set(names)
                imp_mib = impart.split()[0].strip()
                mib_import(imp_mib, name_set, oids, tcs, object_types, resolve)

                           
        # Just ignore compliance stuff for now 
        #if "MODULE-COMPLIANCE" in rest:
        #    rest, _ = rest.split("MODULE-COMPLIANCE", 1)
        # Find all the OBJECT IDENTIFIERs
        parse_oids(text, oids)
        object_types.update(parse_object_types(text))
        
        # Make two passes resolving stuff
        for name, data in oids.items():
            parent, num = data
            if parent in resolve:
                pval = resolve[parent].copy() + [num]
                resolve[name] = pval
    
        for name, data_obj in object_types.items():
            parent, num = data_obj["def"]
            if parent in resolve:
                pval = resolve[parent].copy() + [num]
                resolve[name] = pval
        # Now warning about missing definitions in these passes
        for name, data in oids.items():
            parent, num = data
            if parent in resolve:
                pval = resolve[parent].copy() + [num]
                resolve[name] = pval
            else:
                LOGGER.warning("Unable to find oid parent %s", parent)
        for name, data_obj in object_types.items():
            parent, num = data_obj["def"]
            if parent in resolve:
                pval = resolve[parent].copy() + [num]
                resolve[name] = pval
            else:
                LOGGER.warning("Unable to find %s", parent)
        return object_types, resolve, tcs, entries

# Selection to try in development
mib_files =  ["UDP-MIB",
"UDPLITE-MIB",
"UPS-MIB",
"WWW-MIB",
#"VDSL-LINE-EXT-MCM-MIB"
]


def write_bugs():
    print("""
          MODULE-COMPLIANCE is ignored, but maybe hand coded stubs are OK
          AUGMENTS is ignored
          constraints in SYNTAX are ignored
           - at least should appear in a comment
          constraints in TEXTUAL-CONVENTIONS are ignored
           - at least should appear in a comment
          imports code only lightly tested. Sometimes
             you will need to add bootstrap definitions to resolve.
          OIDs are defined in the code that are never referenced.
          Should use classes, rather than dict of dicts.
    """)
    exit()


if __name__ == '__main__':
    arguments = docopt.docopt(__doc__, version='mib-play 0.0.2',
                              options_first=True)
    if arguments["--bugs"]:
        write_bugs()
    log_level = logging.DEBUG if arguments["--debug"] else logging.INFO
    logging.basicConfig(level=log_level)

    for mib_file in arguments["<mibfile>"]:
        object_types, resolve, tcs, entries = parse_mib(mib_file)

        gen_stub(object_types, resolve, tcs, entries, mibname=mib_file,
                     listen=arguments["--listen"])
    loader(arguments["<mibfile>"])