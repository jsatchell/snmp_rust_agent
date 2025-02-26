"""Comedy MIB compiler

Usage:
  mib-play.py [-d] [-p [-o <out>]] <mibfile> 
  mib-play.py -h
  mib-play.py -b

Options:
  -h --help      Show this screen.
  -v, --version  Show version
  -b, --bugs     Print list of known bugs and limitations
  -d, --debug    Increase log spew.
  -p, --play     Generate self-contained "play" code using memory based
                  classes, rather than stubs that must be completed.
  -o <out>, --out <out>      Write code to file named <out>, rather than to stdout.

<mibfile> can be an absolute path, or if it is a short name the code will try
looking it up in a built-in search path.

At present, generates code in "play" mode regardless of absence of option!!

Copyright Julian Satchell 2025
"""
import os
import logging
import docopt
from gen_rs import gen_rs


LOGGER = logging.getLogger(__file__)

MIB_PATH = [
    "/var/lib/mibs/ietf/",
    "/var/lib/mibs/iana/",
    "/usr/share/snmp/mibs/"
]


def find_mib_file(name: str) -> str:
    """Return absolute file name of MIB file

    If name can't be found,return empty string.
    """
    if name.startswith("/"):
        return name
    if name.endswith(";"):
        name = name[:-1] 
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
            LOGGER.warning("Ignoring TC, not found ::=")
            continue
        x, y = previous.rsplit("::=", 1)
        if y.isspace():
            tc_name = x.strip().rsplit()[-1]
            data = {}
            if "DISPLAY-HINT" in part:
                data["hint"] = part.split("DISPLAY-HINT", 1)[1].split('"', 2)[1]
            if "DESCRIPTION" in part:
                post = part.split("DESCRIPTION", 1)[1].split('"', 2)[2]

            if "SYNTAX" in post:
                data["syntax"] = post.split("SYNTAX", 1)[1].split("\n")[0].strip()
            LOGGER.debug("Defining TC %s as %s", tc_name, data)
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

def parse_module_id(text: str) -> dict:
    ret = {}
    if "MODULE-IDENTITY\n" in text:
        # Some of the core bootstrap files do not have this
        imp_id, rest = text.split("MODULE-IDENTITY\n", 1)
        mod_id = imp_id.rsplit(None, 1)[1]

        rest = rest.split("::=", 1)[1]
        top_def, rest = rest.split("}", 1)
        top_def += "}"  
        ret[mod_id.strip()] = top_def
    return ret


def parse_mib(mib_file: str, depth=0):
    # Bootstrap list of OIDs to get started
    resolve = {"iso": [1],
               "org": [1, 3],
               "dod": [1, 3, 6],
               "internet": [1, 3, 6, 1 ],
               "mib-2": [1, 3, 6, 1, 2, 1],
               "system": [1, 3, 6, 1, 2, 1, 1],
               "mgmt": [1, 3, 6, 1, 2 ],
               "transmission": [1, 3, 6, 1, 2, 1, 10],
               "snmp": [1, 3, 6, 1, 2, 1, 11],
               "private": [1, 3, 6, 1, 4],
               "enterprises": [1, 3, 6, 1, 4, 1],
               "ucdavis": [1, 3, 6, 1, 4, 1, 2021],
               }
    mib_file = find_mib_file(mib_file)
    if not mib_file:
        exit(99)
    with open(mib_file, "r") as stream:
       
        otypes = {}
        text = stream.read()
        ents = parse_table_entries(text)
        tcs = parse_text_conventions(text)
        #lines = text.split("\n")
        oids = parse_module_id(text)
        if "IMPORTS" in text:
            _, rest = text.split("IMPORTS", 1)
            if depth == 0:
                imparts = rest.split("FROM")
                for i, impart in enumerate(imparts[1:]):
                    previous = imparts[i]
                    names = [_.strip() for _ in previous.split(",")]
                    if i>0:
                        names[0] = names[0].split()[-1]
                    LOGGER.debug("Import names %s", names)
                        
                    imp_mib = impart.split()[0].strip()
                    imp_path = find_mib_file(imp_mib)
                    if imp_path:
                        with open(imp_path, "r") as nest:
                            itext = nest.read()
                            inner_oids = {}
                            parse_oids(itext, inner_oids)
                            inner_tcs = parse_text_conventions(itext)
                            for key, value in inner_oids.items():
                                if key in names:
                                    oids[key] = value
                            for key, value in inner_tcs.items():
                                if key in names:
                                    tcs[key] = value
        # Just ignore compliance stuff for now 
        #if "MODULE-COMPLIANCE" in rest:
        #    rest, _ = rest.split("MODULE-COMPLIANCE", 1)
        # Find all the OBJECT IDENTIFIERs
        parse_oids(text, oids)

        parts = text.split(" OBJECT-TYPE")
        for i, part in enumerate(parts[1:]):
            _, oname = parts[i].rsplit("\n", 1)
            if "SYNTAX" not in part or "MAX-ACCESS" not in part:
                LOGGER.debug("No SYNTAX, skipping, probably initial import")
                continue
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
           
            data["syntax"] = part.split("SYNTAX", 1)[1].split("\n")[0].strip()
            data["table"] = "SEQUENCE" in data["syntax"]
            if data["table"]:
                entry = data["syntax"].split("OF")[1].strip()
                data["entry"] = entry
            otypes[oname.strip()] = data
        # Make two passes resolving stuff
        for name, data in oids.items():
            content = data.split("{", 1)[1].split("}")[0].strip()
            parent, snum = content.split(None, 1)
            num = int(snum.strip())
            parent = parent.strip()
            if parent in resolve:
                pval = resolve[parent].copy() + [num]
                resolve[name] = pval
    
        for name, data_obj in otypes.items():
            data = data_obj["def"]
            content = data.split("{", 1)[1].split("}")[0].strip()
            parent, snum = content.split(None, 1)
            num = int(snum.strip())
            parent = parent.strip()
            if parent in resolve:
                pval = resolve[parent].copy() + [num]
                resolve[name] = pval
        # Now warning about missing definitions in these passes
        for name, data in oids.items():
            content = data.split("{", 1)[1].split("}")[0].strip()
            parent, snum = content.split(None, 1)
            num = int(snum.strip())
            parent = parent.strip()
            if parent in resolve:
                pval = resolve[parent].copy() + [num]
                resolve[name] = pval
            else:
                LOGGER.warning("Unable to find oid parent %s", parent)
        for name, data_obj in otypes.items():
            data = data_obj["def"]
            content = data.split("{", 1)[1].split("}")[0].strip()
            parent, snum = content.split(None, 1)
            parent = parent.strip()
            num = int(snum.strip())
            if parent in resolve:
                pval = resolve[parent].copy() + [num]
                resolve[name] = pval
            else:
                LOGGER.warning("Unable to find %s", parent)
        
        return otypes, resolve, tcs, ents

# Selection to try in development
mib_files =  ["UDP-MIB",
"UDPLITE-MIB",
"UPS-MIB",
"WWW-MIB",
#"VDSL-LINE-EXT-MCM-MIB"
]


def write_bugs():
    print("""
          MODULE-COMPLIANCE is ignored
          AUGMENTS is ignored
          IMPLIED in INDEX definitions is ignored
          constraints in SYNTAX are ignored
          constraints in TEXTUAL-CONVENTIONS are ignored
          imports are only followed one layer down
          OIDs are defined in the code that are never referenced
    """)
    exit()


if __name__ == '__main__':
    arguments = docopt.docopt(__doc__, version='mib-play 0.0.1',
                              options_first=True)
    if arguments["--bugs"]:
        write_bugs()
    log_level = logging.DEBUG if arguments["--debug"] else logging.INFO
    logging.basicConfig(level=log_level)

    otypes, resolve, tcs, ents = parse_mib(arguments["<mibfile>"])

    if arguments["--out"]:
        with open(arguments["--out"], "w") as out:
            gen_rs(otypes, resolve, tcs, ents, arguments["--play"], out)
    else:
        gen_rs(otypes, resolve, tcs, ents, arguments["--play"])