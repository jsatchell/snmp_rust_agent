"""Individual item parsers, and import handling"""
import logging
import os

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
    matches = {name, name + ".txt"}
    for dirname in MIB_PATH:
        for fname in os.listdir(dirname):
            if fname in matches:
                return os.path.join(dirname, fname)
    LOGGER.error("Couldn't find MIB named %s", name)
    return ""


def dedent_description(raw: str) -> str:
    """Convert description into Rust comment"""
    lines = [""] + ["// " + _.strip() for _ in raw.split("\n")]
    return "\n".join(lines)


def parse_table_entries(text: str) -> dict:
    """Parse a table definition"""
    entries = {}
    parts = text.split("SEQUENCE")
    for i, part in enumerate(parts[1:]):
        previous = parts[i]
        if "::=" not in previous:
            continue
        x, y = previous.rsplit("::=", 1)
        # print(x[-20:], "Y", y)
        if y.isspace():
            ent_name = x.strip().rsplit()[-1]
            # print(ent_name)
            x, y = part.split("{", 1)
            if x.isspace():
                data = [_.strip().split() for _
                        in y.split("}", 1)[0].split(",")]
                entries[ent_name] = data
    return entries


def parse_text_conventions(text: str):
    """Get any TEXTUAL-CONVENTIONS"""
    tcs = {}
    parts = text.split("TEXTUAL-CONVENTION")
    for i, part in enumerate(parts[1:]):
        previous = parts[i]
        if "::=" not in previous:
            # print(previous[-20:], part[:20])
            LOGGER.debug("Ignoring TC, not found ::=")
            continue
        x, y = previous.rsplit("::=", 1)
        if y.isspace():
            tc_name = x.strip().rsplit()[-1]
            data = {}
            if "DISPLAY-HINT" in part:
                data["hint"] = part.split("DISPLAY-HINT", 1)[1].split('"', 2)[1]
            if "DESCRIPTION" in part:
                post = part.split("DESCRIPTION", 1)[1].split('"', 2)[2]
            else:
                post = part
            if "SYNTAX" in post:
                syntax = post.split("SYNTAX", 1)[1].split("\n")
                if syntax[0].split()[-1] == "{":
                    defs = post.split("{")[1].split("}", 1)[0].split("\n")
                    dsyntax = syntax[0].strip() + " ".join(defs) + "}"
                else:
                    dsyntax = syntax[0].strip()
                data["syntax"] = dsyntax
            LOGGER.debug("Defining TC %s as %s", tc_name, data)
            tcs[tc_name] = data
    return tcs


def strip_comments(text):
    """Remove comments from text"""
    return "\n".join([_.split("--")[0] for _ in text.split("\n")])


def parse_brace(val):
    """Parse braces to get parent and number"""
    val = val.strip()[1:-1]  # Remove braces
    parent, snum = val.split(None, 1)
    num = int(snum.strip())
    return parent, num


def parse_oids(text: str, oids: dict):
    """Find object identifiers"""
    parts = text.split("OBJECT IDENTIFIER")
    for i, part in enumerate(parts[1:]):
        if "::=" in part:
            x, y = part.split("::=", 1)
            previous = parts[i]
            if x.isspace():
                frags = previous.split("\n")
                oname = frags[-2] if frags[-1].isspace() else frags[-1]
                val = y.split("}")[0].strip() + " }"
                oids[oname.strip()] = parse_brace(val)


def parse_obj_ident(text: str, obj_ids: dict):
    """Object identities"""
    parts = text.split("OBJECT-IDENTITY")
    for i, part in enumerate(parts[1:]):
        if "::=" in part:
            _, y = part.split("::=", 1)
            if "FROM" in _:   # Then it is the initial import
                continue
            previous = parts[i]
            oname = previous.rsplit(None, 1)[1]
            val = y.split("}")[0].strip() + " }"
            obj_ids[oname] = parse_brace(val)


def parse_module_id(text: str) -> dict:
    """Parse the MODULE-IDENTITY"""
    ret = {}
    if "MODULE-IDENTITY\n" in text:
        # Some of the core bootstrap files do not have this
        imp_id, rest = text.split("MODULE-IDENTITY\n", 1)
        mod_id = imp_id.rsplit(None, 1)[1]

        rest = rest.split("::=", 1)[1]
        top_def, rest = rest.split("}", 1)
        top_def += "}"
        ret[mod_id.strip()] = parse_brace(top_def)
    return ret


def parse_object_types(text: str) -> dict:
    """Parse the OBJECT-TYPE macros"""
    object_types = {}
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
        if "AUGMENTS" in part:
            atext = part.split("AUGMENTS", 1)[1].split("}", 1)[0].strip() + "}"
            data["augments"] = atext
        if "DESCRIPTION" in part:
            raw_desc = part.split("DESCRIPTION")[1].split('"')[1]
            data["description"] = dedent_description(raw_desc)
        if "MAX-ACCESS" in part:
            data["access"] = part.split("MAX-ACCESS")[1].split("\n")[0].strip()
        if "DEFVAL" in part:
            defval = part.split("DEFVAL")[1].split("}", 1)[0].strip()
            data["defval"] = defval[1:].strip()
            LOGGER.debug("DEFVAL is %s",  defval[1:].strip())
        data["def"] = parse_brace(part.split("::=")[1].split("}", 1)[0] + "}")
        parent = data["def"][0]
        if parent in object_types and "index" in object_types[parent]:
            data["col"] = True
        else:
            data["col"] = False

        data["syntax"] = part.split("SYNTAX", 1)[1].split("MAX-ACCESS")[0].strip()
        data["table"] = "SEQUENCE" in data["syntax"]
        if data["table"]:
            entry = data["syntax"].split("OF")[1].strip()
            data["entry"] = entry
        if parent in object_types and object_types[parent]["table"]:
            if "index" not in data and "augments" not in data:
                LOGGER.warning("Table %s with neither INDEX nor AUGMENTS", oname)
        object_types[oname.strip()] = data
    return object_types


def mib_import(imp_mib: str, name_set: set, oids: dict, tcs: dict,
               object_types: dict, resolve: dict):
    """Process import"""
    builtins = {'TimeTicks', 'OBJECT-TYPE', 'Counter32', 'Gauge32',
                'NOTIFICATION-TYPE', 'Unsigned32', 'Counter64',
                'IpAddress', 'OBJECT-IDENTITY', "internet", "Counter",
                'Integer32', 'MODULE-IDENTITY', 'TEXTUAL-CONVENTION',
                'NOTIFICATION-GROUP', 'OBJECT-GROUP', 'MODULE-COMPLIANCE',
                'EntryStatus', 'OwnerString'
                }
    name_set = name_set.difference(builtins)
    if not name_set:  # Don't bother if we already know all the imports
        return
    imp_path = find_mib_file(imp_mib)
    if imp_path:
        with open(imp_path, "r", encoding="ascii") as nest:
            itext = strip_comments(nest.read())
            inner_oids = {}
            inner_types = {}
            parse_oids(itext, inner_oids)
            inner_tcs = parse_text_conventions(itext)
            for key, value in inner_oids.items():
                if key in name_set:
                    oids[key] = value
                    name_set.discard(key)
                parent, num = value
                if parent in resolve:
                    resolve[key] = resolve[parent].copy() + [num]
            for key, value in inner_tcs.items():
                if key in name_set:
                    tcs[key] = value
                    name_set.discard(key)
            if name_set:
                LOGGER.debug("Unresolved import(s) %s", name_set)
                LOGGER.debug("Try importing object types ")
                inner_types = parse_object_types(itext)
                for key, value in inner_types.items():
                    if key in name_set:
                        object_types[key] = value
                        name_set.discard(key)
                        LOGGER.debug("Found object type %s", key)
            inner_mod_id = parse_module_id(itext)
            for key, value in inner_mod_id.items():
                if key in name_set:
                    name_set.discard(key)
                    oids.update(inner_mod_id)
                    mod_parent, num = value
                    if mod_parent in resolve:
                        resolve[key] = resolve[mod_parent].copy() + [num]
            if name_set:
                iobjs = {}
                parse_obj_ident(itext, iobjs)
                for key, value in iobjs.items():
                    if key in name_set:
                        name_set.discard(key)
                        oids[key] = value
                    parent, num = value
                    if parent in resolve:
                        resolve[key] = resolve[parent].copy() + [num]
            if name_set:
                LOGGER.info("Unresolved import(s) %s for %s, recursing",
                            name_set, imp_mib)
                if "IMPORTS" in itext:
                    _, rest = itext.split("IMPORTS", 1)

                    imparts = rest.split("FROM")
                    for i, impart in enumerate(imparts[1:]):
                        previous = imparts[i]
                        names = [_.strip() for _ in previous.split(",")]
                        if i > 0:
                            names[0] = names[0].split()[-1]
                        LOGGER.debug("Import names %s", names)
                        in_name_set = set(names).intersection(name_set)
                        if in_name_set:
                            LOGGER.info("Trying nested import %s", in_imp_mib)
                            in_imp_mib = impart.split()[0].strip()
                            mib_import(in_imp_mib, in_name_set, oids, tcs,
                                       object_types, resolve)
            # Try a couple of cycles of resolution
            for name, data in inner_oids.items():
                parent, num = data
                if parent in resolve:
                    pval = resolve[parent].copy() + [num]
                    resolve[name] = pval
            for name, data_obj in inner_types.items():
                parent, num = data_obj["def"]
                if parent in resolve:
                    pval = resolve[parent].copy() + [num]
                    resolve[name] = pval
            for key, value in inner_mod_id.items():
                mod_parent, num = value
                if mod_parent in resolve:
                    resolve[key] = resolve[mod_parent].copy() + [num]
            if name_set:
                LOGGER.warning("Unresolved import(s) %s for %s",
                               name_set, imp_mib)
