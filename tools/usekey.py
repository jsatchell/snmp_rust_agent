"""Utility to bootstrap password file"""
import sys
import ipaddress
from hashlib import sha1   # , sha224, sha256, sha384, sha512

LEN = 1048576  # Size of expanded key


def eid_from_str(text: str) -> bytes:
    """Parse engine ID string and return as bytes.

    Exits if parse not possible.
    """
    parts = text.split(" ", 2)
    ent = int(parts[0]).to_bytes(4, "big")
    if parts[1] == "Static":
        assert len(parts[2]) == 16
        return ent + bytes.fromhex(parts[2])
    ent = (ent[0] | 0x80).to_bytes(1) + ent[1:]
    if parts[1] == "1":  # IPv4
        addr = ipaddress.IPv4Address(parts[2])
        return ent + b"\x01" + int(addr).to_bytes(4, "big")
    if parts[1] == "2":  # IPv6
        addr = ipaddress.IPv6Address(parts[2])
        return ent + b"\x02" + int(addr).to_bytes(16, "big")
    if parts[1] == "3":  # MAC Address
        assert len(parts[2]) == 17
        bits = parts[2].split(":")
        assert len(bits) == 6
        mac_bytes = b"".join(bytes.fromhex(_) for _ in bits)
        return ent + b"\x03" + mac_bytes
    if parts[1] == "4":
        return ent + b"\x04" + parts[2].encode("utf-8")
    if parts[1] == "5":
        return ent + b"\x05" + bytes.fromhex(parts[2])
    sys.exit(8)


def get_engine_id(path: str) -> bytes:
    """Parse the config file for EngineID definition and return it as bytes.

    Exits if definition not found.
    """
    with open(path, "r", encoding="utf-8") as conf:
        for line in conf:
            parts = line.split(" ", 1)
            if parts[0] == "EngineID":
                return eid_from_str(parts[1].strip())
    sys.exit(7)


def localise_key(pass_word: bytes, engine_id: bytes,
                 hasher=sha1, trunc=20) -> bytes:
    "Apply RFC3414 key derivation AKA localization. This is the SHA1 version."
    pwlen = len(pass_word)

    cnt = LEN // pwlen
    bit = LEN % pwlen
    big = cnt * pass_word + pass_word[:bit]
    m = hasher()
    m.update(big)

    d = m.digest()[:trunc]
    k2 = d + engine_id + d
    m1 = hasher()
    m1.update(k2)
    return m1.hexdigest()


if len(sys.argv) not in [4, 5]:
    print("Usage:\npython3 usekey.py <group> <user> <password> [<password2>]")
    print("<group> should be a group name in groups.txt")
    sys.exit(1)

group = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3].encode()
password2 = sys.argv[4].encode() if len(sys.argv) == 5 else password
# engine_id = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'
# ENGINE_ID = b"\x80\x00\x4e\x2c\x03\x34\x48\xed\x2d\xe2\x88"
conf_engine_id = get_engine_id(".snmp-agent.conf")


print(username, group, "sha1", localise_key(password, conf_engine_id),
      "aes", localise_key(password2, conf_engine_id))
