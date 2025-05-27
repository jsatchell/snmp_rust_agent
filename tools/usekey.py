"""Utility to bootstrap password file"""
import sys
from hashlib import sha1, sha224, sha256, sha384, sha512

LEN = 1048576  # Size of expanded key


def localise_key(pass_word: bytes, engine_id: bytes, hasher=sha1, trunc=20) -> bytes:
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
    print("Usage:\npython3 usekey.py <group> <username> <password> [<password2>]")
    print("<group> should be a group name in groups.txt")
    sys.exit(1)

group = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3].encode()
password2 = sys.argv[4].encode() if len(sys.argv) == 5 else password
# engine_id = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'
ENGINE_ID = b"\x80\x00\x4e\x2c\x03\x34\x48\xed\x2d\xe2\x88"

print(username, group, "sha1", localise_key(password, ENGINE_ID),
      "aes", localise_key(password2, ENGINE_ID))
