import sys
from hashlib import sha1

LEN = 1048576 # Size of expanded key


def localise_key(password: bytes, engine_id: bytes) -> bytes:
    "Apply RFC3414 key derivation AKA localisation"
    pwlen = len(password)

    cnt = LEN // pwlen
    bit = LEN % pwlen
    big = cnt * password + password[:bit]
    m = sha1()
    m.update(big)

    d = m.digest()[:20]
    #print(m.hexdigest())
    k2 = d + engine_id + d
    m1 = sha1()
    m1.update(k2)
    return m1.hexdigest()

if len(sys.argv) not in [3, 4]:
    print("Usage:\npython3 usekey.py <username> <password> [<password2>]")
    sys.exit(1)

username = sys.argv[1]
password = sys.argv[2].encode()
password2 = sys.argv[3].encode() if len(sys.argv) == 4 else password
# engine_id = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'
engine_id = b"\x80\x00\x4e\x2c\x03\x34\x48\xed\x2d\xe2\x88"

print(username, "sha1", localise_key(password, engine_id),
      "aes", localise_key(password2, engine_id))