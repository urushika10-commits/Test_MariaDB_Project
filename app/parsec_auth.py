"""
parsec_auth.py - the client side of MariaDB's PARSEC authentication, in pure Python.

PyMySQL has no PARSEC support and the C-based connector needs a compiler, so we
implement the protocol ourselves and plug it into PyMySQL's auth_plugin_map:

    pymysql.connect(..., auth_plugin_map={"parsec": ParsecAuth})

The exchange (verified against MariaDB 13.1.1):

  1. server -> client  auth switch to "parsec" + a 32-byte random server scramble
  2. client -> server  an empty packet: "send me the ext-salt"
  3. server -> client  ext-salt = b"P" + iteration exponent + 18-byte salt
  4. client -> server  32-byte random client scramble + ed25519 signature over
                       (server scramble || client scramble)
  5. server -> client  OK, or error 1045

The signing key is never sent and never stored on the server. It is derived on
the client:   seed = PBKDF2-HMAC-SHA512(password, salt, 2**(10 + exponent), 32 bytes)
The server stores only the matching ed25519 PUBLIC key (mysql.global_priv):
    P<exponent>:<base64 salt>:<base64 public key>

Pure functions (derive_seed, parse_ext_salt, client_response) are separate from
the network code so the unit tests can check them without a server.
"""

import hashlib
import secrets

from nacl.signing import SigningKey

SCRAMBLE_LEN = 32
SALT_LEN = 18
BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def iterations_from_exponent(exponent):
    """PARSEC stores log2(iterations) - 10, so 0 -> 1024, 8 -> 262144."""
    return 1 << (exponent + 10)


def parse_ext_salt(ext_salt):
    """Split the server's ext-salt packet into (iterations, salt).

    Byte 0 names the KDF ('P' = PBKDF2-SHA512). Byte 1 is the iteration exponent;
    we accept both the raw byte and its base62 character, whichever the server sends.
    """
    if len(ext_salt) < 2 + SALT_LEN or ext_salt[0:1] != b"P":
        raise ValueError(f"not a PARSEC ext-salt: {ext_salt!r}")
    raw = ext_salt[1]
    exponent = BASE62.index(chr(raw)) if chr(raw) in BASE62 else raw
    return iterations_from_exponent(exponent), ext_salt[2:2 + SALT_LEN]


def derive_seed(password, salt, iterations):
    """The ed25519 private seed both sides agree on (only the client computes it)."""
    if isinstance(password, str):
        password = password.encode()
    return hashlib.pbkdf2_hmac("sha512", password, salt, iterations, 32)


def public_key(password, salt, iterations):
    """What the server stores for this password: used by tests and by crack_bench."""
    return bytes(SigningKey(derive_seed(password, salt, iterations)).verify_key)


def client_response(password, server_scramble, ext_salt, client_scramble=None):
    """Step 4 of the exchange: client scramble (32 bytes) + signature (64 bytes)."""
    iterations, salt = parse_ext_salt(ext_salt)
    if client_scramble is None:
        client_scramble = secrets.token_bytes(SCRAMBLE_LEN)
    key = SigningKey(derive_seed(password, salt, iterations))
    signature = key.sign(server_scramble[:SCRAMBLE_LEN] + client_scramble).signature
    return client_scramble + signature


class ParsecAuth:
    """PyMySQL auth plugin handler for 'parsec' (see auth_plugin_map above)."""

    def __init__(self, con):
        self.con = con

    def authenticate(self, pkt):
        server_scramble = pkt.read_all()[:SCRAMBLE_LEN]
        if len(server_scramble) != SCRAMBLE_LEN:
            raise ValueError("PARSEC: server scramble has the wrong length")
        self.con.write_packet(b"")                      # step 2: ask for the ext-salt
        ext = self.con._read_packet()
        ext.check_error()
        ext_salt = ext.read_all()
        if ext_salt[:1] == b"\x01":                      # "extra auth data" marker
            ext_salt = ext_salt[1:]
        self.con.write_packet(client_response(self.con.password, server_scramble, ext_salt))
        result = self.con._read_packet()
        result.check_error()                             # wrong password -> 1045 here
        return result
