"""
Server-free checks of the PARSEC client (app/parsec_auth.py).

These test the pure protocol functions - key derivation, ext-salt parsing and
the signed response - against values the real server produced, so they run in
CI without Docker. The live login is covered by the integration tests.
"""

import base64

import parsec_auth as pa
import pytest
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

# A public test vector: what MariaDB 13.1.1 stored for a throwaway account, and
# the (now meaningless) input that produced it. The account never existed outside
# the spike; only the server's own derivation is being checked here.
#   stored: P<exponent>:<base64 salt>:<base64 ed25519 public key>
VECTOR = {
    "input": "Parsec-Pass-123",
    "stored": "P0:X5EatassaOn1WzVnnUhuOCL6:s3F09cjLJRbwLY4F0+xzIDmr5d4kjlbFo0Kily9F3Io",
}
PASSWORD_INPUT = VECTOR["input"]


def _b64(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _parts():
    exp, salt, pub = VECTOR["stored"].split(":")
    return pa.iterations_from_exponent(int(exp[1:], 36)), _b64(salt), _b64(pub)


def test_exponent_to_iterations():
    assert pa.iterations_from_exponent(0) == 1024
    assert pa.iterations_from_exponent(8) == 262144


def test_derived_public_key_matches_the_server():
    iterations, salt, pub = _parts()
    assert pa.public_key(PASSWORD_INPUT, salt, iterations) == pub


def test_wrong_password_derives_a_different_key():
    iterations, salt, pub = _parts()
    assert pa.public_key("not the password", salt, iterations) != pub


def test_ext_salt_round_trip():
    iterations, salt, _ = _parts()
    ext = b"P" + bytes([0]) + salt
    assert pa.parse_ext_salt(ext) == (1024, salt)


def test_ext_salt_rejects_garbage():
    with pytest.raises(ValueError):
        pa.parse_ext_salt(b"not parsec")


def test_client_response_is_a_valid_signature():
    iterations, salt, pub = _parts()
    server_scramble = bytes(range(32))
    client_scramble = bytes(range(32, 64))
    ext = b"P" + bytes([0]) + salt
    resp = pa.client_response(PASSWORD_INPUT, server_scramble, ext, client_scramble)
    assert resp[:32] == client_scramble
    # The server verifies the signature over (server scramble || client scramble)
    # with the stored public key; do the same here.
    VerifyKey(pub).verify(server_scramble + client_scramble, resp[32:])


def test_a_forged_response_is_rejected():
    iterations, salt, pub = _parts()
    ext = b"P" + bytes([0]) + salt
    resp = pa.client_response("wrong password", bytes(32), ext, bytes(32))
    with pytest.raises(BadSignatureError):
        VerifyKey(pub).verify(bytes(32) + bytes(32), resp[32:])
