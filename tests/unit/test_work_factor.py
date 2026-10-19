"""
Server-free checks of the work-factor benchmark's derivations
(benchmarks/work_factor.py). Each stored-format formula is pinned to a value a
real MariaDB 13.1.1 server produced, so the benchmark measures the true cost of
an offline guess rather than an approximation. Also covers the timing helpers.
"""

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "benchmarks"))

import work_factor as wf  # noqa: E402


def _b64(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


def test_native_matches_the_server():
    # *CE776D7... is what 13.1.1 stored for this password with mysql_native_password.
    assert wf.native_stored("Native-Pass-123") == "*CE776D7ACEBA6BDB7A272D79AC88598FBFC09E9D"


def test_ed25519_matches_the_server():
    # base64 of the ed25519 public key 13.1.1 stored for this password.
    expected = _b64("rJDS/yGjQHz7X4wUt2+3sil+MpTgKqt7pxUX9+LAemI")
    assert wf.ed25519_stored("Ed-Pass-12345") == expected


def test_parsec_matches_the_server():
    # P0:<salt>:<pubkey> for this password on 13.1.1 (salt from that stored value).
    salt = _b64("X5EatassaOn1WzVnnUhuOCL6")
    expected = _b64("s3F09cjLJRbwLY4F0+xzIDmr5d4kjlbFo0Kily9F3Io")
    assert wf.parsec_stored("Parsec-Pass-123", salt, 1024) == expected


def test_a_wrong_password_derives_a_different_value():
    salt = _b64("X5EatassaOn1WzVnnUhuOCL6")
    expected = _b64("s3F09cjLJRbwLY4F0+xzIDmr5d4kjlbFo0Kily9F3Io")
    assert wf.parsec_stored("not the password", salt, 1024) != expected


def test_more_iterations_is_strictly_slower_per_guess():
    # The security knob: raising iterations lowers the attacker's guess rate.
    fast, _ = wf.measure(lambda pw: wf.parsec_stored(pw, b"0123456789abcdefgh", 1024), 60, 2)
    slow, _ = wf.measure(lambda pw: wf.parsec_stored(pw, b"0123456789abcdefgh", 8192), 60, 2)
    assert slow < fast


def test_guesses_per_second_is_positive():
    rate = wf.guesses_per_second(wf.native_stored, 1000)
    assert rate > 0
