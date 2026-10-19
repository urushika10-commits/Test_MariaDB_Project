"""
work_factor.py - how much does one stolen credential cost an attacker to test?

The threat: an attacker steals the stored authentication value (mysql.global_priv
or mysql.user) and tries passwords OFFLINE, on their own hardware, with no server
to rate-limit or lock them out. The only defence left is the cost of deriving one
candidate's stored value and the per-account salt. This measures that cost for the
three formats MariaDB offers, on THIS machine, so the README can say why PARSEC is
the right choice and what the weaker formats leak.

It never touches a real account: it derives stored values for passwords it makes up
itself, exactly as MariaDB computes them (all three formulas verified against a live
13.1.1 server), and times the derivation. The output is derivations per second
(= guesses per second an attacker gets) with mean and standard deviation over
several runs, plus what that means for a known-size search.

Run:  python benchmarks/work_factor.py          (add --help for options)
"""

import argparse
import hashlib
import secrets
import statistics
import time

from nacl import bindings
from nacl.signing import SigningKey

# --- the three stored formats, each verified against MariaDB 13.1.1 -------------


def native_stored(password):
    """mysql_native_password: *UPPER(SHA1(SHA1(password))). Unsalted, two SHA-1s."""
    if isinstance(password, str):
        password = password.encode()
    return "*" + hashlib.sha1(hashlib.sha1(password).digest()).hexdigest().upper()


def _clamp(s32):
    b = bytearray(s32)
    b[0] &= 248
    b[31] = (b[31] & 127) | 64
    return bytes(b)


def ed25519_stored(password):
    """ed25519: public key of the scalar clamp(SHA512(password)[:32]). Unsalted."""
    if isinstance(password, str):
        password = password.encode()
    s = _clamp(hashlib.sha512(password).digest()[:32])
    return bindings.crypto_scalarmult_ed25519_base_noclamp(s)


def parsec_stored(password, salt, iterations=1024):
    """PARSEC: ed25519 public key whose seed is PBKDF2-HMAC-SHA512. Salted and iterated.

    The seed is the 32-byte PBKDF2 output; the ed25519 public key is derived from it
    the standard way (as MariaDB stores it), which is what nacl's SigningKey does.
    """
    if isinstance(password, str):
        password = password.encode()
    seed = hashlib.pbkdf2_hmac("sha512", password, salt, iterations, 32)
    return bytes(SigningKey(seed).verify_key)


# --- measuring the cost of one guess --------------------------------------------


def _candidates(n):
    """A fixed set of made-up candidate passwords (never a real wordlist)."""
    return [f"candidate-{i:08d}" for i in range(n)]


def guesses_per_second(derive, n):
    """Time deriving the stored value for n candidates; return guesses/second."""
    cands = _candidates(n)
    start = time.perf_counter()
    for c in cands:
        derive(c)
    elapsed = time.perf_counter() - start
    return n / elapsed


def measure(derive, n, runs):
    """Repeat the measurement `runs` times; return (mean, stdev) guesses/second."""
    rates = [guesses_per_second(derive, n) for _ in range(runs)]
    stdev = statistics.stdev(rates) if len(rates) > 1 else 0.0
    return statistics.mean(rates), stdev


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--native-n", type=int, default=200_000,
                    help="candidates per run for the fast hashes (default 200000)")
    ap.add_argument("--parsec-n", type=int, default=2_000,
                    help="candidates per run for PARSEC - it is much slower (default 2000)")
    ap.add_argument("--runs", type=int, default=5, help="repetitions (default 5)")
    ap.add_argument("--iterations", type=int, default=1024,
                    help="PARSEC iterations to test (default 1024, the server default)")
    args = ap.parse_args()

    salt = secrets.token_bytes(18)
    print(f"machine guess-rate, mean +/- sd over {args.runs} runs\n")
    results = []

    for name, derive, n in [
        ("mysql_native_password (SHA-1 x2, no salt)", native_stored, args.native_n),
        ("ed25519 (SHA-512 -> curve, no salt)", ed25519_stored, args.native_n),
        (f"PARSEC (PBKDF2-SHA512 x{args.iterations}, salted)",
         lambda pw: parsec_stored(pw, salt, args.iterations), args.parsec_n),
    ]:
        mean, sd = measure(derive, n, args.runs)
        results.append((name, mean, sd))
        print(f"  {name:48s} {mean:14,.0f} +/- {sd:>10,.0f}  guesses/s")

    fast = results[0][1]
    slow = results[-1][1]
    print(f"\n  Native is ~{fast / slow:,.0f}x faster to attack than PARSEC per guess.")
    print("  Caveat: the ed25519 figure reflects PyMySQL's pure-Python curve code, not an")
    print("  optimised attacker (who derives ed25519 keys far faster); treat the native row")
    print("  as the representative fast-hash rate. ed25519's real weakness is below: no salt.")

    # The controllable knob: PARSEC iterations. Measured on one code path, so this
    # scaling is honest (no cross-library artifact). Doubling iterations halves the
    # attacker's rate, and the server lets you raise it with one setting.
    print("\n  PARSEC iteration scaling (salted; guesses/s falls ~linearly with iterations):")
    for iters in (1024, 4096, 16384, 65536):
        mean, sd = measure(lambda pw, it=iters: parsec_stored(pw, salt, it),
                           max(args.parsec_n // (iters // 1024), 200), args.runs)
        print(f"    {iters:>7,} iterations (P{iters.bit_length() - 11})"
              f"   {mean:10,.0f} +/- {sd:>8,.0f}  guesses/s")

    # The salt point, shown not just asserted: same password, two accounts, two values.
    s1, s2 = secrets.token_bytes(18), secrets.token_bytes(18)
    same = parsec_stored("same-password-123", s1) != parsec_stored("same-password-123", s2)
    print(f"\n  Per-account salt: same password -> different stored value: {same}.")
    print("  So a stolen PARSEC value must be attacked on its own - no table reused across")
    print("  accounts. The unsalted formats (native, ed25519) store one value per password,")
    print("  so one precomputed table covers every account that ever used that password.")


if __name__ == "__main__":
    main()
