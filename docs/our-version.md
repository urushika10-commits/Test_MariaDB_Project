# Our pair's version: PARSEC as primary, and attacks with measured results

This branch (`pair-b`) builds on the shared base and adds the three things the
first version did not do. Everything here runs with one command:

```bash
make attack      # PARSEC role demo + the stolen-hash work factor + the MITM
```

and each part has its own target (`make parsec`, `make benchmark`, `make mitm`)
and integration tests (`make test`). Captured output is in
[attack-output.txt](attack-output.txt), [benchmark-output.txt](benchmark-output.txt),
[parsec-demo-output.txt](parsec-demo-output.txt) and [mitm-output.txt](mitm-output.txt).

## 1. PARSEC authentication, in pure Python

The area brief names PARSEC as one of the authentication methods. The first
version skipped it, because PyMySQL cannot speak PARSEC and the C connector needs
a compiler. We implemented the PARSEC client protocol ourselves
([app/parsec_auth.py](../app/parsec_auth.py)) and plugged it into PyMySQL, so a
PARSEC account logs in through the ordinary verified-TLS path.

Verified against MariaDB 13.1.1, the stored value is
`P<exponent>:<base64 salt>:<base64 ed25519 public key>`, the client key is
`PBKDF2-HMAC-SHA512(password, salt, 2**(10+exponent), 32 bytes)`, and the login
signs `server_scramble || client_scramble` with that ed25519 key. The server
stores only the public key; the password never crosses the wire.

**PARSEC is a drop-in for the whole access-control model, not just a login toy.**
[app/parsec_demo.py](../app/parsec_demo.py) stands up a PARSEC account for each of
the four roles and runs the exact six-action role matrix from the ed25519 demo:

```
PARSEC role demo: 24/24 actions behaved as expected (identical to the ed25519 matrix).
```

including the professor's `DENY` on `financial_records` (error 1142). So the
roles and `DENY` do not depend on which authentication method is used. We keep
ed25519 as the documented comparison rather than removing it, so its findings
(the unix_socket enumeration oracle, the stolen-public-key test, the password
policy behaviour) still stand.

## 2. What a stolen credential costs an attacker (the real reason PARSEC wins)

If the stored value is stolen, the attacker tries passwords offline, with no
server to rate-limit them. The only defence left is the cost of deriving one
candidate and the per-account salt. [benchmarks/work_factor.py](../benchmarks/work_factor.py)
measures that cost for all three formats - deriving stored values for made-up
candidate passwords exactly as MariaDB does (all three formulas verified against
13.1.1), never touching a real account - and reports guesses/second as mean ±
standard deviation over five runs.

| Stored format | Guesses/second (one machine) | Notes |
|---|---|---|
| `mysql_native_password` (SHA-1 ×2, no salt) | ~2,200,000 | unsalted; one table attacks every account |
| ed25519 (SHA-512 → curve, no salt) | ~7,600 (see caveat) | unsalted; same password → same stored value |
| **PARSEC** (PBKDF2-SHA512 ×1024, salted) | **~3,300** | **salted and iterated; ~680× slower than native** |

PARSEC's iteration count is a knob the server controls (`parsec_iterations`), and
the cost scales with it, measured on one code path:

| Iterations | Guesses/second |
|---|---|
| 1,024 (default) | ~3,100 |
| 4,096 | ~1,230 |
| 16,384 | ~345 |
| 65,536 | ~87 |

Two honest points recorded in the output:

* The ed25519 figure reflects PyMySQL's pure-Python curve code, not an optimised
  attacker (who derives ed25519 keys far faster). Treat the **native** row as the
  representative fast-hash rate; ed25519's real weakness is that it is **unsalted**.
* PARSEC's per-account salt means the same password stores a different value for
  each account, so no precomputed table can be reused. The unsalted formats store
  one value per password, so a single table covers every account that ever used it.

## 3. A real man-in-the-middle against TLS

The first version demonstrated the impostor by pointing a client at a wrong CA.
We put a real attacker **in the path**: [attacks/mitm_proxy.py](../attacks/mitm_proxy.py)
is a MySQL-aware, TLS-terminating proxy that speaks enough of MariaDB's
STARTTLS handshake to upgrade each leg, presents an impostor certificate (the
right host name `localhost`, signed by the untrusted CA), and relays the
decrypted session while counting the bytes it can read.

[attacks/mitm_demo.py](../attacks/mitm_demo.py) runs it twice against our own
server and a throwaway PARSEC account:

| Client | Result |
|---|---|
| does **not** verify the certificate (PyMySQL's own default with no CA) | impostor completes TLS and reads ~578 bytes of the session — **attack succeeds** |
| verifies against the real CA (`ssl_verify_cert` + `ssl_verify_identity`) | client refuses the impostor before sending anything — **attack blocked** |

The lesson: TLS without verification is TLS to whoever answers. Only verification
ties the encrypted channel to our server.

One finding worth stating: even over a successful MITM, PARSEC never hands the
attacker a reusable password — only a one-time signature crosses the wire. TLS
protects the channel and the queries; PARSEC protects the credential. Neither
replaces the other.

## Which control stops which attack (our additions)

| Attack | Stopped by | Evidence |
|---|---|---|
| Offline guessing of a stolen credential | PARSEC's salt + PBKDF2 iterations | `benchmarks/work_factor.py`, `test_parsec_auth.py` |
| Rainbow table reused across accounts | PARSEC per-account salt | `work_factor.py` (same password → different value) |
| Impostor server in the path reading the session | verified TLS (`ssl_verify_cert` + identity) | `attacks/mitm_demo.py`, `test_mitm.py` |
| Reading forbidden data under PARSEC auth | roles + `DENY`, unchanged by the auth method | `app/parsec_demo.py`, `test_parsec_roles.py` |

## Reproducibility fixes (so a fresh clone actually runs)

Also on this branch, so the grader's "reproducible on a fresh server" check passes
on a clean machine:

* base image moved to the official `mariadb:13.1.1-rc` (the pinned quay preview
  build no longer resolves on arm64);
* `generate_certs.sh` no longer uses an OpenSSL-3-only flag that fails on the
  LibreSSL shipped with macOS;
* the Makefile picks the first Python ≥3.10 instead of the bare `python3` (macOS
  ships 3.9);
* a stale filename reference in the compose comment was corrected.
