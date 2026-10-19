# MariaDB 13.1 auth & access-control cheat-sheet

The patterns this project demonstrates, on one page, copy-paste ready. Full explanation in the
[README](../README.md); run everything with `make demo`.

## Roles and privileges

```sql
CREATE ROLE professor_role;
GRANT SELECT ON university.* TO professor_role;            -- grant broadly...
DENY  SELECT ON university.financial_records TO professor_role;  -- ...then subtract (MariaDB 13.1)
GRANT UPDATE (grade) ON university.grades TO professor_role;     -- column-level privilege

GRANT professor_role TO 'smith_professor'@'%';             -- give the role to a user
SET DEFAULT ROLE professor_role FOR 'smith_professor'@'%'; -- activate it at every login
```

* **`DENY` beats every `GRANT`**, at any level, in any order. Only `REVOKE DENY` at the **exact** level lifts it.
* A role is inactive until `SET DEFAULT ROLE` (or `SET ROLE`); `SET ROLE NONE` can shed a role-attached DENY.
* See a role's effective rights: `SHOW GRANTS FOR professor_role;`

## Authentication (no password in a config file)

```sql
INSTALL SONAME 'auth_ed25519';   -- or 'auth_parsec'
CREATE USER 'alice'@'%'  IDENTIFIED VIA ed25519 USING PASSWORD('…');   -- server stores a public key only
CREATE USER 'bob'@'%'    IDENTIFIED VIA parsec  USING PASSWORD('…');   -- salted + PBKDF2 (hard to crack)
-- root inside the container, no password at all:
ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket OR ed25519 USING '<unusable key>';
CREATE USER 'harness'@'%' IDENTIFIED VIA ed25519 USING PASSWORD('…') REQUIRE X509;  -- also needs a client cert
```

| Method | Stored on the server | Beats a stolen-hash attack? |
|---|---|---|
| `mysql_native_password` | SHA-1×2 of the password (password-equivalent) | no (unsalted, ~2.4M guesses/s) |
| `ed25519` | a public key | partly (unsalted; same password → same value) |
| `parsec` | salted PBKDF2 → public key | **yes** (~700× slower than native; tune with `parsec_iterations`) |
| `unix_socket` | nothing - the OS user is the credential | n/a (no secret to steal) |

## Verified, required TLS

```ini
# server (docker-compose command:)
--ssl-cert=… --ssl-key=… --ssl-ca=… --tls-version=TLSv1.2,TLSv1.3 --require-secure-transport=ON
```
```python
# client (PyMySQL): encrypt AND verify - not just encrypt
pymysql.connect(..., ssl_ca="certs/ca.pem", ssl_verify_cert=True, ssl_verify_identity=True)
```
"SSL on by default" gives encryption but **not** verification and does not require TLS (`make zerotls`).
Verification is what stops an impostor server (`make mitm`).

## Error codes you will see

| Code | Meaning |
|---|---|
| 1045 | login refused (wrong/empty password, or account does not exist) |
| 1142 | command denied on a table/database (a `DENY` or a missing `GRANT`) |
| 1143 | column-level privilege denied |
| 1370 | routine execute denied |
| 1819 / 1396 | password policy / reuse refused (`SET PASSWORD` vs `ALTER USER`) |
| 3159 | connection refused: TLS required (`require_secure_transport=ON`) |
| 4151 | account is locked |

## Commands

`make demo` (everything) · `make test` (278 tests) · `make shell` (root, no password) ·
`make set-password USER=…` then `make sql USER=…` (log in by hand) · `make attack` (PARSEC + work factor + MITM) ·
`make lockout` / `make zerotls` (disposable-server experiments).
