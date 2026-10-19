"""
parsec_demo.py - prove the whole access-control model works under PARSEC.

Version 1 authenticates the demo accounts with ed25519 and keeps a thorough
set of ed25519 findings. This demonstrates that PARSEC - MariaDB 13.1's newer
authentication plugin, which ed25519 cannot match on a stolen-hash attack
(benchmarks/work_factor.py) - is a drop-in for the SAME roles and the SAME
DENY: it stands up a PARSEC account for each of the four roles, logs in over
verified TLS with our pure-Python PARSEC client, and runs the exact six-action
role matrix from demo.py. Every result must match the ed25519 demo, including
the professor's DENY on financial_records.

It creates its accounts through socket root, gives each a fresh random password
(kept only in memory; the server's reuse check forbids repeats), and drops them
at the end. ed25519 stays the project's documented comparison; this shows the
access-control model does not depend on which of the two is used.

Run:  python app/parsec_demo.py        (needs the server up: make up)
"""

import sys

import pymysql

from admin import socket_sql
from database import connect, strong_password
from demo import ACTION_ORDER, ALLOW, DESCRIPTIONS, POLICY, perform, show_session

# role name -> the PARSEC account we create for it
ROLES = {
    "student": "student_role",
    "professor": "professor_role",
    "finance": "finance_role",
    "admin": "admin_role",
}
ACCOUNT = {role: f"{role}_parsec" for role in ROLES}


def ensure_parsec_installed():
    loaded = socket_sql("SELECT PLUGIN_NAME FROM information_schema.PLUGINS "
                        "WHERE PLUGIN_NAME = 'parsec' AND PLUGIN_STATUS = 'ACTIVE'")
    if not loaded:
        socket_sql("INSTALL SONAME 'auth_parsec'")


def create_accounts():
    """One PARSEC account per role; returns {role: password} (in memory only)."""
    ensure_parsec_installed()
    passwords = {}
    for role, role_name in ROLES.items():
        account = ACCOUNT[role]
        password = strong_password()
        socket_sql("DROP USER IF EXISTS %s@'%%'", (account,))
        socket_sql("CREATE USER %s@'%%' IDENTIFIED VIA parsec USING PASSWORD(%s)",
                   (account, password))
        # role_name is a fixed identifier from ROLES (never user input); the
        # account is still bound as a %s parameter, escaped like PyMySQL does.
        socket_sql(f"GRANT {role_name} TO %s@'%%'", (account,))
        socket_sql(f"SET DEFAULT ROLE {role_name} FOR %s@'%%'", (account,))
        passwords[role] = password
    return passwords


def drop_accounts():
    for account in ACCOUNT.values():
        socket_sql("DROP USER IF EXISTS %s@'%%'", (account,))


def run_role(role, password):
    """Run the six actions as the PARSEC account for `role`; return FAIL count."""
    account = ACCOUNT[role]
    print()
    print("=" * 78)
    print(f" ROLE: {role}   (PARSEC account: {account})")
    print("=" * 78)
    connection = connect(account, password)
    show_session(connection)

    failures = 0
    for number, action in enumerate(ACTION_ORDER, start=1):
        expected, why = POLICY[action][role]
        try:
            sql, rows = perform(connection, action)
            actual = f"{ALLOW} ({len(rows)} rows)" if sql.startswith("SELECT") else ALLOW
            got_allowed = True
        except pymysql.MySQLError as error:
            actual = f"denied (error {error.args[0]})"
            got_allowed = False
        passed = got_allowed == expected.startswith(ALLOW) and (got_allowed or "1142" in actual)
        failures += not passed
        print(f"[{number}/6] {DESCRIPTIONS[action]:<16} expected {expected:<18} "
              f"got {actual:<22} {'PASS' if passed else 'FAIL'}")
    connection.close()
    return failures


def main():
    print("PARSEC role demo - the same model as the ed25519 demo, authenticated with PARSEC\n")
    try:
        passwords = create_accounts()
        try:
            failures = sum(run_role(role, passwords[role]) for role in ROLES)
        finally:
            drop_accounts()
    except pymysql.MySQLError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    total = len(ROLES) * len(ACTION_ORDER)
    print(f"\nPARSEC role demo: {total - failures}/{total} actions behaved as expected "
          "(identical to the ed25519 matrix).")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
