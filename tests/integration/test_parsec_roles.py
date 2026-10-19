"""
The access-control model under PARSEC (app/parsec_demo.py).

Proves PARSEC is a drop-in for ed25519: the same four roles, logged in with
PARSEC over verified TLS, give the same six-action matrix - including the
professor's DENY on financial_records. Needs the server.
"""

import pymysql
import pytest
from parsec_demo import ACCOUNT, ROLES, create_accounts, drop_accounts

from admin import socket_sql
from database import connect
from demo import ACTION_ORDER, ALLOW, POLICY, perform


@pytest.fixture
def parsec_accounts():
    passwords = create_accounts()
    yield passwords
    drop_accounts()


def test_all_four_roles_authenticate_with_parsec(parsec_accounts):
    for role in ROLES:
        # The server records the account's auth plugin as 'parsec' (checked as root).
        plugin = socket_sql("SELECT plugin FROM mysql.user WHERE user = %s", (ACCOUNT[role],))
        assert plugin == ["parsec"], f"{ACCOUNT[role]} is {plugin}, not parsec"
        # And it really logs in with PARSEC over verified TLS (the connection proves it).
        con = connect(ACCOUNT[role], parsec_accounts[role])
        with con.cursor() as cur:
            cur.execute("SHOW SESSION STATUS LIKE 'Ssl_version'")
            assert cur.fetchone()[1].startswith("TLS")
        con.close()


def test_role_matrix_is_identical_under_parsec(parsec_accounts):
    for role in ROLES:
        con = connect(ACCOUNT[role], parsec_accounts[role])
        for action in ACTION_ORDER:
            expected, _ = POLICY[action][role]
            try:
                sql, rows = perform(con, action)
                allowed = True
            except pymysql.MySQLError as error:
                allowed = False
                assert error.args[0] == 1142, f"{role}/{action}: unexpected error {error.args[0]}"
            assert allowed == expected.startswith(ALLOW), f"{role}/{action} mismatch"
        con.close()


def test_professor_deny_on_financial_holds_under_parsec(parsec_accounts):
    con = connect(ACCOUNT["professor"], parsec_accounts["professor"])
    with con.cursor() as cur, pytest.raises(pymysql.err.OperationalError) as exc:
        cur.execute("SELECT * FROM financial_records")
    assert exc.value.args[0] == 1142      # DENY beats the professor's university.* grant
    con.close()
