"""
The man-in-the-middle attack, as a test (attacks/mitm_proxy.py + mitm_demo.py).

Confirms, against the real server, that an impostor in the path succeeds only
while the client does not verify the certificate, and is refused the moment it
does. Needs the server; skipped automatically by the unit run.
"""

import ssl
import sys
import threading
from pathlib import Path

import pymysql
import pytest

ATTACKS = Path(__file__).resolve().parent.parent.parent / "attacks"
sys.path.insert(0, str(ATTACKS))

import mitm_proxy  # noqa: E402
from mitm_demo import PROXY_PORT, STATE, USER, setup_account, teardown_account  # noqa: E402
from parsec_auth import ParsecAuth  # noqa: E402

from database import HOST, PORT, TRUSTED_CA  # noqa: E402


@pytest.fixture
def demo_account():
    setup_account()
    yield
    teardown_account()


def _proxy_thread():
    box = {}
    t = threading.Thread(target=lambda: box.update(
        r=mitm_proxy.serve_once(PROXY_PORT, server_host=HOST, server_port=PORT)))
    t.start()
    return t, box


def test_unverified_client_is_intercepted(demo_account):
    t, box = _proxy_thread()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    con = pymysql.connect(host="localhost", port=PROXY_PORT, user=USER, password=STATE["password"],
                          database="university", ssl=ctx,
                          auth_plugin_map={"parsec": ParsecAuth})
    with con.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM courses")
        cur.fetchone()
    con.close()
    t.join()
    r = box["r"]
    assert r.tls_to_client is True          # the impostor completed TLS with the client
    assert r.bytes_seen > 0                  # and was positioned to read the session


def test_verified_client_refuses_the_impostor(demo_account):
    t, box = _proxy_thread()
    with pytest.raises(pymysql.err.OperationalError):
        pymysql.connect(host="localhost", port=PROXY_PORT, user=USER, password=STATE["password"],
                        database="university", ssl_ca=str(TRUSTED_CA),
                        ssl_verify_cert=True, ssl_verify_identity=True,
                        auth_plugin_map={"parsec": ParsecAuth})
    t.join()
    r = box["r"]
    assert r.blocked is True                 # the client refused the impostor
    assert r.tls_to_client is False          # no session reached the attacker
