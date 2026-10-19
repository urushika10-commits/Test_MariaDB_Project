"""
mitm_demo.py - run the man-in-the-middle attack twice and show what TLS
verification changes. Against our own server and a throwaway account only.

  Attack A - the client does NOT verify the certificate (PyMySQL's own default
             when you pass no CA). The impostor completes the handshake, sits in
             the path and can read every byte. THE ATTACK SUCCEEDS.
  Attack B - the client verifies against the real CA (our database.connect).
             It refuses the impostor's certificate before sending anything.
             THE ATTACK IS BLOCKED.

A quiet finding worth stating: even in attack A, PARSEC never hands the attacker
a reusable password - only a one-time signature crosses the wire. TLS protects
the channel and the queries; PARSEC protects the credential. Neither replaces
the other.

Run:  python attacks/mitm_demo.py   (needs the server up: make up)
"""

import ssl
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

import mitm_proxy  # noqa: E402
import pymysql  # noqa: E402
from parsec_auth import ParsecAuth  # noqa: E402

from admin import socket_sql  # noqa: E402
from database import CERTS_DIR, HOST, PORT, TRUSTED_CA, strong_password  # noqa: E402

PROXY_PORT = 3390
USER = "mitm_demo_user"
# The current run's credential. setup_account() fills it with a fresh random
# value every time: it lives only in this process, and the server's
# password_reuse_check (their finding 9) refuses any value seen before - so a
# fixed password would fail the second time the account is created.
STATE = {"password": None}


def setup_account():
    loaded = socket_sql("SELECT PLUGIN_NAME FROM information_schema.PLUGINS "
                        "WHERE PLUGIN_NAME = 'parsec' AND PLUGIN_STATUS = 'ACTIVE'")
    if not loaded:
        socket_sql("INSTALL SONAME 'auth_parsec'")
    STATE["password"] = strong_password()
    socket_sql("DROP USER IF EXISTS %s@'%%'", (USER,))
    socket_sql("CREATE USER %s@'%%' IDENTIFIED VIA parsec USING PASSWORD(%s)",
               (USER, STATE["password"]))
    socket_sql("GRANT SELECT ON university.courses TO %s@'%%'", (USER,))


def teardown_account():
    socket_sql("DROP USER IF EXISTS %s@'%%'", (USER,))


def run_proxy():
    result_box = {}
    t = threading.Thread(target=lambda: result_box.update(
        r=mitm_proxy.serve_once(PROXY_PORT, server_host=HOST, server_port=PORT)))
    t.start()
    return t, result_box


def attack_unverified():
    """Client with TLS but no verification -> impostor succeeds."""
    t, box = run_proxy()
    unverified = ssl.create_default_context()
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    reached_server = False
    try:
        con = pymysql.connect(host="localhost", port=PROXY_PORT, user=USER, password=STATE["password"],
                              database="university", ssl=unverified,
                              auth_plugin_map={"parsec": ParsecAuth})
        with con.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM courses")
            reached_server = cur.fetchone()[0] >= 0
        con.close()
    except Exception as exc:                       # noqa: BLE001 - report, do not hide
        print(f"  (unverified client error: {exc})")
    t.join()
    r = box["r"]
    ok = r.tls_to_client and reached_server and r.bytes_seen > 0
    print(f"  Attack A (client does NOT verify): "
          f"impostor in path={r.tls_to_client}, query reached the server={reached_server}, "
          f"bytes the attacker could read={r.bytes_seen}")
    print(f"    -> {'ATTACK SUCCEEDS - an impostor read the whole session' if ok else 'unexpected'}")
    return ok


def attack_verified():
    """Client verifies the real CA -> impostor refused."""
    t, box = run_proxy()
    refused = False
    try:
        con = pymysql.connect(host="localhost", port=PROXY_PORT, user=USER, password=STATE["password"],
                              database="university", ssl_ca=str(TRUSTED_CA),
                              ssl_verify_cert=True, ssl_verify_identity=True,
                              auth_plugin_map={"parsec": ParsecAuth})
        con.close()
    except pymysql.err.OperationalError:
        refused = True
    t.join()
    r = box["r"]
    ok = refused and r.blocked and not r.tls_to_client
    print(f"  Attack B (client verifies the CA): "
          f"client refused the impostor={refused}, impostor saw no TLS session={not r.tls_to_client}")
    print(f"    -> {'ATTACK BLOCKED - verification stopped the man in the middle' if ok else 'unexpected'}")
    return ok


def main():
    if not (CERTS_DIR / "proxy-cert.pem").is_file():
        print("No impostor certificate. Run 'make certs' first.")
        return 1
    print("Man-in-the-middle against MariaDB TLS (own server, throwaway account)\n")
    setup_account()
    try:
        a = attack_unverified()
        b = attack_verified()
    finally:
        teardown_account()
    print("\n  Lesson: TLS without verification is TLS to whoever answers. Only verification")
    print("  (ssl_verify_cert + ssl_verify_identity) ties the encrypted channel to OUR server.")
    both = a and b
    print(f"\nmitm_demo: {'2/2 as expected' if both else 'FAILED'}")
    return 0 if both else 1


if __name__ == "__main__":
    sys.exit(main())
