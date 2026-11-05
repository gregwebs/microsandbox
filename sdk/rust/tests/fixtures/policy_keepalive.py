"""Guest-side keep-alive client for a live network-policy replace.

Opens one TLS connection, sends request 1, and then waits for a gate file that
the test creates only *after* the replace has returned. Request 2 then goes out
on that same socket, so a success proves an already-admitted connection keeps
running rather than that a new connection was admitted.

Statuses are written to files, not stdout, so the test can poll them over the
guest filesystem while the client is still running:

    first:<status>   after request 1 (the test's "connection is live" marker)
    second:<status>  after request 2, sent through the gate
    error:<Type>     instead of `second`, when the client failed

Usage: policy_keepalive.py <ip> <port> <sni> <ready> <gate> <second>
"""

import os
import socket
import ssl
import sys
import time

TIMEOUT_SECONDS = 30
# 2400 * 50 ms = 120 s of waiting for the gate. The test uses that window to
# replace the policy twice and run four guest probes, each of which may sit on
# its own socket timeout while the flow is refused.
GATE_POLLS = 2400
GATE_INTERVAL_SECONDS = 0.05


def write(path, text):
    with open(path, "w") as handle:
        handle.write(text + "\n")


def request(stream, path, host):
    """Send one GET and return its status code from a Content-Length response."""
    stream.sendall(
        (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n\r\n" % (path, host)
        ).encode()
    )
    return read_response(stream)


def read_response(stream):
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = stream.recv(4096)
        if not chunk:
            raise EOFError("connection closed in response headers")
        raw += chunk
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1])
    length = 0
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(body) < length:
        chunk = stream.recv(4096)
        if not chunk:
            raise EOFError("connection closed in response body")
        body += chunk
    return status


def wait_for_gate(path):
    for _ in range(GATE_POLLS):
        if os.path.exists(path):
            return True
        time.sleep(GATE_INTERVAL_SECONDS)
    return False


def run(ip, port, sni, ready, gate, second):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    # Upstream verification has its own tests; this client asks only whether an
    # admitted connection keeps working across a policy replace.
    context.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_SECONDS)
    try:
        sock.connect((ip, int(port)))
        stream = context.wrap_socket(sock, server_hostname=sni)
        try:
            first = request(stream, "/one", sni)
            write(ready, "first:%d" % first)
            if not wait_for_gate(gate):
                raise TimeoutError("gate file never appeared")
            # Same socket, same TLS session: request 2 must not be an implicit
            # reconnect, and the sandbox's policy has been replaced by now.
            second_status = request(stream, "/two", sni)
            write(second, "second:%d" % second_status)
        finally:
            stream.close()
    finally:
        sock.close()


def main(argv):
    if len(argv) != 6:
        sys.exit("usage: policy_keepalive.py <ip> <port> <sni> <ready> <gate> <second>")
    ip, port, sni, ready, gate, second = argv
    try:
        run(ip, port, sni, ready, gate, second)
    except Exception as error:  # reported to the test through these files
        write(second, "error:" + type(error).__name__)
        if not os.path.exists(ready):
            write(ready, "error:" + type(error).__name__)
        raise


if __name__ == "__main__":
    main(sys.argv[1:])
