"""Guest-side network-policy probe with two independent signals.

The two questions are deliberately separate commands: a denied DNS lookup must
never be able to masquerade as TLS enforcement, and a refused TLS flow must
never be able to masquerade as a DNS failure.

    policy_probe.py dns <name>             -> ok:<addr> | nxdomain
    policy_probe.py tls <ip> <port> <sni>  -> ok:<status> | refused

`tls` dials the given IP literal with the given SNI and never resolves the name,
so its answer depends on the SNI decision alone.

`ok:<status>` means the flow was admitted: the request completed and reached an
HTTP status line, whichever status that is. `refused` means it was not: the
connection, the handshake, or the response never completed. A readable policy
denial served by the gateway (`ok:403`) is therefore a completed request, not a
refusal, and a scenario that wants resets must disable denial responses.
"""

import socket
import ssl
import sys

TIMEOUT_SECONDS = 15


def dns(name):
    """Answer one name through the guest resolver (the engine's DNS forwarder)."""
    try:
        answers = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        print("nxdomain")
        return
    print("ok:" + answers[0][4][0])


def tls(ip, port, sni):
    """Dial the literal IP with this SNI; report the HTTP status or `refused`."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    # Upstream verification has its own tests; this probe asks one question:
    # was the flow admitted at all?
    context.verify_mode = ssl.CERT_NONE
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_SECONDS)
    try:
        sock.connect((ip, int(port)))
        stream = context.wrap_socket(sock, server_hostname=sni)
        try:
            request = (
                "GET /probe HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n" % sni
            )
            stream.sendall(request.encode())
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = stream.recv(4096)
                if not chunk:
                    break
                response += chunk
            if not response.startswith(b"HTTP/"):
                print("refused")
                return
            print("ok:" + response.split(b" ", 2)[1].decode())
        finally:
            stream.close()
    # ssl.SSLError and socket timeouts are OSError subclasses too, so a connection
    # that never completed reports the same `refused` answer as one that reset.
    # A status line, once reached, is reported as `ok:<status>` above.
    except (OSError, IndexError, ValueError):
        print("refused")
    finally:
        sock.close()


def main(argv):
    if len(argv) == 2 and argv[0] == "dns":
        dns(argv[1])
        return
    if len(argv) == 4 and argv[0] == "tls":
        tls(argv[1], argv[2], argv[3])
        return
    sys.exit("usage: policy_probe.py dns <name> | tls <ip> <port> <sni>")


if __name__ == "__main__":
    main(sys.argv[1:])
