"""Guest-side egress probes for the refusal-log end-to-end tests.

Each subcommand asks one question and prints one machine-readable answer, so a
refusal record can be paired with the outcome the guest actually observed:

    refusal_probe.py dns <name>
        -> ok:<addr> | nxdomain
    refusal_probe.py tcp <ip> <port>
        -> ok | refused
    refusal_probe.py udp <ip> <port> <count>
        -> sent:<count>
    refusal_probe.py udp-flood <ip> <port> <stop-path> <summary-path> <max-seconds>
        -> (prints nothing; writes `sent:<n> elapsed:<seconds>` to <summary-path>)

`dns` goes through the guest resolver (the engine's DNS forwarder), so a denial
there is the forwarder's synthetic NXDOMAIN, not a name that merely does not
exist.

`udp-flood` sends datagrams as fast as it can until <stop-path> exists or its
time budget runs out, then writes its own totals. The caller — not the guest —
decides how long the flood runs, which is what lets a test prove that a probe
really happened while the flood was still going.
"""

import os
import socket
import sys
import time

TIMEOUT_SECONDS = 2


def dns(name):
    """Answer one name through the guest resolver."""
    try:
        answers = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        print("nxdomain")
        return
    print("ok:" + answers[0][4][0])


def tcp(ip, port):
    """Report whether a TCP connection completed."""
    try:
        socket.create_connection((ip, int(port)), TIMEOUT_SECONDS).close()
    except OSError:
        print("refused")
        return
    print("ok")


def udp(ip, port, count):
    """Report how many datagrams were handed to the guest stack."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    try:
        for _ in range(int(count)):
            try:
                sock.sendto(b"refusal-probe", (ip, int(port)))
                sent += 1
            except OSError:
                pass
    finally:
        sock.close()
    print("sent:%d" % sent)


def udp_flood(ip, port, stop_path, summary_path, max_seconds):
    """Send until the stop file appears, then report the totals.

    The stop file is checked every 64 datagrams: often enough that the flood
    ends promptly when the caller asks, cheap enough that it does not change
    what the datagram rate measures.
    """
    budget = float(max_seconds)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    started = time.monotonic()
    sent = 0
    try:
        while time.monotonic() - started < budget:
            try:
                sock.sendto(b"refusal-flood", (ip, int(port)))
                sent += 1
            except OSError:
                pass
            if sent % 64 == 0 and os.path.exists(stop_path):
                break
    finally:
        sock.close()
    with open(summary_path, "w") as summary:
        summary.write("sent:%d elapsed:%.3f" % (sent, time.monotonic() - started))


def main(argv):
    if len(argv) == 2 and argv[0] == "dns":
        dns(argv[1])
        return
    if len(argv) == 3 and argv[0] == "tcp":
        tcp(argv[1], argv[2])
        return
    if len(argv) == 4 and argv[0] == "udp":
        udp(argv[1], argv[2], argv[3])
        return
    if len(argv) == 6 and argv[0] == "udp-flood":
        udp_flood(argv[1], argv[2], argv[3], argv[4], argv[5])
        return
    sys.exit(
        "usage: refusal_probe.py dns <name> | tcp <ip> <port> "
        "| udp <ip> <port> <count> "
        "| udp-flood <ip> <port> <stop-path> <summary-path> <max-seconds>"
    )


if __name__ == "__main__":
    main(sys.argv[1:])
