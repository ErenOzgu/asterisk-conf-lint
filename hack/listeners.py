#!/usr/bin/env python3
"""Print the local addresses that listen on a TCP port, one per line.

Reads /proc/net/tcp{,6}, so it needs no ss or netstat.
usage: listeners.py PORT
"""
import ipaddress
import sys

port = int(sys.argv[1])
found = set()
for path, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
    try:
        lines = open(path).read().splitlines()[1:]
    except OSError:
        continue
    for line in lines:
        fields = line.split()
        local, state = fields[1], fields[3]
        if state != "0A":  # LISTEN
            continue
        addr_hex, port_hex = local.rsplit(":", 1)
        if int(port_hex, 16) != port:
            continue
        raw = bytes.fromhex(addr_hex)
        if v6:
            # /proc stores each 32-bit word in host byte order
            raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
            ip = ipaddress.IPv6Address(raw)
            ip = ip.ipv4_mapped or ip
            text = str(ip) if ip.version == 4 else f"[{ip}]"
        else:
            text = str(ipaddress.IPv4Address(raw[::-1]))
        found.add(f"{text}:{port}")
print("\n".join(sorted(found)))
