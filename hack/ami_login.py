#!/usr/bin/env python3
"""Try an AMI login and print "accepted" or "rejected".

usage: ami_login.py USER SECRET [SOURCE_ADDRESS]

SOURCE_ADDRESS (for example 127.0.0.2) lets the test connect from another
loopback address, to see whether an ACL really lets it in or keeps it out.
"""
import socket
import sys

user, secret = sys.argv[1], sys.argv[2]
source = (sys.argv[3], 0) if len(sys.argv) > 3 else None

s = socket.create_connection(("127.0.0.1", 5038), timeout=5, source_address=source)
s.recv(256)  # banner
s.sendall(f"Action: Login\r\nUsername: {user}\r\nSecret: {secret}\r\nEvents: off\r\n\r\n".encode())
reply = b""
while b"\r\n\r\n" not in reply:
    chunk = s.recv(1024)
    if not chunk:
        break
    reply += chunk
print("accepted" if b"Response: Success" in reply else "rejected")
