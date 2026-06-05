#!/usr/bin/env python3

import sys
check_port = __import__("5-port_scanner").check_port

if len(sys.argv) != 3:
    print("Usage: python3 5-main.py <host> <port>")
    sys.exit(1)

host = sys.argv[1]
port = int(sys.argv[2])

status = "OPEN" if check_port(host, port) else "CLOSED"
print(f"Port {port} on {host}: {status}")
