#!/usr/bin/env python3

import socket

def resolve_domain_to_ipv4(domain_name):
    try:
        return socket.gethostbyname(domain_name)
    except socket.gaierror:
        return None
    except Exception as e:
        return str(e)
