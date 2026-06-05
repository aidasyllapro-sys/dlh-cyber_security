#!/usr/bin/env python3
"""
Module pour vérifier si un port est ouvert sur un hôte.
Utilise le module socket de la bibliothèque standard Python.
"""
import socket


def check_port(host, port):
    """
    Vérifie si un port TCP est ouvert sur un hôte.

    Args:
        host (str): L'hôte cible (ex: "scanme.nmap.org")
        port (int): Le numéro de port à tester (ex: 80)

    Returns:
        True si le port est ouvert
        False si le port est fermé ou inaccessible
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0

    except Exception:
        return False


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 5-port_scanner.py <host> <port>")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    status = "OPEN" if check_port(host, port) else "CLOSED"
    print(f"Port {port} on {host}: {status}")
