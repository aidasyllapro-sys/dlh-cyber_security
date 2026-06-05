#!/usr/bin/env python3
"""
Module pour récupérer les headers HTTP d'une URL.
Utilise la bibliothèque requests.
"""
import requests


def get_http_headers(url):
    """
    Récupère les headers HTTP d'une URL.

    Args:
        url (str): L'URL cible (ex: "https://www.google.com")

    Returns:
        dict: {'status_code': int, 'headers': dict} si succès
        None: si la requête échoue
    """
    try:
        response = requests.get(url)
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers)
        }

    except requests.exceptions.RequestException:
        return None


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 3-http_headers.py <url>")
        sys.exit(1)
    result = get_http_headers(sys.argv[1])
    print(result)
