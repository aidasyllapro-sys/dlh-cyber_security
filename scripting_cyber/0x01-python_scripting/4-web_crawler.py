#!/usr/bin/env python3
"""
Module de web crawling récursif.
Explore les liens internes d'un site jusqu'à une profondeur maximale.
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def _crawl(url, max_depth, visited):
    """Fonction récursive interne."""
    if max_depth < 0:
        return visited

    if url in visited:
        return visited

    try:
        print(f"Crawling: {url}")
        response = requests.get(url, timeout=5)
        visited.add(url)

        soup = BeautifulSoup(response.text, 'html.parser')
        base_domain = urlparse(url).netloc

        for tag in soup.find_all('a', href=True):
            absolute_url = urljoin(url, tag['href'])
            link_domain = urlparse(absolute_url).netloc

            if link_domain == base_domain:
                _crawl(absolute_url, max_depth - 1, visited)

    except requests.exceptions.ConnectionError:
        pass

    except requests.exceptions.InvalidURL:
        pass

    except requests.exceptions.Timeout:
        pass

    except Exception:
        pass

    return visited


def crawl_website(start_url, max_depth=2):
    """
    Crawle récursivement un site web jusqu'à max_depth niveaux.

    Args:
        start_url (str): L'URL de départ
        max_depth (int): Profondeur maximale de crawling (défaut: 2)

    Returns:
        set: Ensemble des URLs visitées appartenant au même domaine
    """
    visited = set()
    return _crawl(start_url, max_depth, visited)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 4-web_crawler.py <url> [max_depth]")
        sys.exit(1)
    url = sys.argv[1]
    depth = int(sys.argv[2]) if len(sys.argv) == 3 else 2
    result = crawl_website(url, depth)
    print(f"\nTotal pages crawled: {len(result)}")
