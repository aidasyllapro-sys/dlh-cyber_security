#!/usr/bin/env python3
"""
Module de web crawling récursif.
Explore les liens internes d'un site jusqu'à une profondeur maximale.
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl_website(start_url, max_depth=2, visited=None):
    """
    Crawle récursivement un site web jusqu'à max_depth niveaux.

    Args:
        start_url (str): L'URL de départ
        max_depth (int): Profondeur maximale de crawling (défaut: 2)
        visited (set): URLs déjà visitées (évite les boucles infinies)

    Returns:
        set: Ensemble des URLs visitées appartenant au même domaine
    """
    # Initialiser le set à la première appel
    if visited is None:
        visited = set()

    # Condition d'arrêt 1 : profondeur maximale atteinte
    if max_depth < 0:
        return visited

    # Condition d'arrêt 2 : URL déjà visitée
    if start_url in visited:
        return visited

    try:
        print(f"Crawling: {start_url}")

        # Télécharger la page
        response = requests.get(start_url, timeout=5)

        # Marquer cette URL comme visitée
        visited.add(start_url)

        # Parser le HTML
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extraire le domaine de base pour rester sur le même site
        base_domain = urlparse(start_url).netloc

        # Trouver tous les liens <a href="...">
        for tag in soup.find_all('a', href=True):

            # Convertir les liens relatifs en absolus
            # ex: "/about" -> "https://example.com/about"
            absolute_url = urljoin(start_url, tag['href'])

            # Extraire le domaine du lien trouvé
            link_domain = urlparse(absolute_url).netloc

            # Ne crawler que les liens du même domaine
            if link_domain == base_domain:

                # Appel récursif avec profondeur diminuée de 1
                crawl_website(absolute_url, max_depth - 1, visited)

    except requests.exceptions.ConnectionError:
        pass

    except requests.exceptions.InvalidURL:
        pass

    except requests.exceptions.Timeout:
        pass

    except Exception:
        pass

    return visited

