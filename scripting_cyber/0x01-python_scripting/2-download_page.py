#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup


def download_page(url):
    try:
        response = requests.get(url)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        return soup.prettify()

    except requests.exceptions.RequestException as e:
        return str(e)
