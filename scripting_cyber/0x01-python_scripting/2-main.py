#!/usr/bin/env python3
import sys

download_page = __import__("2-download_page").download_page

if len(sys.argv) != 2:
    print("Usage: python3 2-main.py <url>")
    sys.exit(1)

url = sys.argv[1]

print(f"\nPage content from {url}:")
print("=" * 50)

content = download_page(url)
print(content)

print("=" * 50)
print(f"Content length: {len(content)} characters")
