#!/usr/bin/env python3

import sys
crawl_website = __import__("4-web_crawler").crawl_website

if len(sys.argv) < 2:
    print("Usage: python3 4-main.py <url> [max_depth]")
    sys.exit(1)

start_url = sys.argv[1]
max_depth = int(sys.argv[2]) if len(sys.argv) == 3 else 2

print("=" * 50)
print(f"Starting crawl of {start_url} (max depth: {max_depth})")
print("=" * 50)

visited = crawl_website(start_url, max_depth)

for url in sorted(visited):
    print(url)

print("\nTotal pages crawled:", len(visited))
