#!/usr/bin/env python3
import sys

get_http_headers = __import__("3-http_headers").get_http_headers

if len(sys.argv) != 2:
    print("Usage: python3 3-main.py <url>")
    sys.exit(1)

url = sys.argv[1]

result = get_http_headers(url)

if result is None:
    print(f"Error: Could not retrieve headers from {url}")
    sys.exit(1)

print(f"HTTP Headers for: {url}")
print("=" * 50)
print(f"Status Code: {result['status_code']}")
print("Headers:")
print()

for key, value in result['headers'].items():
    print(f"  {key}: {value}")
