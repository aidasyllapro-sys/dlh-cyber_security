#!/bin/bash
subfinder -silent -d $1 | while read sub; do nslookup $sub | awk -v h=$sub '/^Address: / {print h "," $2}' ; done > $1.txt
