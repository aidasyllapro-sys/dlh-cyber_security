#!/bin/bash
nslookup -type=A $1 | grep 'Address:' | awk '{print $2}'
