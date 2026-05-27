#!/bin/bash
nslookup -type=A $1 | grep 'Address:' | tail -n +3 | awk '{print $2}'
