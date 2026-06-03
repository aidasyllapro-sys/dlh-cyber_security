#!/bin/bash
nmap -PA22,80,443 -sn $1
