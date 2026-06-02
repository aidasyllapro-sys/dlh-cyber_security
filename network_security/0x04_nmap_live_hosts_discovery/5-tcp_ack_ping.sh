#!/bin/bash
sudo nmap -PA22,80,443 -sA $1
