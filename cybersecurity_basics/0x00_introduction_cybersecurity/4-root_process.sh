#!/bin/bash
ps aux | grep -v " 0  *0 " | grep ^$1
