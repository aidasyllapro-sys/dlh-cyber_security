#!/bin/bash
# Retrieve all DNS records for a domain
dig $1 ANY +noall +answer
