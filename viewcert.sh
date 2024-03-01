#!/usr/bin/env bash

if [ -z "$1" ]; then
  echo "Usage: $0 <certificate>"
  exit 1
fi

openssl x509 -in "$1" -text -noout
