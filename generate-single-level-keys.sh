#!/usr/bin/env bash

set -euo pipefail

# create private RSA key
openssl genpkey -algorithm RSA -out keys/private.key -pkeyopt rsa_keygen_bits:2048

# create public key from private.key
openssl rsa -pubout -in keys/private.key -out keys/public.key

