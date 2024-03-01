#!/usr/bin/env bash

set -euo pipefail

mkdir -p keys/signing
rm -f keys/signing/*


# Key one
#########

# Generate RSA Private Key and CSR for leaf certificate
echo "== Generating RSA Private Key and CSR for leaf certificate =="
openssl req -nodes -newkey rsa:4096 -sha256 -keyout keys/signing/one-i1.pem \
  -out keys/signing/one-i1.csr -subj "/CN=leaf1.example.com"

# Sign leaf CSR with RSA keypair of intermediate cert
echo "== Signing the CSR with the intermediate CA key =="
openssl x509 -req -days 1 -CA keys/ca/intermediate-1.crt -CAkey keys/ca/intermediate-1.private.pem \
  -CAcreateserial -extfile openssl-ca.cnf -extensions server_cert \
  -in keys/signing/one-i1.csr -out keys/signing/one-i1.crt

# Delete csr as no longer needed
rm keys/signing/one-i1.csr

# Validate certificate.crt
echo "== Validating certificate against intermediate certificate =="
openssl verify -CAfile keys/ca/intermediate-1-chain.crt keys/signing/one-i1.crt


# Key two
#########

# Generate RSA Private Key and CSR for leaf certificate
echo ""
echo "== Generating RSA Private Key and CSR for leaf certificate =="
openssl req -nodes -newkey rsa:4096 -sha256 -keyout keys/signing/two-ai1.pem \
  -out keys/signing/two-ai1.csr -subj "/CN=another-leaf2.example.com"

# Sign leaf CSR with RSA keypair of intermediate cert
echo ""
echo "== Signing the CSR with the intermediate CA key =="
openssl x509 -req -days 1 -CA keys/ca/another-intermediate-1.crt -CAkey keys/ca/another-intermediate-1.private.pem \
  -CAcreateserial -extfile openssl-ca.cnf -extensions server_cert \
  -in keys/signing/two-ai1.csr -out keys/signing/two-ai1.crt

# Delete csr as no longer needed
rm keys/signing/two-ai1.csr

# Validate certificate.crt
echo ""
echo "== Validating certificate against intermediate certificate =="
openssl verify -CAfile keys/ca/another-intermediate-2-chain.crt keys/signing/two-ai1.crt


echo "== Done =="

