#!/usr/bin/env bash

set -euo pipefail

mkdir -p keys/ca
rm -f keys/ca/*

# Generate root CA
echo "== Generate root certificate =="
openssl req -x509 -nodes -newkey rsa:4096 -days 365 -config openssl-ca.cnf \
    -sha256 -keyout keys/ca/root-ca.private.pem -out keys/ca/root-ca.crt \
    -subj "/CN=root.example.com"


echo "== Generate another root certificate =="
openssl req -x509 -nodes -newkey rsa:4096 -days 365 -config openssl-ca.cnf \
    -sha256 -keyout keys/ca/another-root-ca.private.pem -out keys/ca/another-root-ca.crt \
    -subj "/CN=another-root.example.com"



# Generate intermediate-1
#########################

# Create private key and CSR
openssl req -nodes -newkey rsa:4096 -sha256 -keyout keys/ca/intermediate-1.private.pem \
  -out keys/ca/intermediate-1.csr -subj "/CN=intermediate-1.example.com"

# Sign CSR with root key
openssl x509 -req -days 60 -CA keys/ca/root-ca.crt -CAkey keys/ca/root-ca.private.pem \
  -CAcreateserial -extfile openssl-ca.cnf -extensions ca_cert \
  -in keys/ca/intermediate-1.csr -out keys/ca/intermediate-1.crt

# Delete csr as no longer needed
rm keys/ca/intermediate-1.csr

# Create chain file
cat keys/ca/intermediate-1.crt keys/ca/root-ca.crt > keys/ca/intermediate-1-chain.crt


# Generate intermediate-2
#########################

# Create private key and CSR
openssl req -nodes -newkey rsa:4096 -sha256 -keyout keys/ca/intermediate-2.private.pem \
  -out keys/ca/intermediate-2.csr -subj "/CN=intermediate-2.example.com"

# Sign CSR with root key
openssl x509 -req -days 60 -CA keys/ca/root-ca.crt -CAkey keys/ca/root-ca.private.pem \
  -CAserial keys/ca/root-ca.srl -extfile openssl-ca.cnf -extensions ca_cert \
  -in keys/ca/intermediate-2.csr -out keys/ca/intermediate-2.crt

# Delete csr as no longer needed
rm keys/ca/intermediate-2.csr

# Create chain file
cat keys/ca/intermediate-2.crt keys/ca/root-ca.crt > keys/ca/intermediate-2-chain.crt


# Generate another-intermediate-1
#################################

# Create private key and CSR
openssl req -nodes -newkey rsa:4096 -sha256 -keyout keys/ca/another-intermediate-1.private.pem \
  -out keys/ca/another-intermediate-1.csr -subj "/CN=another-intermediate-1.example.com"

# Sign CSR with root key
openssl x509 -req -days 60 -CA keys/ca/another-root-ca.crt -CAkey keys/ca/another-root-ca.private.pem \
  -CAcreateserial -extfile openssl-ca.cnf -extensions ca_cert \
  -in keys/ca/another-intermediate-1.csr -out keys/ca/another-intermediate-1.crt

# Delete csr as no longer needed
rm keys/ca/another-intermediate-1.csr

# Create chain file
cat keys/ca/another-intermediate-1.crt keys/ca/another-root-ca.crt > keys/ca/another-intermediate-1-chain.crt


# Generate another-intermediate-2
#################################

# Create private key and CSR
openssl req -nodes -newkey rsa:4096 -sha256 -keyout keys/ca/another-intermediate-2.private.pem \
  -out keys/ca/another-intermediate-2.csr -subj "/CN=another-intermediate-2.example.com"

# Sign CSR with root key
openssl x509 -req -days 60 -CA keys/ca/another-root-ca.crt -CAkey keys/ca/another-root-ca.private.pem \
  -CAserial keys/ca/another-root-ca.srl -extfile openssl-ca.cnf -extensions ca_cert \
  -in keys/ca/another-intermediate-2.csr -out keys/ca/another-intermediate-2.crt

# Delete csr as no longer needed
rm keys/ca/another-intermediate-2.csr

# Create chain file
cat keys/ca/another-intermediate-2.crt keys/ca/another-root-ca.crt > keys/ca/another-intermediate-2-chain.crt


# Validate certificate.crt against root_cert/certificate.crt
openssl verify -CAfile keys/ca/root-ca.crt keys/ca/intermediate-1.crt
openssl verify -CAfile keys/ca/root-ca.crt keys/ca/intermediate-2.crt
openssl verify -CAfile keys/ca/another-root-ca.crt keys/ca/another-intermediate-1.crt
openssl verify -CAfile keys/ca/another-root-ca.crt keys/ca/another-intermediate-2.crt

ls -l keys/ca
