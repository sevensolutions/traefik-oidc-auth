#!/bin/bash

set -e

# Output directories
ROOT_CA_DIR="certificates/root_ca"
INTERMEDIATE_CA_DIR="certificates/intermediate_ca"
WEBSITE_CERT_DIR="certificates/website_cert"
BUNDLE_DIR="certificates/bundle"

# Remove existing directories
rm -rf $ROOT_CA_DIR $INTERMEDIATE_CA_DIR $WEBSITE_CERT_DIR $BUNDLE_DIR

mkdir -p $ROOT_CA_DIR $INTERMEDIATE_CA_DIR $WEBSITE_CERT_DIR $BUNDLE_DIR

# Root CA
ROOT_KEY="$ROOT_CA_DIR/rootCA.key"
ROOT_CERT="$ROOT_CA_DIR/rootCA.pem"

openssl genrsa -out $ROOT_KEY 4096
openssl req -x509 -new -nodes -key $ROOT_KEY -sha256 -days 3650 -out $ROOT_CERT -subj "/C=US/ST=California/L=San Francisco/O=Root CA/OU=Certificate Authority/CN=Root CA"

echo "Root CA created: $ROOT_CERT"

# Intermediate CA
INTERMEDIATE_KEY="$INTERMEDIATE_CA_DIR/intermediateCA.key"
INTERMEDIATE_CSR="$INTERMEDIATE_CA_DIR/intermediateCA.csr"
INTERMEDIATE_CERT="$INTERMEDIATE_CA_DIR/intermediateCA.pem"

openssl genrsa -out $INTERMEDIATE_KEY 4096
openssl req -new -key $INTERMEDIATE_KEY -out $INTERMEDIATE_CSR -subj "/C=US/ST=California/L=San Francisco/O=Intermediate CA/OU=Certificate Authority/CN=Intermediate CA"

openssl x509 -req -in $INTERMEDIATE_CSR -CA $ROOT_CERT -CAkey $ROOT_KEY -CAcreateserial -out $INTERMEDIATE_CERT -days 3650 -sha256 \
    -extfile <(printf "basicConstraints=CA:TRUE\nkeyUsage=keyCertSign,cRLSign")

echo "Intermediate CA created: $INTERMEDIATE_CERT"

# Bundle file (Root CA + Intermediate CA)
BUNDLE_FILE="$BUNDLE_DIR/ca_bundle.pem"
cat $INTERMEDIATE_CERT $ROOT_CERT > $BUNDLE_FILE
echo "CA bundle created: $BUNDLE_FILE"

# Website Certificate
WEBSITE_KEY="$WEBSITE_CERT_DIR/website.key"
WEBSITE_CSR="$WEBSITE_CERT_DIR/website.csr"
WEBSITE_CERT="$WEBSITE_CERT_DIR/website.pem"

openssl genrsa -out $WEBSITE_KEY 2048
openssl req -new -key $WEBSITE_KEY -out $WEBSITE_CSR -subj "/C=US/ST=California/L=San Francisco/O=Example Website/OU=IT Department/CN=localhost"

openssl x509 -req -in $WEBSITE_CSR -CA $INTERMEDIATE_CERT -CAkey $INTERMEDIATE_KEY -CAcreateserial -out $WEBSITE_CERT -days 825 -sha256 \
    -extfile <(printf "subjectAltName=DNS:localhost,DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")

echo "Website certificate created: $WEBSITE_CERT"

# Summary
cat <<EOF
Certificates created successfully:
- Root CA:         $ROOT_CERT
- Intermediate CA: $INTERMEDIATE_CERT
- Website Cert:    $WEBSITE_CERT
- CA Bundle:       $BUNDLE_FILE
EOF
