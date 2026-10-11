#!/bin/sh
set -eu
out=${1:?usage: gen-certs.sh <dir>}
mkdir -p "$out"
cd "$out"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
  -subj /CN=vsu-test-ca -keyout ca.key -out ca.pem \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -subj /CN=vault-0.test -keyout tls.key -out tls.csr 2>/dev/null
printf 'subjectAltName=DNS:vault-0.test,DNS:vault-1.test,DNS:vault-2.test,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > ext.cnf
openssl x509 -req -in tls.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out tls.pem 2>/dev/null
rm -f tls.csr ext.cnf ca.srl ca.key
chmod 0644 ca.pem tls.pem tls.key
