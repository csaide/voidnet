#!/bin/bash

SCRIPT_DIR=$(dirname $0)

openssl genpkey -algorithm ED25519 -out ${SCRIPT_DIR}/server.key.pem
openssl req -new -x509 -days 3650 -nodes -sha256 -out ${SCRIPT_DIR}/server.crt.pem -key ${SCRIPT_DIR}/server.key.pem -config ${SCRIPT_DIR}/server.cnf -extensions v3_req
