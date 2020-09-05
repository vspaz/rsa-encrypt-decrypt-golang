# rsa-encrypt-decrypt-golang

Generating test public/private RSA key-pair.

- openssl genrsa -out private.pem 2048
- openssl rsa -in private.pem -out public.pem -pubout -outform PEM
