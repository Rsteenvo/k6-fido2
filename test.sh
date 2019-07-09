#!/usr/bin/env bash

# Grab the b64-urlsafe-encoded signature and id from the server
getresponse=$(curl -s -X GET http://localhost:8080/data)
reqid=$(echo ${getresponse} | jq '.id')
echo ${getresponse} | jq '.data' | sed s/\"//g > client.data.b64

# b64-decode it to binary
base64 -D client.data.b64 > client.data.bin

# Get the SHA256 Hash (it's output as a hex string)
shasum -a 256 -b client.data.bin | cut -d ' ' -f1 > client.sha256.hexstring

# Get the binary representation of the pure hex
xxd -r -p client.sha256.hexstring > client.sha256.bin

# b64-encode it, in a URL-safe manner - which shell tool can NOT do on its own
b64hash=$(base64 client.sha256.bin | sed s/=//g | sed s/+/-/g | sed "s|/|_|g" | tr -d '\n')
echo ${b64hash} > client.sha256.b64

# Check the hash with the server
curl -s -X POST \
     --header "Content-Type: application/json" \
     --data '{ "id": '${reqid}', "hash": "'${b64hash}'" }' \
      http://localhost:8080/data/hash

echo

# Generate ECDSA key pair (DER format)
openssl ecparam -genkey -name secp384r1 -outform der -out client.private.der.bin -noout
openssl ec -inform der -in client.private.der.bin -pubout -outform der -out client.public.der.bin

# Generate signature (DER format)
openssl pkeyutl -sign -keyform der -inkey client.private.der.bin -in client.sha256.bin -out client.signature.der.bin

# b64-encode the signature
b64sig=$(base64 client.signature.der.bin | sed s/=//g | sed s/+/-/g | sed "s|/|_|g" | tr -d '\n')
echo ${b64sig} > client.signature.der.b64

# b64-encode the public key
b64pubkey=$(base64 client.public.der.bin | sed s/=//g | sed s/+/-/g | sed "s|/|_|g" | tr -d '\n')

# Check the signature with the server
curl -s -X POST \
     --header "Content-Type: application/json" \
     --data '{ "id": '${reqid}', "signature": "'${b64sig}'", "publicKey": "'${b64pubkey}'", "signatureAlgorithm": "ALG_SIGN_SECP256_R1_ECDSA_SHA256_DER" }' \
      http://localhost:8080/data/signature

echo
