# Device Services - Test Crypto Service
This is a web application designed to help with cryptographic operations during functional integration testing,
particularly when using Postman which does not currently appear to have an up-to-date crpytographic library available.

To run app use the following command
`mvn spring-boot:run`

The application will listen on port 8080.

Swagger documentation can then be found at http://localhost:8080/swagger-ui.html

This should be sufficient to explain how to use the API:
* Get some data
* Post the base64-encoded raw SHA-256 hash of that data back to the server for verification.
* Post the ECDSA signature, base64-encoded raw or DER, of that data, along with the public key and algorithm, 
back to the server for verification.
  * The public key must be an EC-generated public key in base64-encoded DER format.
  * The algorithm must be specified as per the FIDO spec:
    * _ALG_SIGN_SECP256_R1_ECDSA_SHA256_RAW_
    * _ALG_SIGN_SECP256_R1_ECDSA_SHA256_DER_
* Generate ECC key pairs and store them under an alias
* Sign some data using a previously-created key pair
* Generate FIDO UAF registration responses and authentication responses, given the key pair alias, signature algorithm,
and UAF request.

# Docker
To build a Docker image, firstly build the application using
`mvn clean install`
Then run the `build-docker.sh` script

To run a container from the image, run the `run-docker.sh` script
This will start a container running the application, binding to port 8877 on the local machine.