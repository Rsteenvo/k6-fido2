#!/usr/bin/env bash
docker run -d -p 8877:8080 --restart=always --name device-services-test-crypto-service device-services-test-crypto-service:latest
