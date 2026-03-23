.PHONY: build test clean

# Build the custom k6 binary with the fido2 extension
build:
	xk6 build --with github.com/rsteenvo/k6-fido2=.

# Build for local development
build-local:
	xk6 build --with xk6-fido2=.

# Run tests
test:
	go test -v ./...

# Run the simple example (requires built k6 binary)
run-simple:
	./k6 run examples/simple.js

# Run the full example (requires built k6 binary and a WebAuthn server)
run-example:
	./k6 run examples/test.js

# Clean build artifacts
clean:
	rm -f k6

# Tidy dependencies
tidy:
	go mod tidy

# Format code
fmt:
	go fmt ./...

# Lint code
lint:
	golangci-lint run
