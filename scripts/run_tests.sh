#!/bin/bash

# Run tests
go test ./test/unit/...
go test ./test/integration/...

# Run the application
go run cmd/main.go
