#!/bin/bash

# Example deployment script
echo "Deploying the application..."
go build -o honeypot cmd/main.go
./honeypot
