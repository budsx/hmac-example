#!/bin/bash

# Set the environment variable for the tests
# export SECRET_SIGNATURE="rahasias"

# Run the Go tests
echo "Running tests..."
go test -v ./...

# Check if the tests passed
if [ $? -eq 0 ]; then
    echo "All tests passed successfully."
else
    echo "Some tests failed. Check the output above for details."
    exit 1
fi
