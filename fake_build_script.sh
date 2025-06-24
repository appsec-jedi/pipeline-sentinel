#!/bin/sh

# fake_build_script.sh

echo "--- Starting fake build process ---"

echo "\nStep 1: Checking user identity..."
whoami

echo "\nStep 2: Downloading a dependency..."
# Use -s for silent, -o /dev/null to discard output
curl -s -o /dev/null https://example.com

echo "\nStep 3: Running a Python script..."
python3 -c 'import os; print(f"Hello from Python, running as user: {os.geteuid()}")'

echo "\n--- Fake build process finished ---"