#!/bin/bash

# Configuration
PORT=3000
PRIVATE_KEY="private.pem"
PUBLIC_KEY="public.pem"
SERVER_URL="http://localhost:${PORT}/verify"
DEPENDENCIES=("openssl" "curl" "jq")

print_dependencies() {
    echo "The dependencies for this script are:"
    for d in "${DEPENDENCIES[@]}"; do
        echo -e "\t$d"
    done
}

# Error on edge cases
if [[ -z "$(lsof -i :$PORT)" ]]; then
    echo -e "Nothing is running on port ${PORT}. Are you sure the server is running?\n"
    echo -e "You can start the server with the following command:\n\n\tcargo run\n"
    exit 1
fi
if [[ -z "$1" ]]; then
    echo -e "Message not provided as first arg. Nothing to sign and verify. Exiting...\n"
    exit 1
fi
for d in "${DEPENDENCIES[@]}"; do
    if ! command -v $d &> /dev/null; then
        echo -e "'$d' not found in path\n"
        print_dependencies
        echo -e "\nExiting..."
        exit 1
    fi
done

# Build message with nonce
echo "Building message with nonce..."
NONCE="$(date +%s)-$(openssl rand -hex 6)"
MESSAGE="${NONCE}:nonce:$1"

# Generate keys if not already present
if [[ ! -f "$PRIVATE_KEY" || ! -f "$PUBLIC_KEY" ]]; then
    echo "Generating RSA key pair..."
    openssl genpkey -algorithm RSA -out "$PRIVATE_KEY"
    openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
else
    echo "Key pair already exists, reusing..."
fi

# Sign the message
echo "Using private key to sign message..."
SIGNATURE=$(echo -n "$MESSAGE" | openssl dgst -sha256 -sign "$PRIVATE_KEY" | base64)

# Prepare JSON payload
echo "Building payload..."
JSON_PAYLOAD=$(jq -n \
    --arg msg "$MESSAGE" \
    --arg pubkey "$(cat $PUBLIC_KEY)" \
    --arg sig "$SIGNATURE" \
    '{message: $msg, public_key: $pubkey, signature: $sig}')


# Send request
echo -e "Sending payload to server...\n"
RESPONSE=$(curl -s -X POST "$SERVER_URL" \
    -H "Content-Type: application/json" \
    -d "$JSON_PAYLOAD")

echo -e "Server Response:\n$(echo ${RESPONSE} | jq .)"
