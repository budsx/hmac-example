# HMAC Signature Validation Example

This repository contains an example of how to validate HMAC (Hash-based Message Authentication Code) signatures in a Golang web server. The server checks the authenticity of incoming requests by verifying the `x-signature` HTTP header using HMAC with SHA-512.

## Overview

The server runs on `localhost:8080` and listens for incoming HTTP requests. For each request, it validates the `x-signature` header by comparing it with an expected signature computed using the request body and a secret key. If the signatures match, the request is considered valid; otherwise, it is rejected.

### Key Features

- **HMAC Signature Verification:** Uses SHA-512 for generating and verifying HMAC signatures.
- **Middleware Implementation:** The signature check is implemented as a middleware to ensure that all incoming requests are validated before they reach the main handler.

## How It Works

1. **Generate HMAC:**
   - The `generateHMAC` function creates an HMAC signature by hashing the request body with a secret key and encoding the result in base64.

2. **Signature Checker Middleware:**
   - The `signatureChecker` function is a middleware that intercepts incoming requests, reads the request body, and validates the `x-signature` header.
   - If the signature is valid, the request is passed on to the main handler; otherwise, it is rejected with a `403 Forbidden` status.

3. **Main Handler:**
   - The `handler` function simply responds with "Valid!" if the signature validation passes.

## Environment Variables

- `SECRET_SIGNATURE`: The secret key used to generate and verify the HMAC signature. This should be set in your environment.

## Example Request

```
curl -X POST http://localhost:8080/ \
-H "x-signature: your_generated_signature" \
-d '{"transaction_datetime":"2024-08-15T12:00:00Z","customer_name":"John Doe","request_id":"12345"}'

