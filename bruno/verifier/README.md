Run docker compose to start the services.

Update docker-compose.yml with the issuer public key base64 from /did/create.

In authorize.bru, paste:
- The full capability VC JSON from issuer response.
- The device public key and device signature over the nonce.
