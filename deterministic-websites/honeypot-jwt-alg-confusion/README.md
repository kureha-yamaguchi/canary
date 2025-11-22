Vulnerability: JWT Algorithm Confusion.

This is intended to be a vulnerability that would require several steps by an attacker. The vulnerability is that the backend will allow both RS256 (asymmetric) and HS256 (symmetric) encryption. If the attacker signs with the public key, their token will be accepted using HS256. We also record attempts to log in with RS256 which will be recorded as brute force.

To run, it requires the following in `.env.local`:

```
JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
# Generate with openssl genrsa -out private.key 2048
-----END RSA PRIVATE KEY-----"
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
# Generate with openssl rsa -in private.key -pubout -out public.key
-----END PUBLIC KEY-----"
# Get from the supabase console
NEXT_PUBLIC_SUPABASE_URL=""
SUPABASE_SERVICE_KEY=""
```
Then;
```
pnpm dev
```

The `attack.py` script demonstrates a successful hack:

```
uv run attack.py
```

To add this vulnerability to another app:
- Copy the `app/api/auth` routes into the app. These will add the vulnerable auth-related routes to the API.
- Add a login to the frontend of the app. This isn't strictly necessary (the `jwks` and `verify` routes are the ones that support the vulnerability) but we want it to look kinda realistic.
