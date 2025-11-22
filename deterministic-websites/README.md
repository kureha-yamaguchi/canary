# Deterministic Websites

Handmade websites with known vulnerabilities for security testing and assessment purposes.

## Structure

Each website in this directory targets a specific vulnerability from `data/vulnarabilities.json`. Each website is self-contained with its own Next.js application, documentation, and vulnerability mapping.

```
deterministic-websites/
├── README.md                    # This file
├── registry.json                # Maps websites to vulnerability IDs
├── vulnerability-8-api-key/     # API Key Exposure (Sensitive Data - Client Side)
├── vulnerability-1-sql-injection/  # SQL Injection
├── vulnerability-2-xss-reflected/  # XSS Reflected
└── vulnerability-3-xss-stored/      # XSS Stored
```

## Website Registry

See `registry.json` for a complete list of all honeypot websites and their target vulnerabilities.

## Adding New Websites

When adding a new honeypot website:

1. Create a new folder: `vulnerability-{ID}-{slug}/`
2. Copy the structure from an existing website (e.g., `vulnerability-8-api-key/`)
3. Implement the vulnerability according to the specification in `data/vulnarabilities.json`
4. Create `docs/vulnerability-mapping.txt` documenting:
   - The vulnerability ID and name
   - How the vulnerability is exposed
   - MITRE ATT&CK technique mappings
   - Detection logic
5. Update `registry.json` with the new website entry

## Running Websites

Each website is a standalone Next.js application. To run a specific website:

```bash
cd vulnerability-{ID}-{slug}/
pnpm install
pnpm dev
```

## Docker Deployment

All websites can be deployed together using the Docker setup in the root directory.
