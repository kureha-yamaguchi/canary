# SQL Injection Honeypot

This honeypot website exposes **Vulnerability ID 1: "SQL Injection"**.

## Vulnerability Details

- **Vulnerability ID**: 1
- **Name**: SQL Injection
- **Description**: User input concatenated directly into SQL queries without sanitization
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)

## How It Works

This website contains a user search form where user input is directly concatenated into SQL queries without proper sanitization or parameterization. The vulnerable code is in `app/api/search/route.ts`:

```typescript
// VULNERABLE CODE - DO NOT USE IN PRODUCTION!
const vulnerableQuery = `SELECT * FROM users WHERE username = '${username}' AND active = 1`;
```

## Testing the Vulnerability

Try these SQL injection payloads in the search form:

- `' OR '1'='1` - Returns all users
- `' OR '1'='1'--` - Bypasses authentication with comment
- `admin' OR 1=1--` - Boolean-based injection
- `' UNION SELECT * FROM users--` - UNION-based injection

## Documentation

See [docs/vulnerability-mapping.txt](docs/vulnerability-mapping.txt) for complete vulnerability mapping and MITRE ATT&CK technique details.

## Getting Started

```bash
# Install dependencies
pnpm install

# Set up environment variables
cp .env.example .env.local
# Edit .env.local with your Supabase credentials

# Run development server
pnpm dev
```

The dev server runs at http://localhost:3001

## Environment Variables

Create a `.env.local` file with:

```
SUPABASE_URL=your_supabase_url
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
```

## Security Warning

⚠️ **This code is intentionally vulnerable for honeypot purposes.**
   DO NOT use this pattern in production code!

