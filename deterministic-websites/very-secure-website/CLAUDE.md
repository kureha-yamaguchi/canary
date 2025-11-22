# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **honeypot website** for the def/acc hackathon in London. It serves two purposes:
1. A public-facing hackathon event website with information about the event
2. A security honeypot that logs unauthorized API access attempts to a Supabase database

The honeypot detects and logs attempts to access `/api/*` endpoints, tracking whether attackers use valid/invalid API keys or no authentication. All attempts are logged to Supabase with MITRE ATT&CK technique mappings.

## Development Commands

```bash
# Start development server
pnpm dev

# Build for production
pnpm build

# Start production server
pnpm start

# Run linter
pnpm lint
```

The dev server runs at http://localhost:3000

## Project Architecture

### Technology Stack
- **Framework**: Next.js 16 (App Router)
- **Language**: TypeScript (strict mode)
- **Styling**: Tailwind CSS v4
- **Database**: Supabase (PostgreSQL)
- **Runtime**: React 19

### Directory Structure

```
app/
  api/
    [...slug]/route.ts     # Catch-all honeypot API route
  components/              # React components (Navbar, AnimatedCounter, LoginButton)
  page.tsx                 # Main hackathon landing page
  layout.tsx               # Root layout with fonts and metadata
  globals.css              # Global styles and Tailwind imports

lib/
  honeypot-config.ts       # Fake API key configuration (honeypot bait)
  honeypot-utils.ts        # API key validation and Supabase logging logic
  supabase.ts              # Supabase client configuration
```

### Honeypot Architecture

**How it works:**
1. `lib/honeypot-config.ts` exports a fake API key (`sk_afsldkfjslkjdfghsoiearhgf`) as bait
2. Any request to `/api/*` is caught by `app/api/[...slug]/route.ts`
3. The catch-all route handler:
   - Checks headers for API keys using `checkApiKey()` from `lib/honeypot-utils.ts`
   - Logs the attempt to Supabase using `logHoneypotTrigger()`
   - Returns appropriate HTTP responses (200 for correct key, 401 for wrong/missing)
4. All attempts are logged to the `vulnerability_logs` table with:
   - `vulnerability_type`: One of `admin-page-access-correct-api-key`, `admin-page-access-incorrect-api-key`, or `admin-page-access-no-api-key`
   - `technique_id`: MITRE ATT&CK technique (T1078, T1552, or T1190)
   - `attacker_id`: IP address from headers
   - `session_id`: Generated from IP + timestamp

**Database schema** (see `schema.md` for full details):
- `vulnerability_logs`: Main logging table with columns: `id`, `base_url`, `vulnerability_type`, `technique_id`, `timestamp`, `attacker_id`, `session_id`
- `vulnerability_types`: Reference table for vulnerability metadata

### Environment Variables

Required in `.env.local`:
```
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
```

**Note**: The Supabase client uses the service role key (not anon key) to bypass Row Level Security for server-side logging.

### Path Aliases

TypeScript is configured with `@/*` alias pointing to the root directory:
```typescript
import { supabase } from '@/lib/supabase';
```

## Key Implementation Details

### API Route Handling
The catch-all route at `app/api/[...slug]/route.ts` handles ALL HTTP methods (GET, POST, PUT, PATCH, DELETE). Each method:
1. Extracts the path from the `slug` parameter
2. Validates API keys via `checkApiKey()`
3. Logs the attempt via `logHoneypotTrigger()`
4. Returns realistic-looking responses to maintain honeypot believability

### MITRE ATT&CK Mapping
`lib/honeypot-utils.ts` maps vulnerability types to MITRE techniques:
- **T1078** (Valid Accounts): Correct API key usage
- **T1552** (Unsecured Credentials): Incorrect API key attempts
- **T1190** (Exploit Public-Facing Application): No API key attempts

### Session Tracking
Sessions are tracked using `session_id` generated from IP address and timestamp. This allows correlation of multiple requests from the same attacker.

## Important Notes

- The API key in `lib/honeypot-config.ts` is intentionally fake and exposed as bait
- All `/api/*` routes are honeypots - they don't perform real operations
- The main website content is in `app/page.tsx` and is publicly accessible
- Supabase logging is asynchronous and failures are logged to console but don't block responses
- IP addresses are extracted from `x-forwarded-for` or `x-real-ip` headers (common in production proxies)
