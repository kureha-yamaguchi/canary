# Repository Structure for Multiple Honeypot Websites

This document explains how the repository is organized to support multiple honeypot websites, each targeting a different vulnerability.

## Directory Structure

```
deterministic-websites/
├── README.md                          # Main overview and instructions
├── registry.json                      # Central registry of all websites
├── STRUCTURE.md                       # This file
│
├── vulnerability-8-api-key/          # ✅ ACTIVE - API Key Exposure
│   ├── README.md                      # Website-specific README
│   ├── docs/
│   │   ├── README.md
│   │   └── vulnerability-mapping.txt # Complete vulnerability mapping
│   ├── app/                           # Next.js application
│   ├── lib/                           # Honeypot utilities
│   └── package.json
│
├── vulnerability-1-sql-injection/    # 🔨 PLANNED - SQL Injection
│   ├── README.md
│   ├── docs/
│   │   └── vulnerability-mapping.txt
│   └── [Next.js app structure]
│
├── vulnerability-2-xss-reflected/    # 🔨 PLANNED - Reflected XSS
│   ├── README.md
│   ├── docs/
│   │   └── vulnerability-mapping.txt
│   └── [Next.js app structure]
│
└── vulnerability-3-xss-stored/       # 🔨 PLANNED - Stored XSS
    ├── README.md
    ├── docs/
    │   └── vulnerability-mapping.txt
    └── [Next.js app structure]
```

## Naming Convention

Each website folder follows the pattern:
```
vulnerability-{ID}-{slug}/
```

Where:
- `{ID}` is the vulnerability ID from `data/vulnarabilities.json`
- `{slug}` is a short, descriptive name (e.g., `api-key`, `sql-injection`, `xss-reflected`)

Examples:
- `vulnerability-8-api-key/` → Vulnerability ID 8
- `vulnerability-1-sql-injection/` → Vulnerability ID 1
- `vulnerability-2-xss-reflected/` → Vulnerability ID 2

## Registry System

The `registry.json` file serves as the central directory of all honeypot websites:

```json
{
  "websites": [
    {
      "id": "vulnerability-8-api-key",
      "vulnerability_id": 8,
      "vulnerability_name": "Sensitive Data Exposure - Client Side",
      "port": 3000,
      "status": "active"
    }
  ]
}
```

This allows:
- Easy discovery of all available websites
- Port management (each website gets its own port)
- Status tracking (active, planned, deprecated)
- Automated deployment and routing

## Standard Website Structure

Each website should have:

```
vulnerability-{ID}-{slug}/
├── README.md                    # Quick start and overview
├── docs/
│   ├── README.md               # Documentation index
│   └── vulnerability-mapping.txt  # Complete vulnerability mapping
├── app/                        # Next.js app directory
│   ├── page.tsx                # Main page
│   ├── api/                    # API routes (if needed)
│   └── components/             # React components
├── lib/                        # Utility functions
│   ├── honeypot-config.ts      # Configuration
│   ├── honeypot-utils.ts       # Detection and logging
│   └── supabase.ts             # Database client
├── package.json                # Dependencies
└── [other Next.js files]
```

## Vulnerability Mapping File

Each website must include `docs/vulnerability-mapping.txt` with:

1. **Vulnerability Details**
   - Vulnerability ID and name from `vulnarabilities.json`
   - Description

2. **Exposure Methods**
   - How the vulnerability is exposed (files, lines, methods)
   - Multiple exposure vectors if applicable

3. **MITRE ATT&CK Mappings**
   - Technique IDs and descriptions
   - Reference to the mapping function in code

4. **Detection Logic**
   - How the honeypot detects exploitation attempts
   - What gets logged

5. **Files Involved**
   - List of files that expose the vulnerability

## Port Allocation

Each website runs on its own port:
- `vulnerability-8-api-key`: 3000
- `vulnerability-1-sql-injection`: 3001
- `vulnerability-2-xss-reflected`: 3002
- `vulnerability-3-xss-stored`: 3003

Ports are defined in `registry.json` and should be unique per website.

## Adding a New Website

1. **Choose a vulnerability** from `data/vulnarabilities.json`
2. **Create the folder**: `vulnerability-{ID}-{slug}/`
3. **Copy structure** from an existing website (e.g., `vulnerability-8-api-key/`)
4. **Implement the vulnerability** according to the specification
5. **Create documentation**:
   - Update `README.md`
   - Create `docs/vulnerability-mapping.txt`
6. **Update registry**: Add entry to `registry.json`
7. **Test**: Ensure the vulnerability is properly exposed and detected

## Benefits of This Structure

✅ **Clear Organization**: Easy to find websites by vulnerability ID
✅ **Scalable**: Can add unlimited websites following the same pattern
✅ **Self-Documenting**: Each website has its own complete documentation
✅ **Centralized Registry**: Single source of truth for all websites
✅ **Consistent**: Same structure across all websites makes maintenance easier

