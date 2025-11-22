# SQL Injection Honeypot Documentation

This directory contains documentation about the SQL injection vulnerability exposed by this honeypot.

## Files

- **vulnerability-mapping.txt** - Complete mapping of the SQL injection vulnerability to the vulnerability database and MITRE ATT&CK techniques

## Quick Reference

This honeypot exposes **Vulnerability ID 1: "SQL Injection"** through:

1. **Search Form API Endpoint** - User input directly concatenated into SQL queries
2. **No Input Sanitization** - No validation or parameterization of user input
3. **Vulnerable Query Construction** - SQL queries built with string concatenation

The vulnerability is located in `app/api/search/route.ts` where user input is inserted directly into SQL query strings.

See `vulnerability-mapping.txt` for complete details including:
- Exact file locations and line numbers
- Example SQL injection payloads
- Detection logic and MITRE ATT&CK mappings
- Security notes and secure alternatives

