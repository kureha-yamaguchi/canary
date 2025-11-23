# General Tool Improvements & Instructions for Better Vulnerability Detection

## General-Purpose Tools to Add

### 1. **Extract JavaScript Sources**
A tool to extract all JavaScript from a page (inline, external scripts, executed code). This helps discover:
- API endpoints referenced in JS
- API keys in JavaScript code
- Authentication mechanisms
- Client-side logic

**Tool Name**: `extract_javascript_sources`
**What it does**: Uses browser automation to get all JavaScript code (from `<script>` tags, external files, executed code)

### 2. **Enumerate Resource IDs**
A general tool to systematically test different resource IDs/parameters. Helps discover:
- IDOR vulnerabilities (by testing different user IDs)
- Sequential ID patterns
- Access control issues

**Tool Name**: `enumerate_resource_ids`
**What it does**: Tests a URL pattern with different ID values (1, 2, 3, 100, 1000, etc.) and reports which are accessible

### 3. **Deep Response Analysis**
Enhanced response analysis that looks for:
- Error messages with stack traces
- Verbose API error responses
- Leaked internal information
- Different response patterns

**Tool Name**: `analyze_response_deeply`
**What it does**: Takes a response and analyzes it for verbose errors, stack traces, file paths, database errors, etc.

### 4. **Extract Tokens from Responses**
General token extraction (JWTs, session tokens, API tokens) from responses/cookies. Helps discover:
- JWT tokens that can be analyzed
- Session tokens
- API tokens

**Tool Name**: `extract_tokens`
**What it does**: Extracts tokens from cookies, headers, response body, JavaScript variables

### 5. **Test Endpoint with Variations**
Systematically test endpoint patterns with different parameters/IDs/values. Helps discover:
- IDOR by testing different IDs
- Parameter pollution
- Missing validation

**Tool Name**: `test_endpoint_variations`
**What it does**: Tests a base URL pattern with systematic variations (different IDs, parameters, values)

### 6. **Execute JavaScript in Browser Context**
Execute custom JavaScript code in the browser to:
- Check window/global variables
- Extract data from client-side code
- Test client-side vulnerabilities

**Tool Name**: `execute_javascript`
**What it does**: Runs custom JavaScript in the page context and returns results

### 7. **Follow API Links**
Discover and follow API discovery endpoints like:
- `/api/auth/jwks` (for JWT public keys)
- `/swagger.json`, `/openapi.json` (API documentation)
- `/robots.txt`, `/sitemap.xml`
- Links in responses

**Tool Name**: `follow_api_discovery_links`
**What it does**: Follows common API discovery endpoints and reports findings

## Improved Instructions/Hints to Add

### For JWT Testing (Algorithm Confusion)
**Instruction**: "If you find JWT tokens or authentication endpoints:
- Look for JWKS endpoints (`/api/auth/jwks`, `.well-known/jwks.json`)
- Extract public keys from JWKS responses
- Analyze JWT token structure (header, payload, signature)
- Test if tokens accept different algorithms than expected
- Try creating tokens with different signing algorithms"

### For IDOR Testing
**Instruction**: "When you find endpoints with user/resource IDs in URLs:
- Test with different ID values (1, 2, 3, 999, 1000, etc.)
- Try accessing resources belonging to different users
- Check if sequential IDs are accessible
- Look for patterns like `/api/users/{id}/profile`, `/api/users/{id}/data`"

### For Verbose Errors
**Instruction**: "When testing API endpoints:
- Send malformed requests to trigger errors
- Analyze error responses carefully - look for stack traces, database errors, file paths
- Check if error messages leak internal system information
- Test with invalid input types, missing parameters, invalid formats"

### For Token/Key Discovery
**Instruction**: "Always check for:
- Tokens in response headers (Authorization, Set-Cookie)
- Tokens in response bodies (JSON responses)
- Keys/tokens in JavaScript code (use browser automation to extract JS)
- Public keys in discovery endpoints (JWKS, /.well-known/)
- Tokens stored in browser storage (localStorage, sessionStorage)"

### For Resource Enumeration
**Instruction**: "Systematically enumerate resources:
- Test sequential IDs (1, 2, 3...)
- Test high-value IDs (999, 1000, admin, 1)
- Look for patterns in URLs (userId, resourceId, id parameters)
- Try common resource paths (/api/users, /api/profiles, /api/data)"

## Example Improved Prompt Additions

Add to the system prompt:

```
SYSTEMATIC TESTING APPROACHES:

1. **Resource Enumeration**: When you find endpoints with IDs (like /api/users/1), systematically test different IDs (1, 2, 3, 999, 1000) to check for unauthorized access.

2. **Error Response Analysis**: When endpoints return errors (400, 500), carefully analyze the error messages - they may contain stack traces, database errors, or internal information.

3. **Token Discovery**: Look for tokens (JWT, session, API keys) in:
   - Response headers (Authorization, Set-Cookie, X-API-Key)
   - Response bodies (JSON responses may contain tokens)
   - JavaScript code (use browser automation to extract and analyze JS)
   - Discovery endpoints (/.well-known/jwks.json, /api/auth/jwks)

4. **Authentication Mechanism Testing**: 
   - If you find JWT tokens, extract and analyze them
   - Look for JWKS endpoints to get public keys
   - Test if authentication accepts different token formats/algorithms
   - Try accessing protected resources without proper authentication

5. **API Discovery**: Check for:
   - API documentation endpoints (/swagger.json, /openapi.json, /api-docs)
   - JWKS endpoints (/api/auth/jwks, /.well-known/jwks.json)
   - Metadata endpoints (/.well-known/, /robots.txt, /sitemap.xml)
```

## Recommended Next Steps

1. Add `extract_javascript_sources` tool (general-purpose JS extraction)
2. Add `enumerate_resource_ids` tool (general ID enumeration)
3. Enhance `analyze_headers` or add `analyze_response_deeply` (better error analysis)
4. Add `extract_tokens` tool (general token extraction)
5. Add `follow_api_discovery_links` tool (follow JWKS, swagger, etc.)
6. Update system prompt with general testing patterns and hints

These general tools will help the agent discover vulnerabilities naturally rather than having specific testers for each vulnerability type.

