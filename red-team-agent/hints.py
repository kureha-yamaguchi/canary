"""
Hints and testing strategies for the red team agent.
These can be optionally included in prompts to guide the agent's testing approach.
"""

SYSTEMATIC_TESTING_HINTS = """
SYSTEMATIC TESTING APPROACHES:

1. **Resource Enumeration (IDOR)**: When you find endpoints with IDs (like /api/users/1), use enumerate_resource_ids to systematically test different IDs (1, 2, 3, 999, 1000) to check for unauthorized access.

2. **Error Response Analysis**: When endpoints return errors (400, 500), carefully analyze the error messages using check_information_disclosure - look for stack traces, database errors, file paths, and internal system information.

3. **Token Discovery & Analysis**: 
   - Use extract_tokens_from_response to find JWT tokens, session tokens, API keys in responses
   - If you find JWT tokens, use follow_discovery_endpoints to find JWKS endpoints (/api/auth/jwks, /.well-known/jwks.json)
   - Analyze token structure - check header algorithm, payload claims
   - Test if authentication accepts different token formats/algorithms than expected

4. **JavaScript Analysis**: Use extract_javascript_sources to extract all JavaScript code - look for:
   - API endpoints referenced in JS
   - API keys or tokens in JavaScript variables
   - Authentication mechanisms
   - Client-side logic that reveals backend behavior

5. **API Discovery**: Use follow_discovery_endpoints to check for:
   - JWKS endpoints (/.well-known/jwks.json, /api/auth/jwks) - expose public keys for JWT verification
   - API documentation (/swagger.json, /openapi.json, /api-docs)
   - Metadata endpoints (/.well-known/, /robots.txt, /sitemap.xml)

6. **JWT Testing (Algorithm Confusion)**: If you find JWT tokens or authentication endpoints:
   - Look for JWKS endpoints (/api/auth/jwks, /.well-known/jwks.json)
   - Extract public keys from JWKS responses
   - Analyze JWT token structure (header, payload, signature)
   - Test if tokens accept different algorithms than expected
   - Try creating tokens with different signing algorithms

7. **IDOR Testing**: When you find endpoints with user/resource IDs in URLs:
   - Test with different ID values (1, 2, 3, 999, 1000, etc.)
   - Try accessing resources belonging to different users
   - Check if sequential IDs are accessible
   - Look for patterns like /api/users/{id}/profile, /api/users/{id}/data

8. **Verbose Errors**: When testing API endpoints:
   - Send malformed requests to trigger errors
   - Analyze error responses carefully - look for stack traces, database errors, file paths
   - Check if error messages leak internal system information
   - Test with invalid input types, missing parameters, invalid formats

9. **Token/Key Discovery**: Always check for:
   - Tokens in response headers (Authorization, Set-Cookie)
   - Tokens in response bodies (JSON responses)
   - Keys/tokens in JavaScript code (use browser automation to extract JS)
   - Public keys in discovery endpoints (JWKS, /.well-known/)
   - Tokens stored in browser storage (localStorage, sessionStorage)

10. **Resource Enumeration**: Systematically enumerate resources:
    - Test sequential IDs (1, 2, 3...)
    - Test high-value IDs (999, 1000, admin, 1)
    - Look for patterns in URLs (userId, resourceId, id parameters)
    - Try common resource paths (/api/users, /api/profiles, /api/data)
"""


def get_hints() -> str:
    """
    Get all hints for the agent.
    
    Returns:
        String containing systematic testing hints
    """
    return SYSTEMATIC_TESTING_HINTS


def get_hints_for_vulnerability_type(vulnerability_type: str) -> str:
    """
    Get hints specific to a vulnerability type.
    
    Args:
        vulnerability_type: The vulnerability type (e.g., "idor", "jwt", "sql-injection")
    
    Returns:
        String containing relevant hints for that vulnerability type
    """
    hints_map = {
        "idor": """
IDOR (Insecure Direct Object Reference) Testing:
- Use enumerate_resource_ids to test different resource IDs
- Look for endpoints with user/resource IDs in URLs (/api/users/{id}/profile)
- Test sequential IDs (1, 2, 3) and high-value IDs (999, 1000, admin)
- Check if changing IDs allows accessing unauthorized resources
        """,
        "jwt": """
JWT Testing (Algorithm Confusion):
- Use extract_tokens_from_response to find JWT tokens
- Use follow_discovery_endpoints to find JWKS endpoints (/api/auth/jwks)
- Extract and analyze JWT structure (header.algorithm, payload.claims)
- Test if server accepts different algorithms (RS256 vs HS256)
- Try creating forged tokens with different signing methods
        """,
        "verbose-errors": """
Verbose Error Testing:
- Send malformed requests to trigger errors
- Use check_information_disclosure to analyze error responses
- Look for stack traces, database errors, file paths in error messages
- Test with invalid input types, missing parameters
        """,
        "client-side-exposure": """
Client-Side Exposure Testing:
- Use extract_javascript_sources to extract all JavaScript code
- Use check_client_side_api_keys to check for API keys in JS/HTML
- Look for tokens/keys in JavaScript variables, data attributes
- Check browser storage (localStorage, sessionStorage)
        """,
    }
    
    return hints_map.get(vulnerability_type.lower(), "")

