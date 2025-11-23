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

### 8. **Test Form Submission Flow & Redirects**
Follow form submissions and test redirect destinations for reflected input vulnerabilities (XSS, JSONP callback injection). This is critical for finding vulnerabilities where:
- Forms submit to an API endpoint
- The API redirects to a confirmation/thank-you page
- User input is reflected in the redirect URL parameters
- The destination page renders user input without sanitization

**Tool Name**: `test_form_flow`
**What it does**: 
1. Finds forms on a page (using check_page_content or browser_interact)
2. Extracts form action, method, and input fields
3. Submits the form with test payloads (XSS, SQL injection, etc.)
4. Follows redirects (HTTP 302/307) to the final destination
5. Tests the final destination URL for reflected input vulnerabilities
6. Specifically tests all query parameters in the redirect URL with XSS payloads
7. Checks if payloads are reflected in the response (unencoded)

**Why it's needed**: The current agent fails to detect XSS in cases like:
- Form submits to `/api/submit` (POST)
- Server redirects to `/thank-you?name=<user_input>&ability=<user_input>`
- The `/thank-you` page uses `dangerouslySetInnerHTML` to render the parameters
- Agent never discovers or tests the `/thank-you` endpoint

**Example usage**:
```python
test_form_flow(
    url="http://localhost:3005/contact",
    form_selector="form",  # or auto-detect
    test_payloads=["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"],
    follow_redirects=True
)
# Returns: Found form submitting to /api/submit
#          Followed redirect to /thank-you?name=<script>alert('XSS')</script>
#          ⚠️ XSS VULNERABILITY: Payload reflected unencoded in /thank-you page
```

**Alternative simpler tool**: `test_reflected_endpoints`
- Takes a list of endpoints that might reflect user input
- Tests each endpoint with XSS payloads in all query parameters
- Checks for unencoded reflection in response
- Useful when agent discovers endpoints but doesn't test them for XSS

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

1. **PRIORITY: Add `test_form_flow` tool** - Critical for detecting XSS/JSONP callback injection in form submission flows
2. Add `extract_javascript_sources` tool (general-purpose JS extraction)
3. Add `enumerate_resource_ids` tool (general ID enumeration)
4. Enhance `analyze_headers` or add `analyze_response_deeply` (better error analysis)
5. Add `extract_tokens` tool (general token extraction)
6. Add `follow_api_discovery_links` tool (follow JWKS, swagger, etc.)
7. Update system prompt with general testing patterns and hints

These general tools will help the agent discover vulnerabilities naturally rather than having specific testers for each vulnerability type.

## Implementation Example: `test_form_flow`

Here's a detailed implementation suggestion for the `test_form_flow` tool:

```python
@tool
def test_form_flow(
    url: str, 
    form_selector: Optional[str] = None,
    follow_redirects: bool = True,
    test_xss: bool = True,
    test_sql_injection: bool = False
) -> str:
    """
    Test form submission flow and follow redirects to detect reflected input vulnerabilities.
    
    This tool is critical for finding XSS vulnerabilities where:
    - Forms submit to an API endpoint
    - Server redirects to a confirmation page with user input in URL
    - The destination page renders user input without sanitization
    
    Args:
        url: The URL containing the form to test
        form_selector: Optional CSS selector for the form (default: auto-detect first form)
        follow_redirects: Whether to follow redirects after form submission
        test_xss: Whether to test for XSS vulnerabilities in redirect destination
        test_sql_injection: Whether to test for SQL injection (optional)
    
    Returns:
        String containing test results and discovered vulnerabilities
    """
    from urllib.parse import urlparse, parse_qs, urlencode
    import re
    
    results = []
    vulnerabilities = []
    
    # Step 1: Get the page and find forms
    try:
        response = requests.get(url, timeout=config.REQUEST_TIMEOUT)
        html = response.text
        
        # Find form elements
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']'
        forms = re.findall(form_pattern, html, re.IGNORECASE)
        
        if not forms:
            return "No forms found on the page"
        
        # Get first form or specified form
        form_action, form_method = forms[0]
        form_method = form_method.upper() if form_method else 'POST'
        
        # Extract input fields
        input_pattern = r'<input[^>]*name=["\']([^"\']*)["\']'
        input_fields = re.findall(input_pattern, html, re.IGNORECASE)
        
        results.append(f"Found form: action={form_action}, method={form_method}")
        results.append(f"Input fields: {', '.join(input_fields)}")
        
        # Step 2: Submit form with test payloads
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        submit_url = urljoin(base_url, form_action) if form_action else url
        
        # XSS test payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
        ]
        
        for payload in xss_payloads:
            # Prepare form data
            form_data = {}
            for field in input_fields[:3]:  # Test first 3 fields
                form_data[field] = payload
            
            try:
                if form_method == 'POST':
                    response = requests.post(
                        submit_url,
                        data=form_data,
                        allow_redirects=follow_redirects,
                        timeout=config.REQUEST_TIMEOUT
                    )
                else:
                    # GET request
                    response = requests.get(
                        submit_url,
                        params=form_data,
                        allow_redirects=follow_redirects,
                        timeout=config.REQUEST_TIMEOUT
                    )
                
                # Step 3: Check final destination URL
                final_url = response.url
                results.append(f"Form submission redirected to: {final_url}")
                
                # Step 4: Test redirect destination for reflected input
                if test_xss and follow_redirects:
                    # Extract query parameters from redirect URL
                    redirect_parsed = urlparse(final_url)
                    redirect_params = parse_qs(redirect_parsed.query)
                    
                    # Check if payload is reflected in the response
                    if payload in response.text:
                        vulnerabilities.append(
                            f"⚠️ XSS VULNERABILITY: Payload '{payload[:30]}...' reflected unencoded in {final_url}"
                        )
                    elif any(payload in str(v) for v in redirect_params.values()):
                        # Payload is in URL parameters - test if it's rendered
                        if '<script>' in response.text.lower() or 'onerror=' in response.text.lower():
                            vulnerabilities.append(
                                f"⚠️ POTENTIAL XSS: Payload in URL parameters of {final_url} may be executed"
                            )
                    
                    # Test each parameter in redirect URL with XSS payloads
                    for param_name in redirect_params.keys():
                        test_params = redirect_params.copy()
                        test_params[param_name] = [payload]
                        test_url = f"{redirect_parsed.scheme}://{redirect_parsed.netloc}{redirect_parsed.path}?{urlencode(test_params, doseq=True)}"
                        
                        test_response = requests.get(test_url, timeout=config.REQUEST_TIMEOUT)
                        if payload in test_response.text:
                            vulnerabilities.append(
                                f"🚨 XSS VULNERABILITY: Parameter '{param_name}' in {final_url} reflects payload unencoded"
                            )
                
            except requests.exceptions.RequestException as e:
                results.append(f"Error testing form submission: {str(e)}")
        
    except requests.exceptions.RequestException as e:
        return f"Error accessing {url}: {str(e)}"
    
    output = []
    if vulnerabilities:
        output.append("🚨 VULNERABILITIES FOUND:")
        output.extend(vulnerabilities)
        output.append("")
    output.append("Form Flow Test Results:")
    output.extend(results)
    
    return "\n".join(output) if output else "No vulnerabilities detected in form flow"
```

**Key features:**
1. Automatically discovers forms on a page
2. Extracts form action, method, and input fields
3. Submits form with XSS payloads
4. Follows redirects to final destination
5. Tests redirect URL parameters for reflected input
6. Checks if payloads are reflected unencoded in the response

**Usage in prompts:**
Add to system prompt: "When you find forms on a page, use `test_form_flow` to test the complete submission flow including redirects. This is critical for finding XSS vulnerabilities where user input is reflected in redirect destination URLs."

