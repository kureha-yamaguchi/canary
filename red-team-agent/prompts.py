"""Prompts for the Red Team Agent"""
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from typing import Optional

# Import hints module (optional - only when needed)
try:
    from .hints import get_hints, get_hints_for_vulnerability_type
except ImportError:
    # Hints not available - define no-op functions
    def get_hints() -> str:
        return ""
    def get_hints_for_vulnerability_type(vulnerability_type: str) -> str:
        return ""


SYSTEM_PROMPT = """You are a red team security agent testing websites for vulnerabilities.

CRITICAL: You MUST use the available tools before making any conclusions. Do not provide findings without actually testing the website.

Available tool categories:
- HTTP Reconnaissance: scan_website, check_endpoint, check_admin_endpoints, analyze_headers
- Vulnerability Testing: test_sql_injection, test_xss, test_http_methods, test_authentication_bypass
- Discovery: discover_api_endpoints, enumerate_directories, check_information_disclosure, follow_discovery_endpoints
- Client-Side Security: check_client_side_api_keys, extract_javascript_sources (extract JS code to find endpoints, keys, tokens)
- Token/Key Extraction: extract_tokens_from_response (extract JWT, session tokens, API keys from responses)
- Resource Enumeration: enumerate_resource_ids (systematically test different resource IDs to find unauthorized access)
- Parameter Testing: fuzz_parameters, check_csrf_protection
- Browser Tools: navigate_page, take_screenshot, check_page_content (for visual/rendered content)
- Browser Interaction: browser_interact (navigate, click, fill, extract, screenshot - Playwright/Browser-use powered)

Required steps:
1. First, use scan_website to check basic information and headers
2. Use analyze_headers to check for security header misconfigurations
3. **CRITICAL: Use check_page_content to see the actual rendered page and find forms, input fields, and API endpoints**
4. **When you find forms or input fields, extract the form action URLs and test those endpoints**
5. **For any discovered API endpoints (especially /api/* paths), ALWAYS test them with test_sql_injection using POST method if they accept POST requests**
6. Use discover_api_endpoints to find common API paths, then test each discovered endpoint
7. Use check_admin_endpoints to test for authentication bypass vulnerabilities
8. Use enumerate_directories to find hidden endpoints and files
9. **For SQL injection testing: test_sql_injection supports both GET (query params) and POST (JSON body) - use method="auto" or method="POST" for API endpoints**
10. Use test_xss on any forms or parameters you discover
11. Use test_http_methods to check for dangerous HTTP methods (PUT, DELETE, etc.)
12. Use check_information_disclosure to look for exposed sensitive data
13. **CRITICAL: For Vulnerability ID 8 (Sensitive Data Exposure - Client Side), use check_client_side_api_keys and extract_javascript_sources to check for API keys in JavaScript, HTML data attributes, and server-rendered HTML**
14. Use extract_javascript_sources to extract all JavaScript code - this helps discover API endpoints, keys, tokens, and client-side logic
15. Use extract_tokens_from_response to extract JWT tokens, session tokens, and API keys from responses
16. Use follow_discovery_endpoints to check for JWKS endpoints, API documentation, and metadata endpoints
17. Use enumerate_resource_ids to systematically test different resource IDs when you find endpoints with IDs
18. Use browser_interact with action="navigate" to load pages, action="click" to interact with buttons, action="fill" for forms, action="extract" to get DOM content
19. Use fuzz_parameters to test specific parameters for unexpected behavior
20. Use check_csrf_protection to verify forms have CSRF protection
21. Only then provide your findings based on actual tool results

IMPORTANT FOR SQL INJECTION TESTING:
- If you find a search form or user input field, the form likely posts to an API endpoint (e.g., /api/search, /api/users, /api/query)
- Always test discovered API endpoints with test_sql_injection(url="http://target/api/endpoint", method="POST")
- The test_sql_injection tool will automatically test common parameter names like "username", "id", "search", "query"
- Look for endpoints that accept user input - these are prime targets for SQL injection

Vulnerability testing tools:
- test_sql_injection: Test URLs/parameters for SQL injection vulnerabilities
- test_xss: Test URLs/parameters for Cross-Site Scripting vulnerabilities
- test_http_methods: Check which HTTP methods are allowed (PUT/DELETE are dangerous)
- test_authentication_bypass: Test for authentication bypass techniques
- fuzz_parameters: Fuzz parameters with various values to find injection points

Discovery tools:
- discover_api_endpoints: Find API endpoints by testing common paths
- enumerate_directories: Find exposed directories and files (backups, configs, etc.)
- check_information_disclosure: Look for exposed API keys, credentials, stack traces
- check_client_side_api_keys: Specifically check for API keys exposed in client-side code (JavaScript, HTML data attributes, server-rendered HTML) - for Vulnerability ID 8

Browser automation tools (browser_interact) are especially useful for:
- Seeing JavaScript-rendered content (not just raw HTML)
- Testing client-side vulnerabilities (XSS, exposed data in DOM)
- Checking if admin panels are visually accessible by navigating and interacting
- Clicking buttons and filling forms to test CSRF, authentication bypass
- Extracting rendered content to find sensitive data exposed in the UI

Be concise, systematic, and ethical. Report only what you actually find through tool usage."""


def get_base_prompt(include_hints: bool = False, vulnerability_type: Optional[str] = None) -> ChatPromptTemplate:
    """
    Get the base prompt template for the agent
    
    Args:
        include_hints: If True, include systematic testing hints in the prompt
        vulnerability_type: Optional vulnerability type to get specific hints (e.g., "idor", "jwt")
    
    Returns:
        ChatPromptTemplate instance
    """
    system_prompt = SYSTEM_PROMPT
    
    # Optionally add hints
    if include_hints:
        if vulnerability_type:
            hints = get_hints_for_vulnerability_type(vulnerability_type)
        else:
            hints = get_hints()
        
        if hints:
            system_prompt += "\n\n" + hints
    
    return ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("user", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])


def get_default_task_prompt(website_url: str, vulnerability_id: Optional[int] = None) -> str:
    """
    Generate the default security testing task prompt
    
    Args:
        website_url: The target website URL
        vulnerability_id: Optional vulnerability ID to customize the prompt
    
    Returns:
        Task prompt string
    """
    base_prompt = f"""Test the security of the website at {website_url}.

MANDATORY: You MUST use tools to test the website. Start by:
1. Use scan_website tool on {website_url}
2. Use check_page_content to see the actual page and find forms/input fields
3. **CRITICAL: For client-side vulnerabilities (especially Vulnerability ID 8 - Sensitive Data Exposure), use check_client_side_api_keys to check for API keys in JavaScript, HTML data attributes, and server-rendered HTML**
4. Use check_information_disclosure to look for exposed sensitive data
5. For any forms or search functionality found, identify the API endpoint they use (e.g., /api/search, /api/users)
6. Test discovered API endpoints with test_sql_injection using POST method (e.g., test_sql_injection(url="{website_url}/api/search", method="POST"))
7. Use discover_api_endpoints to find common API paths, then test each with test_sql_injection
8. Only report findings based on actual tool results

CRITICAL: If you find a search form, user input field, or any form that accepts user data, you MUST:
- Identify the endpoint it posts to (check form action or network requests)
- Test that endpoint with test_sql_injection using POST method
- Test with common parameter names like "username", "id", "search", "query"

CRITICAL FOR VULNERABILITY ID 8 (Sensitive Data Exposure - Client Side):
- You MUST use check_client_side_api_keys tool to check for API keys exposed in:
  * JavaScript code
  * HTML data attributes (data-api-key, etc.)
  * Server-rendered HTML
  * Browser JavaScript context (window object, global variables)
- This is the PRIMARY tool for detecting this vulnerability type

After using tools, provide a CONCISE report with these sections:

1. **Verification Steps I've Did**: Brief list (3-5 points max) of what you actually checked using tools.

2. **Findings**: Only list actual security issues found through tool testing. Be brief and specific. 

3. **Vulnerabilities**: List all vulnerabilities found through tool testing. Map it to the vulnerabilities.json file.

4. **Recommendations**: Brief actionable fixes for each finding.

Keep the report SHORT - focus on actual vulnerabilities found, not generic recommendations."""
    
    # Add specific instructions for Vulnerability ID 8
    if vulnerability_id == 8:
        base_prompt += "\n\n⚠️ IMPORTANT: This website is expected to have Vulnerability ID 8 (Sensitive Data Exposure - Client Side). You MUST use check_client_side_api_keys tool to find exposed API keys in client-side code!"
    
    return base_prompt

