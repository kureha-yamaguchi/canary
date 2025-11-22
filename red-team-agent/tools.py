"""Tools for the Red Team Agent"""
from langchain.tools import tool
import requests
from typing import List, Optional, Dict
import sys
import os
import re
import json
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

# Handle both package and direct imports
try:
    from .config import config
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from config import config


def get_playwright_tools():
    """
    Get Playwright browser automation tools if available.
    These tools allow the agent to interact with web pages directly.
    
    Returns:
        List of Playwright tools, or empty list if not available
    """
    try:
        from langchain_community.tools.playwright import (
            NavigateTool,
            NavigateBackTool,
            ClickTool,
            ExtractTextTool,
            ExtractHyperlinksTool,
            GetElementsTool,
            CurrentWebPageTool,
        )
        from playwright.async_api import async_playwright
        
        # Note: Playwright tools require async context
        # We'll create a simple wrapper or use the sync version
        # For now, return empty list and we'll add a simpler implementation
        return []
    except ImportError:
        return []
    
    except Exception as e:
        print(f"Warning: Could not load Playwright tools: {e}")
        return []


@tool
def scan_website(url: str) -> str:
    """
    Scan a website for basic information like HTTP status and headers.
    This is useful for initial reconnaissance of the target website.
    
    Args:
        url: The full URL to scan (e.g., https://example.com)
    
    Returns:
        String containing HTTP status code and response headers
    """
    try:
        response = requests.get(url, timeout=config.REQUEST_TIMEOUT)
        headers_str = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
        return f"Status: {response.status_code}\nHeaders:\n{headers_str}"
    except requests.exceptions.RequestException as e:
        return f"Error scanning {url}: {str(e)}"


@tool
def check_endpoint(url: str) -> str:
    """
    Check a specific endpoint/URL path on the target website.
    Useful for testing specific routes or pages.
    
    Args:
        url: The full URL including path (e.g., https://example.com/api/users)
    
    Returns:
        String containing endpoint status and basic response info
    """
    try:
        response = requests.get(url, timeout=config.REQUEST_TIMEOUT, allow_redirects=False)
        content_preview = response.text[:300] if response.text else "(empty)"
        # Check if redirected to login (302/307) or if accessible without auth
        redirect_to_login = response.status_code in [302, 307] and 'login' in str(response.headers.get('Location', '')).lower()
        auth_status = "REQUIRES_AUTH" if redirect_to_login else "ACCESSIBLE"
        return f"Status: {response.status_code}\nAuth: {auth_status}\nContent preview: {content_preview}"
    except requests.exceptions.RequestException as e:
        return f"Error checking endpoint {url}: {str(e)}"


@tool
def check_admin_endpoints(base_url: str) -> str:
    """
    Check common admin and management endpoints for authentication bypass vulnerabilities.
    Tests endpoints like /admin, /dashboard, /management, etc.
    
    Args:
        base_url: The base URL of the website (e.g., https://example.com or full URL)
    
    Returns:
        String containing which admin endpoints are accessible without authentication
    """
    # Extract base domain from full URL if needed
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    # Remove trailing slash
    base_url = base_url.rstrip('/')
    
    # Common admin endpoints to check (excluding login pages - those are supposed to be accessible)
    admin_paths = [
        '/admin',              # Admin dashboard (should require auth)
        '/dashboard',          # Dashboard (should require auth)
        '/management',         # Management panel
        '/api/admin',          # Admin API
        '/admin/index',        # Admin index page
        '/administrator',      # Administrator panel
        '/wp-admin',           # WordPress admin
        '/backend',            # Backend panel
        '/panel',              # Control panel
        # Note: /admin/login is excluded - login pages should be accessible
    ]
    
    results = []
    accessible = []
    
    for path in admin_paths:
        url = base_url + path
        try:
            response = requests.get(url, timeout=config.REQUEST_TIMEOUT, allow_redirects=False)
            # Check if redirected to login (authentication required) or accessible
            is_redirect = response.status_code in [302, 307, 301]
            redirect_location = response.headers.get('Location', '')
            requires_auth = is_redirect and ('login' in redirect_location.lower() or 'auth' in redirect_location.lower())
            
            # Check if accessible without authentication
            # Note: /admin/login being accessible is normal (it's a login page)
            # But /admin, /dashboard, etc. being accessible is a vulnerability
            if response.status_code == 200 and not requires_auth:
                # Login pages are expected to be accessible
                if 'login' in path.lower():
                    results.append(f"{path} - Status: {response.status_code} (Login page - normal)")
                else:
                    # Admin/dashboard pages accessible without auth = CRITICAL
                    accessible.append(f"{path} - Status: {response.status_code} - CRITICAL: Accessible without authentication")
            elif response.status_code == 403:
                results.append(f"{path} - Status: 403 (Forbidden - protected)")
            elif requires_auth:
                results.append(f"{path} - Status: {response.status_code} (Redirected to login - protected)")
            else:
                results.append(f"{path} - Status: {response.status_code}")
        except requests.exceptions.RequestException:
            results.append(f"{path} - Error or unreachable")
    
    output = []
    if accessible:
        output.append("CRITICAL: Found admin endpoints accessible without authentication:")
        output.extend(accessible)
        output.append("")
    output.append("All checked endpoints:")
    output.extend(results)
    
    return "\n".join(output)


@tool
def navigate_page(url: str) -> str:
    """
    Navigate to a URL using Playwright browser automation.
    This allows the agent to interact with web pages, see rendered content, and test client-side vulnerabilities.
    
    Args:
        url: The URL to navigate to
    
    Returns:
        String containing page title and basic page information
    """
    try:
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=10000)
            
            title = page.title()
            url_after_nav = page.url
            
            # Get basic page info
            content_length = len(page.content())
            
            browser.close()
            
            return f"Navigated to: {url_after_nav}\nTitle: {title}\nContent size: {content_length} chars"
    except ImportError:
        return "Error: Playwright not installed. Install with: pip install playwright && playwright install"
    except Exception as e:
        return f"Error navigating to {url}: {str(e)}"


@tool
def take_screenshot(url: str) -> str:
    """
    Take a screenshot of a web page using Playwright.
    Useful for seeing the actual rendered page and checking for visual elements or client-side vulnerabilities.
    
    Args:
        url: The URL to screenshot
    
    Returns:
        String with screenshot information and file path
    """
    try:
        from playwright.sync_api import sync_playwright
        from pathlib import Path
        
        screenshot_dir = Path(__file__).parent.parent / "logs" / "screenshots"
        screenshot_dir.mkdir(exist_ok=True, parents=True)
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=10000)
            
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            screenshot_path = screenshot_dir / f"screenshot_{timestamp}.png"
            
            page.screenshot(path=str(screenshot_path), full_page=False)
            title = page.title()
            
            browser.close()
            
            return f"Screenshot saved: {screenshot_path}\nPage title: {title}\nURL: {url}"
    except ImportError:
        return "Error: Playwright not installed. Install with: pip install playwright && playwright install"
    except Exception as e:
        return f"Error taking screenshot of {url}: {str(e)}"


@tool
def check_page_content(url: str, search_text: Optional[str] = None) -> str:
    """
    Check the rendered page content using Playwright.
    This sees the actual DOM and JavaScript-rendered content, not just the raw HTML.
    Useful for testing client-side vulnerabilities and checking for exposed sensitive information.
    
    Args:
        url: The URL to check
        search_text: Optional text to search for in the page content
    
    Returns:
        String containing page content information
    """
    try:
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=15000)
            
            # Get visible text content
            text_content = page.locator("body").inner_text()[:2000]  # First 2000 chars
            
            # Check for specific text if provided
            found_text = ""
            if search_text:
                if search_text.lower() in text_content.lower():
                    found_text = f"\n✓ Found search text: '{search_text}'"
                else:
                    found_text = f"\n✗ Search text '{search_text}' not found"
            
            title = page.title()
            url_after_nav = page.url
            
            browser.close()
            
            return f"URL: {url_after_nav}\nTitle: {title}\nContent preview: {text_content[:500]}...{found_text}"
    except ImportError:
        return "Error: Playwright not installed. Install with: pip install playwright && playwright install"
    except Exception as e:
        return f"Error checking page content for {url}: {str(e)}"


def get_playwright_toolkit_tools():
    """
    Get Playwright Browser Toolkit tools from LangChain.
    These provide comprehensive browser automation capabilities like navigate, click, extract, etc.
    
    Returns:
        List of Playwright toolkit tools, or empty list if not available
    """
    try:
        # Playwright toolkit requires async setup, which can be complex
        # For now, we use our custom sync tools
        # Can be enhanced later with proper async integration
        return []
    except ImportError:
        return []
    except Exception as e:
        return []


@tool
def browser_interact(url: str, action: str = "navigate", selector: Optional[str] = None, text: Optional[str] = None) -> str:
    """
    Interact with a web page using browser automation (Playwright/Browser-use).
    This allows the agent to navigate, click, fill forms, and extract information from rendered pages.
    
    Args:
        url: The URL to interact with
        action: Action to perform - "navigate", "click", "fill", "extract", "screenshot"
        selector: CSS selector for element to interact with (required for click/fill)
        text: Text to fill in a form field (required for fill action)
    
    Returns:
        String containing the result of the interaction
    """
    try:
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=15000)
            
            result = ""
            
            if action == "navigate":
                result = f"Navigated to: {page.url}\nTitle: {page.title()}"
            
            elif action == "click" and selector:
                try:
                    page.click(selector, timeout=5000)
                    result = f"Clicked element: {selector}\nCurrent URL: {page.url}"
                except Exception as e:
                    result = f"Error clicking {selector}: {str(e)}"
            
            elif action == "fill" and selector and text:
                try:
                    page.fill(selector, text)
                    result = f"Filled {selector} with text: {text}"
                except Exception as e:
                    result = f"Error filling {selector}: {str(e)}"
            
            elif action == "extract":
                if selector:
                    try:
                        elements = page.query_selector_all(selector)
                        texts = [el.inner_text() for el in elements[:10]]  # Limit to 10
                        result = f"Extracted from {selector}:\n" + "\n".join(texts)
                    except Exception as e:
                        result = f"Error extracting from {selector}: {str(e)}"
                else:
                    # Extract all visible text
                    text_content = page.locator("body").inner_text()[:2000]
                    result = f"Page content:\n{text_content}"
            
            elif action == "screenshot":
                from pathlib import Path
                screenshot_dir = Path(__file__).parent.parent / "logs" / "screenshots"
                screenshot_dir.mkdir(exist_ok=True, parents=True)
                import datetime
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                screenshot_path = screenshot_dir / f"interaction_{timestamp}.png"
                page.screenshot(path=str(screenshot_path))
                result = f"Screenshot saved: {screenshot_path}"
            
            else:
                result = f"Action '{action}' not supported or missing required parameters"
            
            browser.close()
            return result
            
    except ImportError:
        return "Error: Playwright not installed. Install with: pip install playwright && playwright install"
    except Exception as e:
        return f"Error during browser interaction: {str(e)}"


def get_browser_use_tools():
    """
    Get Browser-use tools if available.
    Browser-use provides browser automation interface.
    
    Returns:
        List of Browser-use tools, or empty list if not available
    """
    tools = []
    
    # Always add browser_interact if Playwright is available
    # It provides comprehensive browser automation
    try:
        from playwright.sync_api import sync_playwright
        tools.append(browser_interact)
    except ImportError:
        pass
    
    # Try to use browser-use package if available (more advanced features)
    try:
        import browser_use
        # Browser-use package is available
        # The browser_interact tool can be enhanced to use it
        pass
    except ImportError:
        pass
    
    return tools


@tool
def test_sql_injection(url: str, parameter: Optional[str] = None) -> str:
    """
    Test a URL or endpoint for SQL injection vulnerabilities.
    Tests common SQL injection payloads and checks for error messages or unusual responses.
    
    Args:
        url: The URL to test (can include query parameters)
        parameter: Optional specific parameter name to test (if not provided, tests all parameters)
    
    Returns:
        String containing SQL injection test results
    """
    from urllib.parse import urlparse, parse_qs, urlencode
    
    # Common SQL injection payloads
    sql_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin'--",
        "admin'/*",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' OR '1'='1",
        "' OR 1=1--",
        "') OR ('1'='1",
    ]
    
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query_params = parse_qs(parsed.query)
    
    results = []
    vulnerable = []
    
    # If no parameters in URL, test common parameter names
    if not query_params and not parameter:
        test_params = ['id', 'user', 'username', 'email', 'search', 'q', 'query']
        for param in test_params:
            query_params[param] = ['test']
    
    # Test each parameter
    params_to_test = [parameter] if parameter else list(query_params.keys())
    
    for param in params_to_test:
        if not param:
            continue
            
        for payload in sql_payloads[:5]:  # Test first 5 payloads to avoid too many requests
            test_params = query_params.copy()
            test_params[param] = [payload]
            test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"
            
            try:
                response = requests.get(test_url, timeout=config.REQUEST_TIMEOUT)
                
                # Check for SQL error indicators
                sql_errors = [
                    'sql syntax', 'mysql', 'postgresql', 'oracle', 'sqlite',
                    'sql error', 'database error', 'query failed',
                    'unclosed quotation', 'syntax error'
                ]
                
                response_lower = response.text.lower()
                found_errors = [err for err in sql_errors if err in response_lower]
                
                if found_errors:
                    vulnerable.append(f"{param} with payload '{payload}': Found SQL error indicators: {', '.join(found_errors)}")
                
                # Check for unusual status codes or response length changes
                if response.status_code == 500:
                    results.append(f"{param} with payload '{payload}': Status 500 (possible SQL error)")
                    
            except requests.exceptions.RequestException as e:
                results.append(f"{param} with payload '{payload}': Error - {str(e)}")
    
    output = []
    if vulnerable:
        output.append("⚠️ POTENTIAL SQL INJECTION VULNERABILITIES:")
        output.extend(vulnerable)
        output.append("")
    output.append("SQL Injection Test Results:")
    output.extend(results[:10])  # Limit output
    
    return "\n".join(output) if output else "No SQL injection vulnerabilities detected in initial tests."


@tool
def test_xss(url: str, parameter: Optional[str] = None) -> str:
    """
    Test a URL or endpoint for Cross-Site Scripting (XSS) vulnerabilities.
    Tests common XSS payloads and checks if they are reflected in the response.
    
    Args:
        url: The URL to test (can include query parameters)
        parameter: Optional specific parameter name to test
    
    Returns:
        String containing XSS test results
    """
    from urllib.parse import urlparse, parse_qs, urlencode
    
    # Common XSS payloads
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<iframe src=javascript:alert('XSS')>",
    ]
    
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query_params = parse_qs(parsed.query)
    
    results = []
    vulnerable = []
    
    # If no parameters, test common parameter names
    if not query_params and not parameter:
        test_params = ['search', 'q', 'query', 'name', 'input', 'message', 'comment']
        for param in test_params:
            query_params[param] = ['test']
    
    params_to_test = [parameter] if parameter else list(query_params.keys())
    
    for param in params_to_test:
        if not param:
            continue
            
        for payload in xss_payloads[:5]:  # Test first 5 payloads
            test_params = query_params.copy()
            test_params[param] = [payload]
            test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"
            
            try:
                response = requests.get(test_url, timeout=config.REQUEST_TIMEOUT)
                
                # Check if payload is reflected in response (unencoded)
                if payload in response.text:
                    vulnerable.append(f"{param}: XSS payload reflected unencoded in response")
                elif payload.replace("'", "&#39;") in response.text or payload.replace("'", "&apos;") in response.text:
                    results.append(f"{param}: Payload reflected but appears to be encoded")
                elif "<script>" in payload.lower() and "<script>" in response.text.lower():
                    vulnerable.append(f"{param}: Script tag detected in response")
                    
            except requests.exceptions.RequestException as e:
                results.append(f"{param} with payload: Error - {str(e)}")
    
    output = []
    if vulnerable:
        output.append("⚠️ POTENTIAL XSS VULNERABILITIES:")
        output.extend(vulnerable)
        output.append("")
    output.append("XSS Test Results:")
    output.extend(results[:10])
    
    return "\n".join(output) if output else "No XSS vulnerabilities detected in initial tests."


@tool
def discover_api_endpoints(base_url: str) -> str:
    """
    Discover API endpoints by testing common API paths and patterns.
    Useful for finding hidden or undocumented API endpoints.
    
    Args:
        base_url: The base URL of the website (e.g., https://example.com)
    
    Returns:
        String containing discovered API endpoints
    """
    from urllib.parse import urlparse
    
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    # Common API endpoint patterns
    api_paths = [
        '/api',
        '/api/v1',
        '/api/v2',
        '/api/users',
        '/api/auth',
        '/api/admin',
        '/api/data',
        '/rest',
        '/rest/api',
        '/graphql',
        '/graphql/v1',
        '/v1',
        '/v2',
        '/swagger',
        '/swagger.json',
        '/swagger.yaml',
        '/openapi.json',
        '/api-docs',
        '/docs',
    ]
    
    discovered = []
    results = []
    
    for path in api_paths:
        url = base + path
        try:
            response = requests.get(url, timeout=config.REQUEST_TIMEOUT, allow_redirects=False)
            
            if response.status_code == 200:
                discovered.append(f"{path} - Status: 200 (accessible)")
            elif response.status_code == 401:
                discovered.append(f"{path} - Status: 401 (requires authentication)")
            elif response.status_code == 403:
                discovered.append(f"{path} - Status: 403 (forbidden)")
            elif response.status_code in [301, 302, 307]:
                location = response.headers.get('Location', '')
                results.append(f"{path} - Status: {response.status_code} (redirects to {location})")
            else:
                results.append(f"{path} - Status: {response.status_code}")
                
        except requests.exceptions.RequestException:
            results.append(f"{path} - Error or unreachable")
    
    output = []
    if discovered:
        output.append("🔍 DISCOVERED API ENDPOINTS:")
        output.extend(discovered)
        output.append("")
    if results:
        output.append("Other tested endpoints:")
        output.extend(results[:10])
    
    return "\n".join(output) if output else "No API endpoints discovered."


@tool
def enumerate_directories(base_url: str) -> str:
    """
    Enumerate common directories and files on the website.
    Tests for exposed directories, backup files, configuration files, etc.
    
    Args:
        base_url: The base URL of the website
    
    Returns:
        String containing discovered directories and files
    """
    from urllib.parse import urlparse
    
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    # Common directories and files to check
    paths = [
        '/admin', '/administrator', '/dashboard', '/panel',
        '/backup', '/backups', '/old', '/test', '/dev', '/staging',
        '/.git', '/.svn', '/.env', '/.htaccess', '/.htpasswd',
        '/config.php', '/config.json', '/config.yaml',
        '/robots.txt', '/sitemap.xml', '/.well-known',
        '/phpinfo.php', '/info.php', '/test.php',
        '/package.json', '/composer.json', '/requirements.txt',
        '/README.md', '/CHANGELOG.md', '/LICENSE',
    ]
    
    discovered = []
    results = []
    
    for path in paths:
        url = base + path
        try:
            response = requests.get(url, timeout=config.REQUEST_TIMEOUT, allow_redirects=False)
            
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                size = len(response.content)
                discovered.append(f"{path} - Status: 200, Type: {content_type}, Size: {size} bytes")
            elif response.status_code == 403:
                results.append(f"{path} - Status: 403 (forbidden - exists but protected)")
            elif response.status_code == 401:
                results.append(f"{path} - Status: 401 (requires authentication)")
            else:
                results.append(f"{path} - Status: {response.status_code}")
                
        except requests.exceptions.RequestException:
            pass  # Skip errors
    
    output = []
    if discovered:
        output.append("📁 DISCOVERED DIRECTORIES/FILES:")
        output.extend(discovered)
        output.append("")
    if results:
        output.append("Other tested paths:")
        output.extend(results[:10])
    
    return "\n".join(output) if output else "No exposed directories or files found."


@tool
def test_http_methods(url: str) -> str:
    """
    Test various HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD) on an endpoint.
    Useful for finding endpoints that accept dangerous methods or missing method restrictions.
    
    Args:
        url: The URL to test
    
    Returns:
        String containing HTTP method test results
    """
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
    results = []
    allowed_methods = []
    
    for method in methods:
        try:
            response = requests.request(method, url, timeout=config.REQUEST_TIMEOUT, allow_redirects=False)
            status = response.status_code
            
            # Methods that return 200/201/204 are likely allowed
            if status in [200, 201, 204]:
                allowed_methods.append(f"{method} - Status: {status} (ALLOWED)")
            elif status == 405:
                results.append(f"{method} - Status: 405 (Method Not Allowed)")
            elif status == 403:
                results.append(f"{method} - Status: 403 (Forbidden)")
            elif status == 401:
                results.append(f"{method} - Status: 401 (Unauthorized)")
            else:
                results.append(f"{method} - Status: {status}")
                
        except requests.exceptions.RequestException as e:
            results.append(f"{method} - Error: {str(e)}")
    
    output = []
    if allowed_methods:
        output.append("⚠️ ALLOWED HTTP METHODS:")
        output.extend(allowed_methods)
        output.append("")
        # Check for dangerous methods
        dangerous = [m for m in allowed_methods if any(d in m for d in ['PUT', 'DELETE', 'PATCH'])]
        if dangerous:
            output.append("🚨 DANGEROUS METHODS ALLOWED (PUT/DELETE/PATCH):")
            output.extend(dangerous)
            output.append("")
    output.append("All method test results:")
    output.extend(results)
    
    return "\n".join(output)


@tool
def analyze_headers(url: str) -> str:
    """
    Analyze HTTP response headers for security misconfigurations.
    Checks for missing security headers, exposed server information, etc.
    
    Args:
        url: The URL to analyze
    
    Returns:
        String containing header analysis results
    """
    try:
        response = requests.get(url, timeout=config.REQUEST_TIMEOUT)
        headers = response.headers
        
        findings = []
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1',
            'Strict-Transport-Security': 'max-age',
            'Content-Security-Policy': None,  # Just check if present
            'Referrer-Policy': None,
        }
        
        # Check for missing security headers
        for header, expected_value in security_headers.items():
            if header not in headers:
                findings.append(f"❌ Missing: {header}")
            elif expected_value:
                if isinstance(expected_value, list):
                    if headers[header] not in expected_value:
                        findings.append(f"⚠️ {header}: {headers[header]} (should be one of {expected_value})")
                elif expected_value not in headers[header].lower():
                    findings.append(f"⚠️ {header}: {headers[header]} (should contain '{expected_value}')")
        
        # Check for information disclosure
        info_disclosure = []
        sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        for header in sensitive_headers:
            if header in headers:
                info_disclosure.append(f"⚠️ {header}: {headers[header]} (exposes server information)")
        
        # Check for CORS
        cors_headers = [h for h in headers.keys() if 'access-control' in h.lower()]
        if cors_headers:
            findings.append(f"🌐 CORS headers present: {', '.join(cors_headers)}")
        
        output = []
        if findings:
            output.append("🔒 SECURITY HEADER ANALYSIS:")
            output.extend(findings)
            output.append("")
        if info_disclosure:
            output.append("📢 INFORMATION DISCLOSURE:")
            output.extend(info_disclosure)
            output.append("")
        output.append("All response headers:")
        for key, value in list(headers.items())[:15]:  # First 15 headers
            output.append(f"  {key}: {value}")
        
        return "\n".join(output)
        
    except requests.exceptions.RequestException as e:
        return f"Error analyzing headers: {str(e)}"


@tool
def test_authentication_bypass(url: str, methods: Optional[List[str]] = None) -> str:
    """
    Test for authentication bypass vulnerabilities.
    Tests common bypass techniques like null bytes, case variations, path traversal, etc.
    
    Args:
        url: The URL to test (should be a protected endpoint)
        methods: Optional list of bypass methods to test (default: common bypasses)
    
    Returns:
        String containing authentication bypass test results
    """
    if methods is None:
        methods = ['null_byte', 'case_variation', 'trailing_slash', 'double_slash']
    
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    base_path = parsed.path
    
    results = []
    bypassed = []
    
    # Test different bypass techniques
    test_paths = []
    
    if 'null_byte' in methods:
        # Null byte injection (encoded)
        test_paths.append((base_path + '%00', 'Null byte'))
    
    if 'case_variation' in methods:
        # Case variations
        if 'admin' in base_path.lower():
            test_paths.append((base_path.replace('admin', 'Admin'), 'Case variation'))
            test_paths.append((base_path.replace('admin', 'ADMIN'), 'Case variation'))
    
    if 'trailing_slash' in methods:
        # Trailing slash
        if not base_path.endswith('/'):
            test_paths.append((base_path + '/', 'Trailing slash'))
        else:
            test_paths.append((base_path.rstrip('/'), 'Remove trailing slash'))
    
    if 'double_slash' in methods:
        # Double slash
        test_paths.append((base_path.replace('/', '//'), 'Double slash'))
    
    # Test each variation
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    for test_path, method_name in test_paths:
        test_url = base_url + test_path
        try:
            response = requests.get(test_url, timeout=config.REQUEST_TIMEOUT, allow_redirects=False)
            
            if response.status_code == 200:
                bypassed.append(f"{method_name} ({test_path}): Status 200 - Possible bypass!")
            elif response.status_code not in [401, 403, 404]:
                results.append(f"{method_name} ({test_path}): Status {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            results.append(f"{method_name}: Error - {str(e)}")
    
    output = []
    if bypassed:
        output.append("🚨 POTENTIAL AUTHENTICATION BYPASS:")
        output.extend(bypassed)
        output.append("")
    if results:
        output.append("Bypass test results:")
        output.extend(results)
    
    return "\n".join(output) if output else "No authentication bypass vulnerabilities detected."


@tool
def check_csrf_protection(url: str) -> str:
    """
    Check if a page/form has CSRF protection by looking for CSRF tokens.
    Tests both GET and POST requests to see if tokens are present.
    
    Args:
        url: The URL to check (typically a form page)
    
    Returns:
        String containing CSRF protection analysis
    """
    try:
        # Get the page
        response = requests.get(url, timeout=config.REQUEST_TIMEOUT)
        content = response.text.lower()
        
        findings = []
        
        # Look for CSRF tokens
        csrf_patterns = [
            r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)',
            r'name=["\']csrf[_-]?token["\']',
            r'_token["\']?\s*[:=]\s*["\']([^"\']+)',
            r'csrfmiddlewaretoken',
            r'x-csrf-token',
        ]
        
        found_tokens = []
        for pattern in csrf_patterns:
            matches = re.findall(pattern, content)
            if matches:
                found_tokens.append(f"Found CSRF token pattern: {pattern}")
        
        # Check for SameSite cookie attribute (CSRF protection)
        cookies = response.cookies
        samesite_cookies = [c.name for c in cookies if hasattr(c, 'samesite') and c.samesite]
        
        if found_tokens:
            findings.append("✓ CSRF tokens detected in page")
            findings.extend(found_tokens[:3])  # First 3 matches
        else:
            findings.append("⚠️ No CSRF tokens detected")
        
        if samesite_cookies:
            findings.append(f"✓ SameSite cookies present: {', '.join(samesite_cookies)}")
        
        # Check response headers for CSRF protection
        if 'X-CSRF-Token' in response.headers:
            findings.append("✓ X-CSRF-Token header present")
        
        output = ["🔐 CSRF PROTECTION ANALYSIS:"]
        output.extend(findings)
        
        return "\n".join(output)
        
    except requests.exceptions.RequestException as e:
        return f"Error checking CSRF protection: {str(e)}"


@tool
def fuzz_parameters(url: str, parameter: str, fuzz_values: Optional[List[str]] = None) -> str:
    """
    Fuzz a specific parameter with various values to find unexpected behavior.
    Useful for finding injection points, type confusion, or parameter pollution.
    
    Args:
        url: The URL with the parameter to fuzz
        parameter: The parameter name to fuzz
        fuzz_values: Optional list of values to test (default: common fuzz values)
    
    Returns:
        String containing fuzzing results
    """
    from urllib.parse import urlparse, parse_qs, urlencode
    
    if fuzz_values is None:
        fuzz_values = [
            '../../', '../../../', '....//....//',
            'null', 'NULL', 'None', 'undefined',
            '-1', '0', '999999', '-999999',
            'true', 'false', 'True', 'False',
            "'; DROP TABLE--", '<script>alert(1)</script>',
            '%00', '%0a', '%0d',
            '{{7*7}}', '${7*7}', '#{7*7}',
        ]
    
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query_params = parse_qs(parsed.query)
    
    results = []
    interesting = []
    
    # Get baseline response
    try:
        baseline = requests.get(url, timeout=config.REQUEST_TIMEOUT)
        baseline_status = baseline.status_code
        baseline_length = len(baseline.content)
    except:
        baseline_status = None
        baseline_length = None
    
    for value in fuzz_values[:10]:  # Limit to 10 values
        test_params = query_params.copy()
        test_params[parameter] = [value]
        test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"
        
        try:
            response = requests.get(test_url, timeout=config.REQUEST_TIMEOUT)
            
            # Compare with baseline
            if baseline_status:
                if response.status_code != baseline_status:
                    interesting.append(f"{parameter}={value}: Status changed from {baseline_status} to {response.status_code}")
                elif baseline_length and abs(len(response.content) - baseline_length) > 1000:
                    interesting.append(f"{parameter}={value}: Response length changed significantly")
            
            # Check for errors
            if response.status_code == 500:
                interesting.append(f"{parameter}={value}: Status 500 (server error)")
            elif 'error' in response.text.lower()[:500]:
                interesting.append(f"{parameter}={value}: Error message in response")
                
        except requests.exceptions.RequestException as e:
            results.append(f"{parameter}={value}: Error - {str(e)}")
    
    output = []
    if interesting:
        output.append("🔍 INTERESTING FUZZING RESULTS:")
        output.extend(interesting)
        output.append("")
    if results:
        output.append("Fuzzing test results:")
        output.extend(results[:5])
    
    return "\n".join(output) if output else f"No interesting results from fuzzing parameter '{parameter}'."


@tool
def check_information_disclosure(url: str) -> str:
    """
    Check for information disclosure vulnerabilities.
    Looks for exposed sensitive data like API keys, credentials, stack traces, etc.
    
    Args:
        url: The URL to check
    
    Returns:
        String containing information disclosure findings
    """
    try:
        response = requests.get(url, timeout=config.REQUEST_TIMEOUT)
        content = response.text
        
        findings = []
        
        # Patterns to look for
        patterns = {
            'API Keys': [
                r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})',
                r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})',
            ],
            'AWS Keys': [
                r'AKIA[0-9A-Z]{16}',
                r'aws[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([A-Z0-9]{20})',
            ],
            'Private Keys': [
                r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----',
            ],
            'Credentials': [
                r'password["\']?\s*[:=]\s*["\']([^"\']{6,})',
                r'passwd["\']?\s*[:=]\s*["\']([^"\']{6,})',
            ],
            'Stack Traces': [
                r'at\s+\w+\.\w+\([^)]+\)',
                r'File "[^"]+", line \d+',
                r'Traceback \(most recent call last\)',
            ],
            'Database Info': [
                r'mysql://[^"\'\s]+',
                r'postgresql://[^"\'\s]+',
                r'mongodb://[^"\'\s]+',
            ],
        }
        
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings.append(f"⚠️ {category}: Found potential {category.lower()} in response")
                    # Show first match (truncated)
                    match_preview = str(matches[0])[:50] if matches else ""
                    if match_preview:
                        findings.append(f"   Preview: {match_preview}...")
                    break  # Only report once per category
        
        # Check for exposed file paths
        file_paths = re.findall(r'[A-Z]:\\[^"\'\s<>]+|/[^"\'\s<>]+\.(php|py|js|java|rb)', content)
        if file_paths:
            findings.append(f"⚠️ Exposed file paths: Found {len(file_paths)} potential file paths")
        
        # Check for email addresses
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
        if len(emails) > 5:  # More than 5 emails might be sensitive
            findings.append(f"⚠️ Email addresses: Found {len(emails)} email addresses in response")
        
        output = []
        if findings:
            output.append("📢 INFORMATION DISCLOSURE CHECK:")
            output.extend(findings)
        else:
            output.append("✓ No obvious information disclosure detected")
        
        return "\n".join(output)
        
    except requests.exceptions.RequestException as e:
        return f"Error checking information disclosure: {str(e)}"


def get_tools() -> List:
    """
    Get all available tools for the agent
    
    Returns:
        List of tool instances
    """
    tools = [
        scan_website,
        check_endpoint,
        check_admin_endpoints,
        test_sql_injection,
        test_xss,
        discover_api_endpoints,
        enumerate_directories,
        test_http_methods,
        analyze_headers,
        test_authentication_bypass,
        check_csrf_protection,
        fuzz_parameters,
        check_information_disclosure,
    ]
    
    # Add custom Playwright tools if available
    try:
        from playwright.sync_api import sync_playwright
        # Test if playwright works
        tools.extend([
            navigate_page,
            take_screenshot,
            check_page_content,
        ])
    except ImportError:
        pass  # Playwright not installed, skip browser tools
    except Exception:
        pass  # Playwright installed but browsers not installed
    
    # Add Browser-use/Playwright browser interaction tool
    browser_use_tools = get_browser_use_tools()
    if browser_use_tools:
        tools.extend(browser_use_tools)
    
    return tools

