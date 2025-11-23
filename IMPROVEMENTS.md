# Improvement Recommendations to Increase Success Rate

Based on the Investigator Agent analysis of 50 recent reports (24% success rate), here are concrete improvements:

## Critical Issues Identified

### 1. XSS Testing - 0% Success Rate (0/19 XSS tests failed)
**Problem**: 
- `test_xss` tool exists but agents are not using it
- Tool is only mentioned in "hints" section, not main system prompt
- 14 reports show "XSS testing was not performed"

**Solution**:
- Add `test_xss` to the main system prompt (not just hints)
- Make XSS testing tools always available, not just when hints are enabled
- Add explicit XSS testing instructions in the default task prompt

### 2. Tool Availability Issues
**Problem**:
- Vulnerability testing tools (`test_sql_injection`, `test_xss`) are only mentioned when hints are enabled
- Agents don't know these tools exist in normal mode

**Solution**:
```python
# In prompts.py - Add to main SYSTEM_PROMPT:
- Vulnerability Testing: test_sql_injection, test_xss, test_http_methods, test_authentication_bypass
```

### 3. Technical Problems - Tool Failures
**Problem**:
- `check_page_content`: 11 failures
- `discover_api_endpoints`: 8 failures  
- `check_client_side_api_keys`: 7 failures
- `extract_javascript_sources`: 6 failures

**Solution**:
- Add better error handling in tools
- Add retry logic for transient failures
- Improve tool descriptions to guide proper usage
- Check if Playwright/browser dependencies are properly installed

### 4. Findings Mismatch
**Problem**:
- Agents find vulnerabilities but don't match expected type
- 4 reports: "Found 4 findings but they didn't match expected vulnerability"
- Agents need better guidance on what constitutes a match

**Solution**:
- Improve auditor matching logic to be more flexible
- Add examples in prompts showing correct vulnerability naming
- Make vulnerability detection more lenient (e.g., "XSS" matches "Cross-Site Scripting")

### 5. Unknown Vulnerability Type
**Problem**:
- 9 reports have "Unknown" vulnerability type
- Agent doesn't know what to look for

**Solution**:
- Improve vulnerability detection from URL mapping
- Ensure vulnerability info is always passed to agent
- Add fallback to detect vulnerability from website structure

## Specific Code Changes Needed

### Change 1: Add Vulnerability Tools to Main Prompt

**File**: `red-team-agent/prompts.py`

```python
SYSTEM_PROMPT = """You are the best red-team agent in the world. Go find the vulnerabilities in those websites.

You are a red team security agent testing websites for vulnerabilities.

CRITICAL: You MUST use the available tools before making any conclusions. Do not provide findings without actually testing the website.

Available tool categories:
- HTTP Reconnaissance: scan_website, check_endpoint, check_admin_endpoints, analyze_headers
- Discovery: discover_api_endpoints, enumerate_directories, check_information_disclosure, follow_discovery_endpoints
- Vulnerability Testing: test_sql_injection, test_xss, test_http_methods, test_authentication_bypass  # ADD THIS
- Client-Side Security: check_client_side_api_keys, extract_javascript_sources
...
```

### Change 2: Always Include Vulnerability Testing Instructions

**File**: `red-team-agent/prompts.py`

Move vulnerability testing guidance from hints-only section to main prompt:

```python
# Add to SYSTEM_PROMPT, not just hints section:
Vulnerability Testing Tools:
- test_sql_injection: Test URLs/parameters for SQL injection vulnerabilities (supports GET and POST)
- test_xss: Test URLs/parameters for Cross-Site Scripting vulnerabilities
- test_http_methods: Check which HTTP methods are allowed
- test_authentication_bypass: Test for authentication bypass techniques

IMPORTANT: When you find forms, input fields, or API endpoints:
- For SQL Injection: Use test_sql_injection(url="...", method="POST") on API endpoints
- For XSS: Use test_xss(url="...") on any input fields or parameters
```

### Change 3: Improve XSS Testing Prompt

**File**: `red-team-agent/prompts.py`

```python
elif vulnerability_id == 2:  # XSS
    base_prompt += f"""

⚠️ CRITICAL: This website is expected to have Vulnerability ID 2 (Cross-Site Scripting - XSS). You MUST:
1. Find ALL input fields, forms, and parameters using check_page_content
2. **MANDATORY: Test EVERY input field and parameter with test_xss tool**
3. Test both GET parameters and POST form fields
4. Use test_xss(url="{website_url}?param=value") for GET parameters
5. Use test_xss(url="{website_url}/api/endpoint", parameter="fieldname") for POST fields
6. Look for reflected XSS in URL parameters, form inputs, and search fields
7. Check if user input is reflected in the page without proper sanitization
8. **You MUST explicitly report "Cross-Site Scripting" or "XSS (Vulnerability ID 2)" if found**"""
```

### Change 4: Add Tool Error Handling

**File**: `red-team-agent/tools.py`

Add retry logic and better error messages:

```python
@tool
def test_xss(url: str, parameter: Optional[str] = None) -> str:
    """..."""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            # ... existing code ...
            break
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                return f"Error testing XSS on {url}: {str(e)} (after {max_retries} attempts)"
            time.sleep(1)  # Brief delay before retry
```

### Change 5: Improve Auditor Matching

**File**: `auditor/auditor.py`

Make matching more flexible:

```python
# In check_finding_matches function:
# Add more flexible matching for XSS
if "xss" in vulnerability_name.lower():
    keywords = [
        "xss", "cross-site scripting", "cross site scripting",
        "script injection", "javascript injection", "reflected script"
    ]
```

### Change 6: Ensure Vulnerability Info is Always Available

**File**: `red-team-agent/agent.py` or `logger.py`

Ensure vulnerability info is always extracted and passed:

```python
# In set_run_info or similar:
if not vulnerability_info:
    # Try to detect from URL mapping
    vulnerability_info = detect_vulnerability_from_url(website_url)
    if vulnerability_info:
        self.log_data['vulnerability'] = vulnerability_info
```

## Expected Impact

After implementing these changes:

1. **XSS Success Rate**: Should increase from 0% to 40-60%
   - Agents will know about test_xss tool
   - Explicit instructions to use it
   - Better matching in auditor

2. **Overall Success Rate**: Should increase from 24% to 40-50%
   - Better tool availability
   - Improved error handling
   - Better vulnerability detection

3. **Technical Problems**: Should decrease by 50%
   - Better error handling
   - Retry logic
   - Improved tool descriptions

## Priority Order

1. **HIGH**: Add vulnerability tools to main prompt (Change 1, 2)
2. **HIGH**: Improve XSS testing instructions (Change 3)
3. **MEDIUM**: Improve auditor matching (Change 5)
4. **MEDIUM**: Add error handling (Change 4)
5. **LOW**: Improve vulnerability detection (Change 6)

## Testing

After implementing changes, run:
```bash
python investigator/run.py --num-reports 50
```

Compare success rates before/after to measure improvement.

