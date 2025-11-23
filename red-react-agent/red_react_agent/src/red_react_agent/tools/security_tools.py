"""Security tools for the red-react-agent crew."""
import base64
import json
import os
import re
from typing import Type
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

import requests
from requests.cookies import RequestsCookieJar
from playwright.sync_api import sync_playwright
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

# Shared session and settings
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": os.getenv("HTTP_USER_AGENT", "RedReactAgent/1.0")})
TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))
TARGET_DOMAIN = os.getenv("TARGET_DOMAIN")
LOG_DIR = os.getenv("LOG_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "..", "logs"))


def _in_scope(url: str) -> bool:
    if not TARGET_DOMAIN:
        return True
    host = urlparse(url).hostname or ""
    return TARGET_DOMAIN in host


def _scope_guard(url: str):
    if not _in_scope(url):
        return {"status": "error", "error": f"out_of_scope:{url}", "action": "scope_check"}
    return None


def _fmt(data) -> str:
    try:
        return json.dumps(data, indent=2)
    except Exception:
        return str(data)


def _scroll_page(page, max_steps: int = 20, wait_ms: int = 600):
    """Scroll downward with pauses to trigger lazy-loaded content."""
    previous_height = -1
    for _ in range(max_steps):
        current_height = page.evaluate(
            "() => { const { scrollHeight } = document.documentElement; window.scrollTo(0, scrollHeight); return scrollHeight; }"
        )
        if current_height == previous_height:
            break
        previous_height = current_height
        page.wait_for_timeout(wait_ms)
    page.wait_for_timeout(wait_ms)


def _save_screenshot(page, prefix: str = "screenshot"):
    import datetime
    from pathlib import Path

    shot_dir = Path(LOG_DIR)
    shot_dir.mkdir(exist_ok=True, parents=True)
    path = shot_dir / f"{prefix}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.png"
    page.screenshot(path=str(path), full_page=True)
    return str(path)


def _jar_from_playwright_cookies(cookies, fallback_domain: str):
    jar = RequestsCookieJar()
    for c in cookies:
        jar.set(
            c.get("name", ""),
            c.get("value", ""),
            domain=c.get("domain") or fallback_domain,
            path=c.get("path") or "/",
        )
    return jar


LEAK_PATTERNS = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("gcp_api_key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("stripe_live_key", r"sk_live_[0-9A-Za-z]{24,}"),
    ("stripe_test_key", r"sk_test_[0-9A-Za-z]{24,}"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,48}"),
    ("twilio_key", r"SK[0-9a-fA-F]{32}"),
    ("jwt_token", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
]


def _decode_b64url(segment: str):
    missing_padding = len(segment) % 4
    if missing_padding:
        segment += "=" * (4 - missing_padding)
    try:
        return base64.urlsafe_b64decode(segment.encode()).decode()
    except Exception:
        return None


def _decode_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_raw = _decode_b64url(parts[0])
    payload_raw = _decode_b64url(parts[1])
    try:
        header = json.loads(header_raw) if header_raw else None
        payload = json.loads(payload_raw) if payload_raw else None
    except Exception:
        header, payload = header_raw, payload_raw
    return {"header": header, "payload": payload}


def _detect_secret_leaks(text: str, limit: int = 50):
    leaks = []
    for name, pattern in LEAK_PATTERNS:
        for match in re.finditer(pattern, text):
            token = match.group(0)
            leak = {"type": name, "value_preview": f"{token[:6]}...{token[-4:]}"}
            if name == "jwt_token":
                decoded = _decode_jwt(token)
                if decoded:
                    leak["decoded"] = decoded
            leaks.append(leak)
            if len(leaks) >= limit:
                return leaks
    return leaks


class URLInput(BaseModel):
    url: str = Field(..., description="Target URL")


class ScanWebsiteTool(BaseTool):
    name: str = "scan_website"
    description: str = "GET the URL and return status and headers."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        try:
            resp = SESSION.get(url, timeout=TIMEOUT)
            return _fmt({
                "action": self.name,
                "url": resp.url,
                "status": resp.status_code,
                "headers": dict(resp.headers),
            })
        except Exception as exc:
            return _fmt({"action": self.name, "error": str(exc)})


class AnalyzeHeadersTool(BaseTool):
    name: str = "analyze_headers"
    description: str = "Analyze security headers on the URL (HSTS, X-Frame-Options, CSP, etc.)."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        try:
            resp = SESSION.get(url, timeout=TIMEOUT)
            headers = dict(resp.headers)
            expected = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": None,
                "Strict-Transport-Security": None,
                "Content-Security-Policy": None,
                "Referrer-Policy": None,
            }
            missing = []
            issues = []
            for h, must_contain in expected.items():
                if h not in headers:
                    missing.append(h)
                elif must_contain and must_contain not in headers[h]:
                    issues.append({"header": h, "issue": f"expected '{must_contain}'", "value": headers[h]})
            return _fmt({
                "action": self.name,
                "url": resp.url,
                "status": resp.status_code,
                "missing": missing,
                "issues": issues,
                "headers_sample": {k: headers[k] for k in list(headers.keys())[:15]},
            })
        except Exception as exc:
            return _fmt({"action": self.name, "error": str(exc)})


class TestHttpMethodsTool(BaseTool):
    name: str = "test_http_methods"
    description: str = "Probe allowed HTTP methods on a URL."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        results = []
        for m in methods:
            try:
                resp = SESSION.request(m, url, timeout=TIMEOUT, allow_redirects=False)
                results.append({"method": m, "status": resp.status_code})
            except Exception as exc:
                results.append({"method": m, "error": str(exc)})
        return _fmt({"action": self.name, "url": url, "results": results})


class DiscoverApiEndpointsTool(BaseTool):
    name: str = "discover_api_endpoints"
    description: str = "Check common API paths (/api, /api/v1, /graphql, /swagger)."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        paths = ["/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/swagger.json", "/openapi.json", "/api/auth", "/api/users", "/api/search"]
        results = []
        for path in paths:
            target = base + path
            try:
                resp = SESSION.get(target, timeout=TIMEOUT, allow_redirects=False)
                results.append({"path": path, "status": resp.status_code})
            except Exception as exc:
                results.append({"path": path, "error": str(exc)})
        found = [r for r in results if isinstance(r.get("status"), int) and r["status"] in (200, 401, 403)]
        return _fmt({"action": self.name, "base": base, "found": found, "results": results})


class EnumerateDirectoriesTool(BaseTool):
    name: str = "enumerate_directories"
    description: str = "Check common admin/config/backup paths."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        paths = ["/admin", "/dashboard", "/backup", "/.git", "/.env", "/robots.txt", "/sitemap.xml", "/config.php", "/swagger.json", "/openapi.json"]
        results = []
        for path in paths:
            target = base + path
            try:
                resp = SESSION.get(target, timeout=TIMEOUT, allow_redirects=False)
                results.append({"path": path, "status": resp.status_code})
            except Exception as exc:
                results.append({"path": path, "error": str(exc)})
        return _fmt({"action": self.name, "base": base, "results": results})


class CheckAdminEndpointsTool(BaseTool):
    name: str = "check_admin_endpoints"
    description: str = "Test common admin endpoints for unauthenticated access."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        paths = ["/admin", "/dashboard", "/management", "/admin/index", "/administrator", "/wp-admin", "/panel"]
        results = []
        for path in paths:
            target = base + path
            try:
                resp = SESSION.get(target, timeout=TIMEOUT, allow_redirects=False)
                results.append({"path": path, "status": resp.status_code, "location": resp.headers.get("Location", "")})
            except Exception as exc:
                results.append({"path": path, "error": str(exc)})
        exposed = [r for r in results if isinstance(r.get("status"), int) and r["status"] == 200]
        return _fmt({"action": self.name, "base": base, "exposed": exposed, "results": results})


class InfoDisclosureTool(BaseTool):
    name: str = "info_disclosure"
    description: str = "Search response for secrets/keys/stack traces."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        try:
            resp = SESSION.get(url, timeout=TIMEOUT)
            text = resp.text
            signals = []
            if "AKIA" in text:
                signals.append("aws_key_pattern")
            if "BEGIN PRIVATE KEY" in text:
                signals.append("private_key_block")
            if "password" in text.lower():
                signals.append("password_string_present")
            leaks = _detect_secret_leaks(text, limit=30)
            return _fmt({
                "action": self.name,
                "url": resp.url,
                "status": resp.status_code,
                "signals": signals,
                "leaks": leaks,
                "body_preview": text[:300],
            })
        except Exception as exc:
            return _fmt({"action": self.name, "error": str(exc)})


class RenderPageTool(BaseTool):
    name: str = "render_page"
    description: str = "Render URL with Playwright (headless) and return title/content preview."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="networkidle", timeout=15000)
                page.wait_for_timeout(2000)
                _scroll_page(page)  # wait/scroll until height stops changing
                html = page.content()
                max_len = 50000  # keep payload manageable while showing most of the page
                data = {
                    "action": self.name,
                    "url": page.url,
                    "title": page.title(),
                    "content_preview": html[:max_len],
                    "content_length": len(html),
                    "truncated": len(html) > max_len,
                }
                browser.close()
                return _fmt(data)
        except Exception as exc:
            return _fmt({"action": self.name, "error": str(exc)})


class DiscoverFormsTool(BaseTool):
    name: str = "discover_forms"
    description: str = "Render page and return form actions/methods/input names and clickable targets (links/buttons)."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        forms = []
        click_targets = []
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="networkidle", timeout=15000)
                page.wait_for_timeout(2000)
                _scroll_page(page)
                for form in page.query_selector_all("form")[:10]:
                    action_attr = form.get_attribute("action") or page.url
                    action = urljoin(page.url, action_attr)
                    method = (form.get_attribute("method") or "GET").upper()
                    inputs = []
                    for inp in form.query_selector_all("input, textarea, select")[:15]:
                        inputs.append({
                            "name": inp.get_attribute("name"),
                            "type": inp.get_attribute("type") or inp.evaluate("el => el.tagName"),
                        })
                    forms.append({"action": action, "method": method, "inputs": inputs})

                seen = set()

                def add_target(raw_url: str | None, kind: str, label: str):
                    if not raw_url:
                        return
                    resolved = urljoin(page.url, raw_url)
                    if resolved in seen:
                        return
                    seen.add(resolved)
                    click_targets.append({
                        "type": kind,
                        "text": (label or "").strip()[:120],
                        "target": resolved,
                        "in_scope": _in_scope(resolved),
                    })

                max_targets = 40
                for link in page.query_selector_all("a[href]"):
                    if len(click_targets) >= max_targets:
                        break
                    href = link.get_attribute("href")
                    text = link.inner_text() or link.get_attribute("aria-label") or ""
                    add_target(href, "link", text)

                if len(click_targets) < max_targets:
                    for btn in page.query_selector_all("button, [role='button'], input[type=button], input[type=submit]"):
                        if len(click_targets) >= max_targets:
                            break
                        text = btn.inner_text() or btn.get_attribute("value") or btn.get_attribute("aria-label") or ""
                        action = btn.evaluate("el => { const f = el.form || el.closest('form'); return f ? (f.action || f.getAttribute('action')) : null; }")
                        add_target(action or page.url, "button", text)
                browser.close()
            return _fmt({"action": self.name, "forms": forms, "click_targets": click_targets})
        except Exception as exc:
            return _fmt({"action": self.name, "error": str(exc)})


class ExplorePageInput(BaseModel):
    url: str = Field(..., description="Target URL to explore for clickable targets.")
    max_targets: int = Field(20, description="Maximum clickable items to collect.")
    max_clicks: int = Field(5, description="Maximum in-scope targets to follow.")


class ExploreClickTargetsTool(BaseTool):
    name: str = "explore_click_targets"
    description: str = "Use Playwright to extract links/buttons and follow a few to surface new URLs."
    args_schema: Type[BaseModel] = ExplorePageInput

    def _run(self, url: str, max_targets: int = 20, max_clicks: int = 5) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        click_targets = []
        followed = []
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="networkidle", timeout=15000)
                seen = set()

                def add_target(raw_url: str | None, kind: str, label: str):
                    if not raw_url:
                        return
                    resolved = urljoin(page.url, raw_url)
                    if resolved in seen:
                        return
                    seen.add(resolved)
                    click_targets.append({
                        "type": kind,
                        "text": (label or "").strip()[:120],
                        "target": resolved,
                        "in_scope": _in_scope(resolved),
                    })

                for link in page.query_selector_all("a[href]"):
                    if len(click_targets) >= max_targets:
                        break
                    href = link.get_attribute("href")
                    text = link.inner_text()
                    add_target(href, "link", text or "")

                if len(click_targets) < max_targets:
                    for btn in page.query_selector_all("button, [role='button'], input[type=button], input[type=submit]"):
                        if len(click_targets) >= max_targets:
                            break
                        text = btn.inner_text() or btn.get_attribute("value") or btn.get_attribute("aria-label") or ""
                        action = btn.evaluate("el => { const f = el.form || el.closest('form'); return f ? (f.action || f.getAttribute('action')) : null; }")
                        add_target(action, "button_form_action", text)

                for target in click_targets:
                    if len(followed) >= max_clicks:
                        break
                    if not target["in_scope"]:
                        continue
                    nav_page = browser.new_page()
                    try:
                        resp = nav_page.goto(target["target"], wait_until="domcontentloaded", timeout=10000)
                        followed.append({
                            "target": target["target"],
                            "status": resp.status if resp else None,
                            "final_url": nav_page.url,
                            "title": nav_page.title(),
                        })
                    except Exception as exc:
                        followed.append({"target": target["target"], "error": str(exc)})
                    finally:
                        nav_page.close()
                browser.close()
                return _fmt({
                    "action": self.name,
                    "url": page.url,
                    "title": page.title(),
                    "click_targets": click_targets,
                    "followed": followed,
                })
        except Exception as exc:
            return _fmt({"action": self.name, "error": str(exc)})


class StatefulExploreInput(BaseModel):
    url: str = Field(..., description="Starting URL to explore.")
    max_hops: int = Field(5, description="Maximum navigation hops to follow in-scope links/buttons.")
    per_hop_targets: int = Field(5, description="Max targets to try per page.")


class StatefulExploreTool(BaseTool):
    name: str = "stateful_explore"
    description: str = "Stateful click-through exploration with Playwright; keeps cookies and screenshots each hop."
    args_schema: Type[BaseModel] = StatefulExploreInput

    def _run(self, url: str, max_hops: int = 5, per_hop_targets: int = 5) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)

        def collect_targets(page, cap: int):
            seen = set()
            targets = []

            def add_target(raw_url: str | None, kind: str, label: str):
                if not raw_url:
                    return
                resolved = urljoin(page.url, raw_url)
                if resolved in seen:
                    return
                seen.add(resolved)
                targets.append({
                    "type": kind,
                    "text": (label or "").strip()[:120],
                    "target": resolved,
                    "in_scope": _in_scope(resolved),
                })

            for link in page.query_selector_all("a[href]"):
                if len(targets) >= cap:
                    break
                add_target(link.get_attribute("href"), "link", link.inner_text() or link.get_attribute("aria-label") or "")

            if len(targets) < cap:
                for btn in page.query_selector_all("button, [role='button'], input[type=button], input[type=submit]"):
                    if len(targets) >= cap:
                        break
                    text = btn.inner_text() or btn.get_attribute("value") or btn.get_attribute("aria-label") or ""
                    action = btn.evaluate("el => { const f = el.form || el.closest('form'); return f ? (f.action || f.getAttribute('action')) : null; }")
                    add_target(action or page.url, "button", text)
            return targets

        hops = []
        visited = set()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                resp = page.goto(url, wait_until="networkidle", timeout=15000)
                page.wait_for_timeout(6000)
                _scroll_page(page)
                visited.add(page.url)
                hops.append({
                    "url": page.url,
                    "status": resp.status if resp else None,
                    "title": page.title(),
                    "screenshot": _save_screenshot(page, prefix="stateful_hop0"),
                })

                for i in range(max_hops):
                    targets = collect_targets(page, per_hop_targets)
                    next_target = None
                    for t in targets:
                        if t["in_scope"] and t["target"] not in visited:
                            next_target = t
                            break
                    if not next_target:
                        break
                    try:
                        nav_resp = page.goto(next_target["target"], wait_until="networkidle", timeout=12000)
                        page.wait_for_timeout(4000)
                        _scroll_page(page)
                        visited.add(page.url)
                        hops.append({
                            "url": page.url,
                            "from": next_target,
                            "status": nav_resp.status if nav_resp else None,
                            "title": page.title(),
                            "screenshot": _save_screenshot(page, prefix=f"stateful_hop{i+1}"),
                        })
                    except Exception as exc:
                        hops.append({"from": next_target, "error": str(exc)})
                        break

                browser.close()
                return _fmt({"action": self.name, "start_url": url, "hops": hops})
        except Exception as exc:
            return _fmt({"action": self.name, "error": str(exc)})


class ScreenshotTool(BaseTool):
    name: str = "screenshot_page"
    description: str = "Take a screenshot of the URL using Playwright."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        try:
            import datetime
            from pathlib import Path
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="networkidle", timeout=15000)
                page.wait_for_timeout(6000)
                _scroll_page(page)
                shot_dir = Path(LOG_DIR)
                shot_dir.mkdir(exist_ok=True, parents=True)
                path = shot_dir / f"screenshot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                page.screenshot(path=str(path))
                browser.close()
                return _fmt({"action": self.name, "path": str(path)})
        except Exception as exc:
            return _fmt({"action": self.name, "error": str(exc)})


class SqliTestInput(BaseModel):
    url: str = Field(..., description="Target URL or endpoint.")
    method: str = Field("auto", description="GET, POST, or auto.")
    param: str | None = Field(None, description="Optional parameter name to target.")


class SqliTestTool(BaseTool):
    name: str = "sqli_test"
    description: str = "Test URL/endpoint for basic SQL injection indicators using common payloads."
    args_schema: Type[BaseModel] = SqliTestInput

    def _run(self, url: str, method: str = "auto", param: str | None = None) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        payloads = ["' OR '1'='1", "' UNION SELECT NULL--", "1' AND '1'='1"]
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        targets = [param] if param else (list(params.keys()) or ["id", "q", "search", "username"])
        methods = ["GET", "POST"] if method.lower() == "auto" else [method.upper()]
        findings = []
        for m in methods:
            for t in targets:
                for payload in payloads:
                    try:
                        if m == "GET":
                            q = params.copy()
                            q[t] = payload
                            resp = SESSION.get(f"{base}?{urlencode(q, doseq=True)}", timeout=TIMEOUT)
                        else:
                            resp = SESSION.post(base, json={t: payload}, timeout=TIMEOUT)
                        body = resp.text.lower()
                        if any(err in body for err in ["sql", "syntax", "sqlite", "mysql", "postgres"]):
                            findings.append({"method": m, "param": t, "payload": payload, "signal": "sql_error"})
                        elif resp.status_code == 500:
                            findings.append({"method": m, "param": t, "payload": payload, "signal": "http_500"})
                    except Exception as exc:
                        findings.append({"method": m, "param": t, "error": str(exc)})
        return _fmt({"action": self.name, "target": url, "findings": findings})


class XssTestInput(BaseModel):
    url: str = Field(..., description="Target URL with query parameter or form endpoint.")
    param: str | None = Field(None, description="Parameter to target (default common params).")


class XssTestTool(BaseTool):
    name: str = "xss_test"
    description: str = "Test URL for reflected XSS indicators with common payloads."
    args_schema: Type[BaseModel] = XssTestInput

    def _run(self, url: str, param: str | None = None) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'\"><svg/onload=alert(1)>",
        ]
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        targets = [param] if param else (list(params.keys()) or ["q", "search", "name"])
        findings = []
        for t in targets:
            for payload in payloads:
                try:
                    q = params.copy()
                    q[t] = payload
                    resp = SESSION.get(f"{base}?{urlencode(q, doseq=True)}", timeout=TIMEOUT)
                    if payload in resp.text:
                        findings.append({"param": t, "payload": payload, "signal": "reflected"})
                except Exception as exc:
                    findings.append({"param": t, "error": str(exc)})
        return _fmt({"action": self.name, "target": url, "findings": findings})


class CsrfCheckTool(BaseTool):
    name: str = "csrf_check"
    description: str = "Check for CSRF tokens in a page response."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        try:
            resp = SESSION.get(url, timeout=TIMEOUT)
            text = resp.text.lower()
            has_token = any(k in text for k in ["csrf", "xsrf", "_token"])
            return _fmt({"action": self.name, "url": resp.url, "status": resp.status_code, "has_token": has_token})
        except Exception as exc:
            return _fmt({"action": self.name, "error": str(exc)})


class CorsCheckTool(BaseTool):
    name: str = "cors_check"
    description: str = "Check for permissive CORS headers via GET and OPTIONS."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        results = []
        for method in ("GET", "OPTIONS"):
            try:
                resp = SESSION.request(method, url, timeout=TIMEOUT, allow_redirects=False)
                results.append({
                    "method": method,
                    "status": resp.status_code,
                    "acao": resp.headers.get("Access-Control-Allow-Origin"),
                    "acac": resp.headers.get("Access-Control-Allow-Credentials"),
                    "acm": resp.headers.get("Access-Control-Allow-Methods"),
                })
            except Exception as exc:
                results.append({"method": method, "error": str(exc)})
        permissive = [
            r for r in results
            if isinstance(r.get("acao"), str) and (r["acao"] == "*" or "localhost" in r["acao"])
        ]
        return _fmt({"action": self.name, "url": url, "results": results, "permissive": permissive})


class AuthBypassTool(BaseTool):
    name: str = "auth_bypass"
    description: str = "Try common auth-bypass path tricks (trailing slash, case changes, null byte encoded)."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        variants = [
            path + "%00",
            path + "/",
            path.replace("admin", "Admin") if "admin" in path.lower() else path,
            path.replace("/", "//"),
        ]
        results = []
        for v in variants:
            try:
                resp = SESSION.get(base + v, timeout=TIMEOUT, allow_redirects=False)
                results.append({"variant": v, "status": resp.status_code, "location": resp.headers.get("Location", "")})
            except Exception as exc:
                results.append({"variant": v, "error": str(exc)})
        bypassed = [r for r in results if isinstance(r.get("status"), int) and r["status"] == 200]
        return _fmt({"action": self.name, "base": base, "results": results, "bypassed": bypassed})


class FuzzParameterInput(BaseModel):
    url: str = Field(..., description="Target URL with query parameter to fuzz.")
    param: str = Field(..., description="Parameter name to fuzz.")


class FuzzParameterTool(BaseTool):
    name: str = "fuzz_parameter"
    description: str = "Fuzz a query parameter with common payloads and report status/length changes."
    args_schema: Type[BaseModel] = FuzzParameterInput

    def _run(self, url: str, param: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        values = ["../../", "%00", "<script>alert(1)</script>", "' OR 1=1--", "999999"]
        findings = []
        for val in values:
            try:
                q = params.copy()
                q[param] = val
                resp = SESSION.get(f"{base}?{urlencode(q, doseq=True)}", timeout=TIMEOUT)
                findings.append({"value": val, "status": resp.status_code, "len": len(resp.content)})
            except Exception as exc:
                findings.append({"value": val, "error": str(exc)})
        return _fmt({"action": self.name, "target": url, "param": param, "findings": findings})


class FormFuzzInput(BaseModel):
    url: str = Field(..., description="Page URL whose forms should be fuzzed.")
    max_forms: int = Field(5, description="Maximum number of forms to fuzz.")


class FormFuzzTool(BaseTool):
    name: str = "form_fuzz"
    description: str = "Use Playwright to discover forms and fuzz inputs for XSS/SQLi with cookies preserved."
    args_schema: Type[BaseModel] = FormFuzzInput

    def _run(self, url: str, max_forms: int = 5) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)

        payloads = [
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "\" onmouseover=\"alert(1)",
        ]
        findings = []
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                page.goto(url, wait_until="networkidle", timeout=15000)
                page.wait_for_timeout(4000)
                _scroll_page(page)
                cookies = _jar_from_playwright_cookies(context.cookies(), urlparse(page.url).hostname or "")

                forms = page.query_selector_all("form")[:max_forms]
                for form in forms:
                    action_attr = form.get_attribute("action") or page.url
                    action = urljoin(page.url, action_attr)
                    method = (form.get_attribute("method") or "GET").upper()
                    inputs = [inp for inp in form.query_selector_all("input, textarea, select") if inp.get_attribute("name")]
                    if not inputs:
                        continue
                    for payload in payloads:
                        data = {inp.get_attribute("name"): payload for inp in inputs[:8]}
                        try:
                            if method == "POST":
                                resp = SESSION.post(action, data=data, timeout=TIMEOUT, allow_redirects=False, cookies=cookies)
                            else:
                                resp = SESSION.get(action, params=data, timeout=TIMEOUT, allow_redirects=False, cookies=cookies)
                            body = resp.text.lower()
                            signal = None
                            if payload.lower() in body:
                                signal = "reflected"
                            elif any(err in body for err in ["sql", "syntax", "sqlite", "mysql", "postgres"]):
                                signal = "sql_error"
                            elif resp.status_code == 500:
                                signal = "http_500"
                            if signal:
                                findings.append({
                                    "form_action": action,
                                    "method": method,
                                    "payload": payload,
                                    "signal": signal,
                                    "status": resp.status_code,
                                })
                        except Exception as exc:
                            findings.append({"form_action": action, "method": method, "payload": payload, "error": str(exc)})
                browser.close()
            return _fmt({"action": self.name, "url": url, "findings": findings})
        except Exception as exc:
            return _fmt({"action": self.name, "error": str(exc)})


class ApiKeyLeakScanTool(BaseTool):
    name: str = "api_key_leak_scan"
    description: str = "Fetch URL and scan for leaked API keys/tokens/JWTs."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        try:
            resp = SESSION.get(url, timeout=TIMEOUT)
            leaks = _detect_secret_leaks(resp.text, limit=50)
            return _fmt({
                "action": self.name,
                "url": resp.url,
                "status": resp.status_code,
                "leaks": leaks,
                "body_preview": resp.text[:300],
            })
        except Exception as exc:
            return _fmt({"action": self.name, "error": str(exc)})


class JwtDecodeInput(BaseModel):
    token: str = Field(..., description="JWT string to decode (no signature verification).")


class JwtDecodeTool(BaseTool):
    name: str = "jwt_decode"
    description: str = "Decode JWT header and payload without verifying signature."
    args_schema: Type[BaseModel] = JwtDecodeInput

    def _run(self, token: str) -> str:
        decoded = _decode_jwt(token)
        if not decoded:
            return _fmt({"action": self.name, "error": "invalid_jwt"})
        return _fmt({"action": self.name, "decoded": decoded})


class SitemapTool(BaseTool):
    name: str = "sitemap_check"
    description: str = "Fetch sitemap.xml (and robots.txt for Sitemap entries) and list on-scope URLs to inspect."
    args_schema: Type[BaseModel] = URLInput

    def _run(self, url: str) -> str:
        guard = _scope_guard(url)
        if guard:
            return _fmt(guard)
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        urls = set()
        errors = []

        def fetch(path: str):
            try:
                resp = SESSION.get(base + path, timeout=TIMEOUT)
                return resp
            except Exception as exc:
                errors.append(f"{path}:{exc}")
                return None

        # robots.txt might point to sitemap
        robots = fetch("/robots.txt")
        if robots and robots.ok:
            for line in robots.text.splitlines():
                if "sitemap:" in line.lower():
                    try:
                        sm_url = line.split(":", 1)[1].strip()
                        sm_resp = SESSION.get(sm_url, timeout=TIMEOUT)
                        if sm_resp.ok:
                            urls.update(_extract_sitemap_urls(sm_resp.text, sm_url))
                    except Exception as exc:
                        errors.append(f"robots-sitemap:{exc}")

        # default sitemap.xml
        sitemap = fetch("/sitemap.xml")
        if sitemap and sitemap.ok:
            urls.update(_extract_sitemap_urls(sitemap.text, base + "/sitemap.xml"))

        scoped = [u for u in urls if _in_scope(u)]
        return _fmt({
            "action": self.name,
            "base": base,
            "urls": list(scoped)[:50],
            "errors": errors,
        })


def _extract_sitemap_urls(xml_text: str, source: str):
    # lightweight extraction
    urls = []
    for line in xml_text.splitlines():
        if "<loc>" in line:
            start = line.find("<loc>") + 5
            end = line.find("</loc>")
            if end > start:
                urls.append(line[start:end].strip())
    return urls

# Instantiate tool objects for easy import
scan_website_tool = ScanWebsiteTool()
analyze_headers_tool = AnalyzeHeadersTool()
test_http_methods_tool = TestHttpMethodsTool()
discover_api_endpoints_tool = DiscoverApiEndpointsTool()
enumerate_directories_tool = EnumerateDirectoriesTool()
info_disclosure_tool = InfoDisclosureTool()
render_page_tool = RenderPageTool()
discover_forms_tool = DiscoverFormsTool()
explore_click_targets_tool = ExploreClickTargetsTool()
stateful_explore_tool = StatefulExploreTool()
screenshot_tool = ScreenshotTool()
sqli_test_tool = SqliTestTool()
xss_test_tool = XssTestTool()
csrf_check_tool = CsrfCheckTool()
cors_check_tool = CorsCheckTool()
auth_bypass_tool = AuthBypassTool()
fuzz_parameter_tool = FuzzParameterTool()
form_fuzz_tool = FormFuzzTool()
check_admin_endpoints_tool = CheckAdminEndpointsTool()
sitemap_tool = SitemapTool()
api_key_leak_scan_tool = ApiKeyLeakScanTool()
jwt_decode_tool = JwtDecodeTool()
