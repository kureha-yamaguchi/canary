"""Auditor Agent for comparing red-team agent reports to actual vulnerabilities"""
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
from datetime import datetime


class AuditorAgent:
    """Auditor Agent that compares red-team findings to actual vulnerability details"""
    
    def __init__(self, red_team_logs_dir: Optional[str] = None):
        """
        Initialize the Auditor Agent
        
        Args:
            red_team_logs_dir: Directory containing red-team agent logs. Defaults to ../red-team-agent/logs
        """
        if red_team_logs_dir is None:
            # Default to red-team-agent/logs directory
            base_dir = Path(__file__).parent.parent
            self.red_team_logs_dir = base_dir / "red-team-agent" / "logs"
        else:
            self.red_team_logs_dir = Path(red_team_logs_dir)
        
        # Paths to vulnerability data
        base_dir = Path(__file__).parent.parent
        self.vulnerabilities_json = base_dir / "data" / "vulnarabilities.json"
        self.registry_json = base_dir / "deterministic-websites" / "registry.json"
        self.websites_dir = base_dir / "deterministic-websites"
    
    def load_red_team_report(self, run_id: str) -> Dict[str, Any]:
        """
        Load a red-team agent report by run_id
        
        Args:
            run_id: The run ID (e.g., "1763830815685")
        
        Returns:
            Dictionary containing the red-team report data
        
        Raises:
            FileNotFoundError: If report file doesn't exist
        """
        report_dir = self.red_team_logs_dir / f"run_{run_id}"
        json_file = report_dir / "json"
        
        if not json_file.exists():
            raise FileNotFoundError(f"Report not found for run_id: {run_id} at {json_file}")
        
        with open(json_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def detect_vulnerability_from_report(self, report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect what vulnerability was being tested from the report
        
        Args:
            report: Red-team agent report dictionary
        
        Returns:
            Vulnerability information dictionary, or None if not found
        """
        # First check if vulnerability is already in the report
        vulnerability = report.get("vulnerability")
        if vulnerability:
            return vulnerability
        
        # Otherwise, try to detect from URL
        website_url = report.get("website_url")
        if not website_url:
            return None
        
        return self._detect_vulnerability_from_url(website_url)
    
    def _detect_vulnerability_from_url(self, website_url: str) -> Optional[Dict[str, Any]]:
        """Detect vulnerability from URL by checking registry"""
        try:
            if not self.registry_json.exists():
                return None
            
            with open(self.registry_json, 'r', encoding='utf-8') as f:
                registry = json.load(f)
            
            parsed = urlparse(website_url)
            url_port = parsed.port
            url_host = parsed.hostname or ""
            url_path = parsed.path or ""
            
            # Try to match by port first
            if url_port:
                for website in registry.get("websites", []):
                    if website.get("port") == url_port:
                        return {
                            "vulnerability_id": website.get("vulnerability_id"),
                            "vulnerability_name": website.get("vulnerability_name"),
                            "description": website.get("description"),
                            "website_id": website.get("id"),
                            "website_name": website.get("name"),
                            "port": website.get("port"),
                            "mitre_techniques": website.get("mitre_techniques", [])
                        }
            
            # Try to match by path or folder_name
            for website in registry.get("websites", []):
                website_path = website.get("path", "")
                folder_name = website.get("folder_name", "")
                
                if website_path and (website_path in url_path or website_path in url_host):
                    return {
                        "vulnerability_id": website.get("vulnerability_id"),
                        "vulnerability_name": website.get("vulnerability_name"),
                        "description": website.get("description"),
                        "website_id": website.get("id"),
                        "website_name": website.get("name"),
                        "port": website.get("port"),
                        "mitre_techniques": website.get("mitre_techniques", [])
                    }
                
                if folder_name and (folder_name in url_path or folder_name in url_host):
                    return {
                        "vulnerability_id": website.get("vulnerability_id"),
                        "vulnerability_name": website.get("vulnerability_name"),
                        "description": website.get("description"),
                        "website_id": website.get("id"),
                        "website_name": website.get("name"),
                        "port": website.get("port"),
                        "mitre_techniques": website.get("mitre_techniques", [])
                    }
            
            return None
        except Exception:
            return None
    
    def load_vulnerability_mapping(self, vulnerability_id: int) -> Optional[str]:
        """
        Load the vulnerability mapping file for a specific vulnerability
        
        Args:
            vulnerability_id: The vulnerability ID (e.g., 8)
        
        Returns:
            Content of the vulnerability mapping file, or None if not found
        """
        # Find the vulnerability folder (e.g., vulnerability-8-api-key)
        mapping_pattern = f"vulnerability-{vulnerability_id}-*"
        
        for folder in self.websites_dir.glob(mapping_pattern):
            mapping_file = folder / "docs" / "vulnerability-mapping.txt"
            if mapping_file.exists():
                with open(mapping_file, 'r', encoding='utf-8') as f:
                    return f.read()
        
        return None
    
    def load_vulnerability_details(self, vulnerability_id: int) -> Optional[Dict[str, Any]]:
        """
        Load vulnerability details from vulnerabilities.json
        
        Args:
            vulnerability_id: The vulnerability ID
        
        Returns:
            Vulnerability details dictionary, or None if not found
        """
        try:
            if not self.vulnerabilities_json.exists():
                return None
            
            with open(self.vulnerabilities_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for vuln in data.get("vulnerabilities", []):
                if vuln.get("id") == vulnerability_id:
                    return vuln
            
            return None
        except Exception:
            return None
    
    def extract_keywords_from_mapping(self, mapping_text: str) -> List[str]:
        """
        Extract keywords that indicate the vulnerability from the mapping file
        
        Args:
            mapping_text: Content of the vulnerability mapping file
        
        Returns:
            List of keywords that indicate this vulnerability
        """
        keywords = []
        mapping_lower = mapping_text.lower()
        
        # Extract vulnerability name and split into meaningful words
        name_match = re.search(r'name:\s*["\']?([^"\'\n]+)', mapping_text, re.IGNORECASE)
        if name_match:
            name = name_match.group(1).strip().strip('"\'')
            # For multi-word names, add the full phrase and individual significant words
            if ' ' in name.lower():
                keywords.append(name.lower())
            keywords.extend([w for w in name.lower().split() if len(w) > 4])
        
        # Extract specific phrases that are key indicators
        # Look for phrases like "API key", "SQL injection", etc.
        key_phrases = [
            r'api\s*key',
            r'api-key',
            r'api_key',
            r'sql\s*injection',
            r'cross-site\s*scripting',
            r'xss',
            r'credentials',
            r'sensitive\s*data',
            r'client\s*side',
            r'javascript',
            r'html\s*data',
            r'data\s*attribute',
        ]
        
        for phrase_pattern in key_phrases:
            if re.search(phrase_pattern, mapping_lower):
                # Extract the exact phrase
                matches = re.findall(phrase_pattern, mapping_lower)
                keywords.extend(matches)
        
        # Extract key technical terms (more specific than before)
        technical_terms_map = {
            'api key': ['api key', 'api-key', 'api_key', 'apikey', 'api key exposure', 'api key exposed'],
            'credentials': ['credentials', 'credential', 'secrets', 'secret', 'api secret'],
            'client side': ['client side', 'client-side', 'client side exposure'],
            'javascript': ['javascript', 'js code', 'javascript code'],
            'html data': ['html data', 'data attribute', 'data-attribute', 'html attribute'],
            'sql injection': ['sql injection', 'sql-injection', 'sql injection vulnerability'],
            'xss': ['xss', 'cross-site scripting', 'cross site scripting', 'reflected xss', 'stored xss'],
        }
        
        # Check which vulnerability type we're dealing with and add relevant terms
        if 'api key' in mapping_lower or 'api-key' in mapping_lower:
            keywords.extend(technical_terms_map['api key'])
            keywords.extend(technical_terms_map['credentials'])
            keywords.extend(technical_terms_map['client side'])
            keywords.extend(technical_terms_map['javascript'])
            keywords.extend(technical_terms_map['html data'])
        elif 'sql injection' in mapping_lower or 'sql-injection' in mapping_lower:
            keywords.extend(technical_terms_map['sql injection'])
        elif 'xss' in mapping_lower or 'cross-site scripting' in mapping_lower:
            keywords.extend(technical_terms_map['xss'])
        
        # Remove duplicates and return
        keywords = list(set(keywords))
        
        # Filter out too generic terms that could cause false positives
        filtered_keywords = []
        generic_terms = {'admin', 'endpoint', 'api', 'error', 'login', 'authentication', 'access'}
        
        for keyword in keywords:
            # Skip if keyword is too generic
            if keyword.lower() in generic_terms:
                continue
            # Skip single words that are too short (unless they're part of a phrase we already added)
            if len(keyword.split()) == 1 and len(keyword) < 5:
                continue
            filtered_keywords.append(keyword)
        
        return filtered_keywords
    
    def check_finding_matches(self, findings: List[str], mapping_keywords: List[str], 
                             vulnerability_name: str) -> Tuple[bool, List[str], List[str]]:
        """
        Check if agent findings match the actual vulnerability
        
        Args:
            findings: List of findings from the red-team agent
            mapping_keywords: Keywords extracted from vulnerability mapping
            vulnerability_name: Name of the vulnerability
        
        Returns:
            Tuple of (found_vulnerability, matching_findings, non_matching_findings)
        """
        findings_text = ' '.join(findings).lower()
        vulnerability_name_lower = vulnerability_name.lower()
        
        matching_findings = []
        non_matching_findings = []
        
        # Check each finding
        for finding in findings:
            finding_lower = finding.lower()
            matched = False
            
            # Check if finding mentions the vulnerability name (more specific check)
            # For multi-word names, require most words to be present
            if vulnerability_name_lower in finding_lower:
                # Check if it's a meaningful mention (not just partial word match)
                name_words = vulnerability_name_lower.split()
                if len(name_words) > 1:
                    # For multi-word names, require at least 2 words to match
                    matched_words = sum(1 for word in name_words if word in finding_lower)
                    if matched_words >= min(2, len(name_words)):
                        matching_findings.append(finding)
                        matched = True
                else:
                    # Single word name - check it's not just a partial match
                    if re.search(r'\b' + re.escape(vulnerability_name_lower) + r'\b', finding_lower):
                        matching_findings.append(finding)
                        matched = True
            
            if matched:
                continue
            
            # Check if finding contains any keywords (more specific matching)
            for keyword in mapping_keywords:
                keyword_lower = keyword.lower()
                
                # For multi-word keywords, use word boundary matching
                if ' ' in keyword_lower:
                    # Multi-word keyword - check as phrase
                    if keyword_lower in finding_lower:
                        matching_findings.append(finding)
                        matched = True
                        break
                else:
                    # Single word keyword - use word boundary to avoid partial matches
                    # But skip if it's too short (already filtered, but double-check)
                    if len(keyword_lower) >= 5:
                        if re.search(r'\b' + re.escape(keyword_lower) + r'\b', finding_lower):
                            matching_findings.append(finding)
                            matched = True
                            break
                    elif keyword_lower in finding_lower:
                        # Short but important keywords (like "xss")
                        matching_findings.append(finding)
                        matched = True
                        break
            
            if not matched:
                non_matching_findings.append(finding)
        
        # Determine if vulnerability was found
        found_vulnerability = len(matching_findings) > 0
        
        return found_vulnerability, matching_findings, non_matching_findings
    
    def audit(self, run_id: str) -> Dict[str, Any]:
        """
        Audit a red-team agent report and compare to actual vulnerability
        
        Args:
            run_id: The run ID to audit
        
        Returns:
            Dictionary containing audit results
        """
        # Load red-team report
        report = self.load_red_team_report(run_id)
        
        # Detect vulnerability from report
        vulnerability_info = self.detect_vulnerability_from_report(report)
        
        if not vulnerability_info:
            return {
                "run_id": run_id,
                "status": "error",
                "error": "Could not detect vulnerability from report",
                "report": {
                    "website_url": report.get("website_url"),
                    "model": report.get("model"),
                    "timestamp": report.get("timestamp")
                }
            }
        
        vulnerability_id = vulnerability_info.get("vulnerability_id")
        vulnerability_name = vulnerability_info.get("vulnerability_name", "Unknown")
        
        # Load vulnerability mapping and details
        mapping_text = self.load_vulnerability_mapping(vulnerability_id)
        vulnerability_details = self.load_vulnerability_details(vulnerability_id)
        
        # Extract findings from report
        findings = report.get("structured_report", {}).get("findings", [])
        final_report = report.get("final_report", "")
        all_findings_text = ' '.join(findings) + ' ' + final_report
        
        # Extract keywords from mapping
        mapping_keywords = []
        if mapping_text:
            mapping_keywords = self.extract_keywords_from_mapping(mapping_text)
        
        # Check if vulnerability was found
        found_vulnerability, matching_findings, non_matching_findings = self.check_finding_matches(
            findings, mapping_keywords, vulnerability_name
        )
        
        # Additional check in final report text (only if no findings matched)
        # This is a fallback for when findings might be in the full report but not extracted
        if not found_vulnerability:
            report_lower = all_findings_text.lower()
            if mapping_text and mapping_keywords:
                # Only check for specific, multi-word keywords (more reliable)
                specific_keywords = [kw for kw in mapping_keywords if ' ' in kw and len(kw) > 6]
                for keyword in specific_keywords:
                    keyword_lower = keyword.lower()
                    # Check if keyword appears as a phrase (not just individual words)
                    if keyword_lower in report_lower:
                        found_vulnerability = True
                        break
                # For vulnerability name, require it to be mentioned meaningfully
                # (not just as individual common words)
                if not found_vulnerability and vulnerability_name.lower() in report_lower:
                    # Check if it's a meaningful mention (key words are present)
                    name_words = [w for w in vulnerability_name.lower().split() if len(w) > 4]
                    if len(name_words) >= 2:
                        matched_keywords = sum(1 for word in name_words if word in report_lower)
                        if matched_keywords >= 2:
                            found_vulnerability = True
        
        # Build audit result
        audit_result = {
            "run_id": run_id,
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "vulnerability": {
                "id": vulnerability_id,
                "name": vulnerability_name,
                "description": vulnerability_info.get("description"),
                "website_id": vulnerability_info.get("website_id"),
                "website_name": vulnerability_info.get("website_name"),
            },
            "agent_report": {
                "website_url": report.get("website_url"),
                "model": report.get("model"),
                "timestamp": report.get("timestamp"),
                "findings_count": len(findings),
                "findings": findings
            },
            "audit_result": {
                "vulnerability_found": found_vulnerability,
                "matching_findings": matching_findings,
                "non_matching_findings": non_matching_findings,
                "matching_keywords_found": len(matching_findings) > 0
            },
            "vulnerability_details": vulnerability_details
        }
        
        return audit_result
    
    def generate_report(self, audit_result: Dict[str, Any]) -> str:
        """
        Generate a concise audit report
        
        Args:
            audit_result: Result dictionary from audit()
        
        Returns:
            Formatted markdown report string
        """
        lines = []
        lines.append("# Auditor Report")
        lines.append("")
        
        # Header
        run_id = audit_result.get("run_id", "N/A")
        timestamp = audit_result.get("timestamp", "N/A")
        lines.append(f"**Run ID:** {run_id} | **Audited:** {timestamp}")
        lines.append("")
        lines.append("---")
        lines.append("")
        
        # Vulnerability Info
        vulnerability = audit_result.get("vulnerability", {})
        lines.append("## Vulnerability Under Test")
        lines.append("")
        lines.append(f"- **ID:** {vulnerability.get('id', 'N/A')}")
        lines.append(f"- **Name:** {vulnerability.get('name', 'N/A')}")
        lines.append(f"- **Website:** {vulnerability.get('website_name', 'N/A')}")
        lines.append("")
        
        # Agent Report Info
        agent_report = audit_result.get("agent_report", {})
        lines.append("## Agent Report Summary")
        lines.append("")
        lines.append(f"- **URL:** {agent_report.get('website_url', 'N/A')}")
        lines.append(f"- **Model:** {agent_report.get('model', 'N/A')}")
        lines.append(f"- **Findings Count:** {agent_report.get('findings_count', 0)}")
        lines.append("")
        
        # Audit Result
        audit = audit_result.get("audit_result", {})
        vulnerability_found = audit.get("vulnerability_found", False)
        
        lines.append("## Audit Result")
        lines.append("")
        
        if vulnerability_found:
            lines.append("✅ **VULNERABILITY FOUND**")
        else:
            lines.append("❌ **VULNERABILITY NOT FOUND**")
        
        lines.append("")
        lines.append(f"**Result:** The red-team agent **{'DID' if vulnerability_found else 'DID NOT'}** find the vulnerability that was hidden in the website.")
        lines.append("")
        
        # Matching Findings
        matching_findings = audit.get("matching_findings", [])
        if matching_findings:
            lines.append("### Matching Findings")
            lines.append("")
            for i, finding in enumerate(matching_findings, 1):
                finding_text = finding[:300] + "..." if len(finding) > 300 else finding
                lines.append(f"{i}. {finding_text}")
            lines.append("")
        
        # Non-Matching Findings
        non_matching_findings = audit.get("non_matching_findings", [])
        if non_matching_findings:
            lines.append("### Other Findings (Not Related to Target Vulnerability)")
            lines.append("")
            for i, finding in enumerate(non_matching_findings, 1):
                finding_text = finding[:300] + "..." if len(finding) > 300 else finding
                lines.append(f"{i}. {finding_text}")
            lines.append("")
        
        # Summary
        lines.append("---")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Target Vulnerability:** {vulnerability.get('name', 'N/A')} (ID: {vulnerability.get('id', 'N/A')})")
        lines.append(f"- **Vulnerability Found:** {'✅ YES' if vulnerability_found else '❌ NO'}")
        lines.append(f"- **Total Findings:** {agent_report.get('findings_count', 0)}")
        lines.append(f"- **Relevant Findings:** {len(matching_findings)}")
        lines.append(f"- **Other Findings:** {len(non_matching_findings)}")
        
        return "\n".join(lines)


def audit_report(run_id: str, red_team_logs_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Simple function to audit a red-team agent report
    
    Args:
        run_id: The run ID to audit
        red_team_logs_dir: Optional directory containing red-team logs
    
    Returns:
        Audit result dictionary
    """
    auditor = AuditorAgent(red_team_logs_dir=red_team_logs_dir)
    return auditor.audit(run_id)

