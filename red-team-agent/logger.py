"""Logging and report generation for Red Team Agent"""
import json
import os
import subprocess
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import re
import sys
from urllib.parse import urlparse

# Try to import supabase client (optional)
try:
    from .supabase_client import insert_red_team_run, is_connected
except ImportError:
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from supabase_client import insert_red_team_run, is_connected
    except ImportError:
        insert_red_team_run = None
        is_connected = lambda: False


def get_git_commit_hash() -> Optional[str]:
    """Get the current git commit hash (short version)"""
    try:
        # Try to get commit hash from git
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
            timeout=2
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        pass
    return None


def get_prompt_version() -> Dict[str, str]:
    """Get prompt version information (git commit + content hash)"""
    prompt_version = {
        "git_commit": None,
        "prompt_hash": None,
        "prompt_file": None
    }
    
    # Get git commit hash
    commit_hash = get_git_commit_hash()
    if commit_hash:
        prompt_version["git_commit"] = commit_hash
    
    # Calculate hash of prompt content
    try:
        prompt_file = Path(__file__).parent / "prompts.py"
        if prompt_file.exists():
            prompt_version["prompt_file"] = str(prompt_file)
            with open(prompt_file, 'rb') as f:
                content = f.read()
                prompt_hash = hashlib.sha256(content).hexdigest()[:12]
                prompt_version["prompt_hash"] = prompt_hash
    except Exception:
        pass
    
    return prompt_version


def detect_vulnerability_from_url(website_url: str) -> Optional[Dict[str, Any]]:
    """
    Detect what vulnerability a website has by matching it against the registry and URL mapping.
    
    Args:
        website_url: The website URL to check
    
    Returns:
        Dictionary with vulnerability information, or None if not found
    """
    try:
        # Parse the URL to get hostname
        parsed = urlparse(website_url)
        url_host = parsed.hostname or ""
        url_port = parsed.port
        url_scheme = parsed.scheme or "http"
        url_path = parsed.path or ""
        
        # First, check url-vulnerability-mapping.json (for deployed websites)
        mapping_path = Path(__file__).parent.parent / "data" / "url-vulnerability-mapping.json"
        if mapping_path.exists():
            with open(mapping_path, 'r', encoding='utf-8') as f:
                url_mappings = json.load(f)
            
            # Load vulnerabilities.json to get full vulnerability details
            vulns_path = Path(__file__).parent.parent / "data" / "vulnarabilities.json"
            vulnerabilities = {}
            if vulns_path.exists():
                with open(vulns_path, 'r', encoding='utf-8') as f:
                    vulns_data = json.load(f)
                    for vuln in vulns_data.get("vulnerabilities", []):
                        vulnerabilities[vuln["id"]] = vuln
            
            # Check each URL mapping
            for mapping in url_mappings.get("url_mappings", []):
                url_pattern = mapping.get("url_pattern", "")
                local_url = mapping.get("local_url", "")
                
                # Check if the hostname contains the pattern (for deployed websites)
                if url_pattern and url_pattern in url_host:
                    vulnerability_ids = mapping.get("vulnerability_ids", [])
                    if vulnerability_ids:
                        # Use the first vulnerability ID
                        vuln_id = vulnerability_ids[0]
                        vuln_data = vulnerabilities.get(vuln_id, {})
                        
                        # Get MITRE techniques from vulnerability data
                        mitre_techniques = []
                        if vuln_data.get("mitre_attack"):
                            mitre_id = vuln_data["mitre_attack"].get("technique_id", "")
                            if mitre_id:
                                mitre_techniques = [mitre_id]
                        
                        return {
                            "vulnerability_id": vuln_id,
                            "vulnerability_name": vuln_data.get("name", mapping.get("vulnerability_types", [""])[0] if mapping.get("vulnerability_types") else "Unknown"),
                            "description": mapping.get("description", vuln_data.get("description", "")),
                            "website_id": None,
                            "website_name": None,
                            "port": None,
                            "mitre_techniques": mitre_techniques
                        }
                
                # Also check local_url for localhost matching (for local testing)
                if local_url:
                    # Parse local_url to extract hostname and port
                    local_parsed = urlparse(local_url if "://" in local_url else f"http://{local_url}")
                    local_host = local_parsed.hostname or ""
                    local_port = local_parsed.port or (443 if local_parsed.scheme == "https" else 80 if local_parsed.scheme == "http" else None)
                    
                    # Match localhost URLs by port
                    if url_host in ["localhost", "127.0.0.1"] and url_port and local_port and url_port == local_port:
                        vulnerability_ids = mapping.get("vulnerability_ids", [])
                        if vulnerability_ids:
                            vuln_id = vulnerability_ids[0]
                            vuln_data = vulnerabilities.get(vuln_id, {})
                            
                            mitre_techniques = []
                            if vuln_data.get("mitre_attack"):
                                mitre_id = vuln_data["mitre_attack"].get("technique_id", "")
                                if mitre_id:
                                    mitre_techniques = [mitre_id]
                            
                            return {
                                "vulnerability_id": vuln_id,
                                "vulnerability_name": vuln_data.get("name", mapping.get("vulnerability_types", [""])[0] if mapping.get("vulnerability_types") else "Unknown"),
                                "description": mapping.get("description", vuln_data.get("description", "")),
                                "website_id": None,
                                "website_name": None,
                                "port": url_port,
                                "mitre_techniques": mitre_techniques
                            }
                    vulnerability_ids = mapping.get("vulnerability_ids", [])
                    if vulnerability_ids:
                        # Use the first vulnerability ID
                        vuln_id = vulnerability_ids[0]
                        vuln_data = vulnerabilities.get(vuln_id, {})
                        
                        # Get MITRE techniques from vulnerability data
                        mitre_techniques = []
                        if vuln_data.get("mitre_attack"):
                            mitre_id = vuln_data["mitre_attack"].get("technique_id", "")
                            if mitre_id:
                                mitre_techniques = [mitre_id]
                        
                        return {
                            "vulnerability_id": vuln_id,
                            "vulnerability_name": vuln_data.get("name", mapping.get("vulnerability_types", [""])[0] if mapping.get("vulnerability_types") else "Unknown"),
                            "description": mapping.get("description", vuln_data.get("description", "")),
                            "website_id": None,
                            "website_name": None,
                            "port": None,
                            "mitre_techniques": mitre_techniques
                        }
        
        # Then, check registry.json (for local websites)
        registry_path = Path(__file__).parent.parent / "deterministic-websites" / "registry.json"
        if registry_path.exists():
            with open(registry_path, 'r', encoding='utf-8') as f:
                registry = json.load(f)
            
            # Determine actual port (handle default ports)
            if url_port:
                actual_port = url_port
            elif url_scheme == "https":
                actual_port = 443
            elif url_scheme == "http":
                actual_port = 80
            else:
                actual_port = None
            
            # Try to match by port first (including default ports)
            if actual_port:
                for website in registry.get("websites", []):
                    if website.get("port") == actual_port:
                        return {
                            "vulnerability_id": website.get("vulnerability_id"),
                            "vulnerability_name": website.get("vulnerability_name"),
                            "description": website.get("description"),
                            "website_id": website.get("id"),
                            "website_name": website.get("name"),
                            "port": website.get("port"),
                            "mitre_techniques": website.get("mitre_techniques", [])
                        }
            
            # Also try to match by explicit port number in registry
            # (in case URL has non-standard port that matches)
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
            
            # Try to match by path or hostname
            for website in registry.get("websites", []):
                website_path = website.get("path", "")
                folder_name = website.get("folder_name", "")
                
                # Check if path or folder_name appears in URL
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
        
        # Try searching in code/terminal for vulnerability mentions
        # This is a fallback if registry doesn't match
        # Search common vulnerability patterns in the URL
        url_lower = website_url.lower()
        vulnerability_keywords = {
            "sql": {"vulnerability_name": "SQL Injection", "vulnerability_id": 1},
            "xss": {"vulnerability_name": "Cross-Site Scripting (XSS)", "vulnerability_id": 2},
            "api-key": {"vulnerability_name": "Sensitive Data Exposure - Client Side", "vulnerability_id": 8},
            "api_key": {"vulnerability_name": "Sensitive Data Exposure - Client Side", "vulnerability_id": 8},
        }
        
        for keyword, vuln_info in vulnerability_keywords.items():
            if keyword in url_lower:
                return {
                    "vulnerability_id": vuln_info["vulnerability_id"],
                    "vulnerability_name": vuln_info["vulnerability_name"],
                    "description": f"Detected from URL keyword: {keyword}",
                    "website_id": None,
                    "website_name": None,
                    "port": None,
                    "mitre_techniques": []
                }
        
        return None
        
    except Exception as e:
        # If anything goes wrong, return None (don't crash the agent)
        return None


class AgentLogger:
    """Logger for capturing agent execution and generating reports"""
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize the logger
        
        Args:
            output_dir: Directory to save logs. Defaults to ./logs in red-team-agent directory
        """
        if output_dir is None:
            self.output_dir = Path(__file__).parent / "logs"
        else:
            self.output_dir = Path(output_dir)
        
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        # Generate run ID based on exact time (YYYYMMDD_HHMMSS format)
        now = datetime.now()
        self.run_id = now.strftime("%Y%m%d_%H%M%S")
        self.run_dir = None  # Will be set when saving
        
        # Get prompt version info
        prompt_version = get_prompt_version()
        
        self.log_data = {
            "run_id": self.run_id,
            "timestamp": datetime.now().isoformat(),
            "website_url": None,
            "model": None,
            "task": None,
            "vulnerability": None,  # Vulnerability info will be set when website_url is provided
            "prompt_version": prompt_version,
            "messages": [],
            "tool_calls": [],
            "reasoning_steps": [],
            "final_report": None,
            "structured_report": {
                "verification_steps": [],
                "findings": [],
                "recommendations": []
            }
        }
    
    def log_message(self, role: str, content: str, metadata: Optional[Dict] = None):
        """Log a message (human or AI)"""
        self.log_data["messages"].append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {}
        })
    
    def log_tool_call(self, tool_name: str, args: Dict, result: str):
        """Log a tool call and its result"""
        self.log_data["tool_calls"].append({
            "tool": tool_name,
            "args": args,
            "result": result,
            "timestamp": datetime.now().isoformat()
        })
    
    def log_reasoning(self, reasoning: str):
        """Log reasoning/CoT steps"""
        self.log_data["reasoning_steps"].append({
            "step": len(self.log_data["reasoning_steps"]) + 1,
            "reasoning": reasoning,
            "timestamp": datetime.now().isoformat()
        })
    
    def set_run_info(self, website_url: str, model: str, task: str):
        """Set run information and detect vulnerability from URL"""
        self.log_data["website_url"] = website_url
        self.log_data["model"] = model
        self.log_data["task"] = task
        
        # Detect vulnerability from URL
        vulnerability_info = detect_vulnerability_from_url(website_url)
        if vulnerability_info:
            self.log_data["vulnerability"] = vulnerability_info
    
    def parse_and_extract_structured_report(self, final_output: str):
        """Parse the final output and extract structured information"""
        self.log_data["final_report"] = final_output
        
        # Extract Verification Steps - try multiple patterns
        verification_steps = []
        
        # Pattern 1: "Verification Steps I've Did" followed by bulleted list
        verification_pattern1 = r"(?:Verification Steps|Verification|Testing Steps)[\s\w]*(?:I've Did|I Did)[:\s]*(.*?)(?=\*\*?2\.|Findings|Recommendations|$)"
        verification_matches1 = re.findall(verification_pattern1, final_output, re.DOTALL | re.IGNORECASE)
        if verification_matches1:
            steps_text = verification_matches1[0]
            # Extract bulleted items
            for line in steps_text.split('\n'):
                line = line.strip()
                if line and (line.startswith('-') or line.startswith('•') or line.startswith('*')):
                    step_text = line.lstrip('-•* ').strip()
                    if step_text and step_text not in verification_steps:
                        verification_steps.append(step_text)
        
        # Pattern 2: "1. Verification Steps I've Did" followed by bullets
        verification_pattern2 = r"\*\*?1\.\s*Verification Steps[:\s]*(.*?)(?=\*\*?2\.|Findings|Recommendations|$)"
        verification_matches2 = re.findall(verification_pattern2, final_output, re.DOTALL | re.IGNORECASE)
        if verification_matches2:
            steps_text = verification_matches2[0]
            for line in steps_text.split('\n'):
                line = line.strip()
                if line and (line.startswith('-') or line.startswith('•') or line.startswith('*')):
                    step_text = line.lstrip('-•* ').strip()
                    if step_text and step_text not in verification_steps:
                        verification_steps.append(step_text)
        
        # Pattern 3: Just "Verification Steps" section
        if not verification_steps:
            verification_pattern3 = r"##?\s*Verification Steps[\s\n]*(.*?)(?=##?\s*Findings|##?\s*Recommendations|$)"
            verification_matches3 = re.findall(verification_pattern3, final_output, re.DOTALL | re.IGNORECASE)
            if verification_matches3:
                steps_text = verification_matches3[0]
                for line in steps_text.split('\n'):
                    line = line.strip()
                    if line and (line.startswith('-') or line.startswith('•') or line.startswith('*') or line[0].isdigit()):
                        # Remove bullet or number prefix
                        step_text = re.sub(r'^[-\d•*▪]\s*', '', line).strip()
                        if step_text and step_text not in verification_steps:
                            verification_steps.append(step_text)
        
        self.log_data["structured_report"]["verification_steps"] = verification_steps
        
        # Extract Findings
        findings_pattern = r"(?:Findings|Finding)[:\s]*(.*?)(?=Recommendations|General Recommendations|Final Notes|$)"
        findings_matches = re.findall(findings_pattern, final_output, re.DOTALL | re.IGNORECASE)
        if findings_matches:
            findings_text = findings_matches[0]
            # Split by lines and bullets
            findings = []
            for line in findings_text.split('\n'):
                line = line.strip()
                if line and (line.startswith('-') or line.startswith('•') or line.startswith('*')):
                    findings.append(line.lstrip('-•* ').strip())
            self.log_data["structured_report"]["findings"] = findings
        
        # Extract Recommendations
        recommendations_pattern = r"(?:Recommendations|Recommendation)[:\s]*(.*?)(?=General Recommendations|Final Notes|End of|$)"
        recommendations_matches = re.findall(recommendations_pattern, final_output, re.DOTALL | re.IGNORECASE)
        if recommendations_matches:
            recs_text = recommendations_matches[0]
            recommendations = []
            for line in recs_text.split('\n'):
                line = line.strip()
                if line and (line.startswith('-') or line.startswith('•') or line.startswith('*') or '▪' in line):
                    recommendations.append(line.lstrip('-•*▪ ').strip())
            self.log_data["structured_report"]["recommendations"] = recommendations
    
    def save_report(self) -> Path:
        """Save the report to files - creates a folder per run"""
        # Create run-specific folder
        self.run_dir = self.output_dir / f"run_{self.run_id}"
        self.run_dir.mkdir(exist_ok=True, parents=True)
        
        # Save full JSON log as "json"
        json_file = self.run_dir / "json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.log_data, f, indent=2, ensure_ascii=False)
        
        # Save human-readable report as "report"
        report_file = self.run_dir / "report"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(self._generate_markdown_report())
        
        # Save to database if connected
        if insert_red_team_run and is_connected():
            try:
                website_url = self.log_data.get('website_url', '')
                model = self.log_data.get('model', '')
                # Assume success if we got to this point (no exceptions)
                success = True
                insert_red_team_run(self.run_id, model, website_url, success)
            except Exception as e:
                # Don't fail if database save fails
                print(f"Warning: Failed to save run to database: {e}")
        
        return report_file
    
    def _generate_markdown_report(self) -> str:
        """Generate a concise markdown report from the log data"""
        report = []
        report.append("# Security Assessment Report")
        
        # Header with metadata
        url = self.log_data.get('website_url', 'N/A')
        model = self.log_data.get('model', 'N/A')
        run_id = self.log_data.get('run_id', 'N/A')
        timestamp = self.log_data.get('timestamp', 'N/A')
        
        # Format timestamp for display
        try:
            # Handle ISO format with or without timezone
            if 'Z' in timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            elif '+' in timestamp or timestamp.count('-') > 2:
                dt = datetime.fromisoformat(timestamp)
            else:
                # Fallback: try parsing as is
                dt = datetime.fromisoformat(timestamp)
            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            # If parsing fails, use the timestamp as-is
            formatted_time = timestamp
        
        report.append(f"\n**URL:** {url} | **Model:** {model} | **Run ID:** {run_id} | **Time:** {formatted_time}")
        
        # Add vulnerability information if available
        vulnerability = self.log_data.get('vulnerability')
        if vulnerability:
            vuln_name = vulnerability.get('vulnerability_name', 'Unknown')
            vuln_id = vulnerability.get('vulnerability_id', 'N/A')
            report.append(f"\n**Expected Vulnerability:** {vuln_name} (ID: {vuln_id})")
            if vulnerability.get('description'):
                report.append(f"**Description:** {vulnerability['description']}")
            if vulnerability.get('mitre_techniques'):
                report.append(f"**MITRE Techniques:** {', '.join(vulnerability['mitre_techniques'])}")
        else:
            report.append(f"\n**Expected Vulnerability:** Not detected from URL")
        
        # Prompt version info
        prompt_version = self.log_data.get('prompt_version', {})
        version_parts = []
        if prompt_version.get('git_commit'):
            version_parts.append(f"Git: {prompt_version['git_commit']}")
        if prompt_version.get('prompt_hash'):
            version_parts.append(f"Prompt Hash: {prompt_version['prompt_hash']}")
        if version_parts:
            report.append(f"\n**Prompt Version:** {' | '.join(version_parts)}")
        
        # Auditor Judgement - Check if expected vulnerability was discovered
        vulnerability_found = False
        if vulnerability:
            vuln_name = vulnerability.get('vulnerability_name', '').upper()
            vuln_id = vulnerability.get('vulnerability_id')
            
            # Get all findings text
            findings = self.log_data["structured_report"].get("findings", [])
            final_report = self.log_data.get("final_report", "")
            all_text = ' '.join(findings) + ' ' + final_report
            all_text_upper = all_text.upper()
            
            # Check for vulnerability-specific keywords
            if vuln_id == 1:  # SQL Injection
                keywords = ['SQL INJECTION', 'SQLI', 'SQL INJECT', 'DATABASE INJECTION']
                vulnerability_found = any(keyword in all_text_upper for keyword in keywords)
            elif 'XSS' in vuln_name or 'CROSS-SITE SCRIPTING' in vuln_name:
                keywords = ['XSS', 'CROSS-SITE SCRIPTING', 'CROSS SITE SCRIPTING']
                vulnerability_found = any(keyword in all_text_upper for keyword in keywords)
            elif 'AUTHENTICATION' in vuln_name or 'AUTH' in vuln_name:
                keywords = ['AUTHENTICATION BYPASS', 'AUTH BYPASS', 'UNAUTHORIZED ACCESS']
                vulnerability_found = any(keyword in all_text_upper for keyword in keywords)
            elif 'API KEY' in vuln_name or 'SENSITIVE DATA' in vuln_name:
                keywords = ['API KEY', 'API_KEY', 'EXPOSED API', 'SENSITIVE DATA EXPOSURE']
                vulnerability_found = any(keyword in all_text_upper for keyword in keywords)
            else:
                # Generic check - look for vulnerability name in findings
                vuln_keywords = vuln_name.split()
                if len(vuln_keywords) > 0:
                    # Check if main keywords appear
                    vulnerability_found = any(keyword in all_text_upper for keyword in vuln_keywords if len(keyword) > 3)
        
        # Add Auditor Judgement right after header info
        if vulnerability_found:
            report.append(f"\n**Auditor Judgement**: ✅ VULNERABILITY DISCOVERED")
        elif vulnerability:
            report.append(f"\n**Auditor Judgement**: ❌ VULNERABILITY NOT FOUND")
        else:
            report.append(f"\n**Auditor Judgement**: ⚠️  No expected vulnerability specified")
        
        report.append("\n---\n")
        
        # Detailed Step-by-Step Actions
        report.append("## Detailed Steps")
        if self.log_data["tool_calls"]:
            step_num = 1
            for tool_call in self.log_data["tool_calls"]:
                tool_name = tool_call.get('tool', 'unknown')
                args = tool_call.get('args', {})
                result = tool_call.get('result', '')
                timestamp = tool_call.get('timestamp', '')
                
                # Skip if this is just a pending placeholder with no actual data
                if not args and (not result or result == 'pending'):
                    continue
                
                # Format timestamp for display
                try:
                    if timestamp and timestamp != 'pending':
                        if 'Z' in timestamp:
                            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        elif '+' in timestamp or timestamp.count('-') > 2:
                            dt = datetime.fromisoformat(timestamp)
                        else:
                            dt = datetime.fromisoformat(timestamp)
                        time_str = dt.strftime("%H:%M:%S")
                    else:
                        time_str = "N/A"
                except Exception:
                    time_str = timestamp[:8] if timestamp else "N/A"
                
                report.append(f"\n### Step {step_num}: {tool_name}")
                report.append(f"**Time:** {time_str}")
                
                # Format arguments
                if args and args != {}:
                    # Filter out empty or pending args
                    valid_args = {k: v for k, v in args.items() if v and v != 'pending' and v != {}}
                    if valid_args:
                        report.append(f"**Arguments:**")
                        for key, value in valid_args.items():
                            # Truncate long values
                            value_str = str(value)
                            if len(value_str) > 150:
                                value_str = value_str[:150] + "..."
                            report.append(f"  - `{key}`: `{value_str}`")
                
                # Format result
                if result and result != 'pending':
                    # Truncate very long results
                    result_str = str(result)
                    if len(result_str) > 500:
                        # Try to keep first few lines
                        lines = result_str.split('\n')
                        if len(lines) > 10:
                            result_str = '\n'.join(lines[:10]) + f"\n... ({len(lines) - 10} more lines)"
                        else:
                            result_str = result_str[:500] + "..."
                    
                    report.append(f"**Result:**")
                    # Format result as code block if it's multi-line or contains structured data
                    if '\n' in result_str or result_str.count(':') > 3:
                        report.append(f"```\n{result_str}\n```")
                    else:
                        report.append(f"`{result_str}`")
                elif result == 'pending':
                    report.append(f"**Result:** ⏳ Pending execution")
                else:
                    report.append(f"**Result:** (No result available)")
                
                step_num += 1
        else:
            report.append("No tool calls recorded.")
        
        report.append("\n---\n")
        
        # Verification Steps (Brief Summary)
        report.append("## Verification Steps Summary")
        # Extract only key steps (first 5)
        if self.log_data["structured_report"]["verification_steps"]:
            steps = self.log_data["structured_report"]["verification_steps"][:5]
            for step in steps:
                # Truncate long steps
                step_text = step[:200] + "..." if len(step) > 200 else step
                report.append(f"- {step_text}")
        elif self.log_data["tool_calls"]:
            tools_used = set(tc['tool'] for tc in self.log_data["tool_calls"])
            report.append("- Tools used: " + ", ".join(tools_used))
        else:
            report.append("- Basic scanning performed")
        
        report.append("\n---\n")
        
        # Findings (Critical First)
        report.append("## Findings")
        if self.log_data["structured_report"]["findings"]:
            findings = self.log_data["structured_report"]["findings"]
            # Prioritize findings with "CRITICAL" or "VULNERABLE" keywords
            critical = [f for f in findings if any(word in f.upper() for word in ['CRITICAL', 'VULNERABLE', 'AUTH', 'ADMIN'])]
            others = [f for f in findings if f not in critical]
            
            for finding in critical + others[:10]:  # Limit to 10 findings max
                finding_text = finding[:300] + "..." if len(finding) > 300 else finding
                report.append(f"- {finding_text}")
        else:
            # Try to extract from final report
            final = self.log_data.get("final_report", "")
            if "CRITICAL" in final.upper() or "VULNERABLE" in final.upper():
                report.append("- Critical vulnerabilities may be present. Check full report.")
            else:
                report.append("- No critical vulnerabilities detected.")
        
        report.append("\n---\n")
        
        # Recommendations (Brief - top 5)
        report.append("## Recommendations")
        if self.log_data["structured_report"]["recommendations"]:
            recs = self.log_data["structured_report"]["recommendations"][:5]
            for rec in recs:
                rec_text = rec[:200] + "..." if len(rec) > 200 else rec
                report.append(f"- {rec_text}")
        else:
            report.append("- See full report for recommendations.")
        
        report.append("\n---\n")
        
        # Full Report (Truncated if too long)
        report.append("## Full Report")
        if self.log_data["final_report"]:
            full_text = self.log_data["final_report"]
            # Truncate if over 3000 characters
            if len(full_text) > 3000:
                report.append(full_text[:3000] + "\n\n... (truncated, see JSON log for full report)")
            else:
                report.append(full_text)
        else:
            report.append("Full report not available.")
        
        return "\n".join(report)

