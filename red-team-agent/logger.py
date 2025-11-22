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
    Detect what vulnerability a website has by matching it against the registry.
    
    Args:
        website_url: The website URL to check
    
    Returns:
        Dictionary with vulnerability information, or None if not found
    """
    try:
        # Load registry.json
        registry_path = Path(__file__).parent.parent / "deterministic-websites" / "registry.json"
        if not registry_path.exists():
            return None
        
        with open(registry_path, 'r', encoding='utf-8') as f:
            registry = json.load(f)
        
        # Parse the URL to get port or path
        parsed = urlparse(website_url)
        url_port = parsed.port
        url_scheme = parsed.scheme or "http"
        url_host = parsed.hostname or ""
        url_path = parsed.path or ""
        
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
        
        report.append("\n---\n")
        
        # Verification Steps (Brief)
        report.append("## Verification Steps")
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

