"""Logging and report generation for TTP Master Agent"""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import re
import sys

# Try to import supabase client (optional)
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'red-team-agent'))
    from supabase_client import insert_ttp_runs, is_connected
except ImportError:
    insert_ttp_runs = None
    is_connected = lambda: False


class TTPLogger:
    """Logger for capturing TTP analysis and generating reports"""
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize the logger
        
        Args:
            output_dir: Directory to save logs. Defaults to the same directory as the red-team-agent report
        """
        self.output_dir = Path(output_dir) if output_dir else None
        self.run_dir = None
        
        # Generate run ID based on exact time (YYYYMMDD_HHMMSS format)
        now = datetime.now()
        self.run_id = now.strftime("%Y%m%d_%H%M%S")
        
        self.log_data = {
            "run_id": self.run_id,
            "timestamp": datetime.now().isoformat(),
            "source_report_path": None,
            "source_run_id": None,
            "model": None,
            "ttp_analysis": [],
            "final_report": None,
            "structured_ttps": {
                "techniques": [],
                "sub_techniques": [],
                "by_step": [],
                "by_finding": []
            }
        }
    
    def set_source_report(self, report_path: str, run_id: str):
        """Set the source red-team-agent report information"""
        self.log_data["source_report_path"] = str(report_path)
        self.log_data["source_run_id"] = run_id
    
    def set_model(self, model: str):
        """Set the model used for analysis"""
        self.log_data["model"] = model
    
    def set_output_dir(self, output_dir: Path):
        """Set the output directory (should be the same as source report directory)"""
        self.output_dir = output_dir
        self.output_dir.mkdir(exist_ok=True, parents=True)
    
    def log_ttp_analysis(self, step_or_finding: str, ttp_id: str, ttp_name: str, 
                        rationale: str, mitre_url: str, category: str = "step"):
        """
        Log a TTP mapping
        
        Args:
            step_or_finding: The step or finding being mapped
            ttp_id: MITRE TTP ID (e.g., T1552) - sub-techniques will be stripped to base ID
            ttp_name: Full TTP name
            rationale: Why this maps to the TTP
            mitre_url: MITRE ATT&CK URL
            category: "step" or "finding"
        """
        # Strip sub-technique suffix (e.g., T1592.002 -> T1592)
        base_ttp_id = re.match(r'(T\d{4})', ttp_id)
        if base_ttp_id:
            ttp_id = base_ttp_id.group(1)
        
        # Map category to mapping_type
        mapping_type = "verification step" if category == "step" else "security finding"
        
        ttp_entry = {
            "step_or_finding": step_or_finding,
            "ttp_id": ttp_id,
            "ttp_name": ttp_name,
            "rationale": rationale,
            "mitre_url": mitre_url,
            "category": category,
            "mapping_type": mapping_type,
            "mapping_rationale": rationale,
            "timestamp": datetime.now().isoformat()
        }
        self.log_data["ttp_analysis"].append(ttp_entry)
        
        # Also add to structured data
        if category == "step":
            self.log_data["structured_ttps"]["by_step"].append(ttp_entry)
        else:
            self.log_data["structured_ttps"]["by_finding"].append(ttp_entry)
        
        # Track unique techniques
        if ttp_id not in [t["ttp_id"] for t in self.log_data["structured_ttps"]["techniques"]]:
            self.log_data["structured_ttps"]["techniques"].append({
                "ttp_id": ttp_id,
                "ttp_name": ttp_name,
                "mitre_url": mitre_url
            })
        
        # Track sub-techniques separately
        if "." in ttp_id:
            if ttp_id not in [t["ttp_id"] for t in self.log_data["structured_ttps"]["sub_techniques"]]:
                self.log_data["structured_ttps"]["sub_techniques"].append({
                    "ttp_id": ttp_id,
                    "ttp_name": ttp_name,
                    "mitre_url": mitre_url
                })
    
    def set_final_report(self, report: str):
        """Set the final analysis report"""
        self.log_data["final_report"] = report
    
    def parse_ttp_from_report(self, report_text: str):
        """Parse TTP information from the agent's final report"""
        # Extract TTP IDs (format: T#### or T####.###)
        ttp_pattern = r'T\d{4}(?:\.\d{3})?'
        
        # Extract TTP sections - match "### Step:" or "### Finding:" patterns
        # Pattern matches: ### Step: ... or ### Finding: ... followed by content until next ### or end
        ttp_sections = re.findall(
            r'###\s*(Step|Finding)[:\s]*(.*?)(?=\n###\s*(?:Step|Finding|Summary)|\Z)',
            report_text,
            re.DOTALL | re.IGNORECASE
        )
        
        # Try to extract structured TTP mappings from each section
        for section_type, section_content in ttp_sections:
            # Look for TTP ID in the section
            ttp_id_match = re.search(ttp_pattern, section_content)
            if ttp_id_match:
                ttp_id = ttp_id_match.group(0)
                
                # Extract the step/finding description (first line)
                lines = section_content.split('\n')
                description = lines[0].strip() if lines else ""
                
                # Try to extract name and rationale
                name = ""
                rationale = ""
                mitre_url = ""
                
                for line in lines:
                    line_lower = line.lower()
                    if '**ttp name**' in line_lower or '**name**' in line_lower:
                        # Extract name after the colon
                        name_match = re.search(r':\s*(.+?)(?:\n|$)', line, re.IGNORECASE)
                        if name_match:
                            name = name_match.group(1).strip()
                    elif '**mapping rationale**' in line_lower or '**rationale**' in line_lower:
                        # Extract rationale after the colon
                        rationale_match = re.search(r':\s*(.+?)(?:\n|$)', line, re.IGNORECASE)
                        if rationale_match:
                            rationale = rationale_match.group(1).strip()
                    elif '**mitre url**' in line_lower or 'mitre.org' in line_lower:
                        # Extract URL
                        url_match = re.search(r'https?://[^\s\)]+', line)
                        if url_match:
                            mitre_url = url_match.group(0)
                
                # If we found a TTP ID, log it
                if ttp_id:
                    category = "step" if section_type.lower() == "step" else "finding"
                    if not mitre_url:
                        mitre_url = f"https://attack.mitre.org/techniques/{ttp_id.replace('.', '/')}/"
                    
                    self.log_ttp_analysis(
                        step_or_finding=description[:200] if description else section_content[:200],
                        ttp_id=ttp_id,
                        ttp_name=name or "Unknown",
                        rationale=rationale or "Extracted from report",
                        mitre_url=mitre_url,
                        category=category
                    )
        
        # Also try a simpler pattern: look for all TTP IDs with their context
        # This is a fallback if the structured parsing didn't work
        if len(self.log_data["ttp_analysis"]) == 0:
            # Find all TTP IDs with surrounding context
            ttp_matches = re.finditer(
                r'(?:TTP ID|TTP|Technique)[:\s]*\*\*(T\d{4}(?:\.\d{3})?)\*\*',
                report_text,
                re.IGNORECASE
            )
            
            for match in ttp_matches:
                ttp_id = match.group(1)
                # Get context around the match (50 chars before and after)
                start = max(0, match.start() - 50)
                end = min(len(report_text), match.end() + 200)
                context = report_text[start:end]
                
                # Try to extract name from context
                name_match = re.search(r'(?:TTP Name|Name)[:\s]*\*\*([^\*]+)\*\*', context, re.IGNORECASE)
                name = name_match.group(1).strip() if name_match else "Unknown"
                
                # Determine category from context
                category = "step" if "step" in context.lower() else "finding"
                
                self.log_ttp_analysis(
                    step_or_finding=context[:200],
                    ttp_id=ttp_id,
                    ttp_name=name,
                    rationale="Extracted from report",
                    mitre_url=f"https://attack.mitre.org/techniques/{ttp_id.replace('.', '/')}/",
                    category=category
                )
    
    def save_report(self) -> Path:
        """Save the TTP analysis report to files"""
        if not self.output_dir:
            raise ValueError("Output directory not set. Call set_output_dir() first.")
        
        # Save full JSON log as "ttp_analysis.json"
        json_file = self.output_dir / "ttp_analysis.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.log_data, f, indent=2, ensure_ascii=False)
        
        # Save human-readable report as "ttp_analysis_report"
        report_file = self.output_dir / "ttp_analysis_report"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(self._generate_markdown_report())
        
        # Save to database if connected
        if insert_ttp_runs and is_connected():
            try:
                # Import the new function
                from supabase_client import insert_ttp_runs_with_details
                
                # Get source run_id (the red-team-agent run_id)
                source_run_id = self.log_data.get("source_run_id")
                if source_run_id:
                    # Extract TTP mappings with details
                    ttp_analysis = self.log_data.get("ttp_analysis", [])
                    
                    # Prepare mappings for database
                    ttp_mappings = []
                    for entry in ttp_analysis:
                        ttp_id = entry.get("ttp_id")
                        mapping_type = entry.get("mapping_type", "unknown")
                        mapping_rationale = entry.get("mapping_rationale", entry.get("rationale", ""))
                        
                        if ttp_id:
                            ttp_mappings.append({
                                "ttp_id": ttp_id,
                                "mapping_type": mapping_type,
                                "mapping_rationale": mapping_rationale
                            })
                    
                    # Insert all TTPs with details
                    if ttp_mappings:
                        insert_ttp_runs_with_details(source_run_id, ttp_mappings)
            except Exception as e:
                # Don't fail if database save fails
                print(f"Warning: Failed to save TTP runs to database: {e}")
        
        return report_file
    
    def _generate_markdown_report(self) -> str:
        """Generate a markdown report from the log data"""
        report = []
        report.append("# MITRE ATT&CK TTP Analysis Report")
        report.append("")
        
        # Header with metadata
        source_path = self.log_data.get('source_report_path', 'N/A')
        source_run_id = self.log_data.get('source_run_id', 'N/A')
        model = self.log_data.get('model', 'N/A')
        run_id = self.log_data.get('run_id', 'N/A')
        timestamp = self.log_data.get('timestamp', 'N/A')
        
        # Format timestamp
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00') if 'Z' in timestamp else timestamp)
            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            formatted_time = timestamp
        
        report.append(f"**Source Report:** {source_path}")
        report.append(f"**Source Run ID:** {source_run_id}")
        report.append(f"**Analysis Model:** {model}")
        report.append(f"**Analysis Run ID:** {run_id}")
        report.append(f"**Analysis Time:** {formatted_time}")
        report.append("")
        report.append("---")
        report.append("")
        
        # Summary
        techniques = self.log_data["structured_ttps"]["techniques"]
        sub_techniques = self.log_data["structured_ttps"]["sub_techniques"]
        ttp_analysis = self.log_data["ttp_analysis"]
        
        report.append("## Summary")
        report.append("")
        report.append(f"- **Total TTPs Identified:** {len(techniques)}")
        report.append(f"- **Sub-techniques Identified:** {len(sub_techniques)}")
        report.append(f"- **Total Mappings:** {len(ttp_analysis)}")
        report.append("")
        
        if sub_techniques:
            report.append("### Most Specific TTPs (Sub-techniques)")
            for st in sub_techniques:
                report.append(f"- **{st['ttp_id']}**: {st['ttp_name']}")
            report.append("")
        
        report.append("---")
        report.append("")
        
        # TTP Analysis by Step
        steps = [t for t in ttp_analysis if t.get("category") == "step"]
        if steps:
            report.append("## TTP Mappings by Verification Step")
            report.append("")
            for i, step in enumerate(steps, 1):
                report.append(f"### Step {i}: {step['step_or_finding'][:100]}")
                report.append("")
                report.append(f"- **TTP ID**: {step['ttp_id']}")
                report.append(f"- **TTP Name**: {step['ttp_name']}")
                report.append(f"- **Mapping Rationale**: {step['rationale']}")
                report.append(f"- **MITRE URL**: {step['mitre_url']}")
                report.append("")
        
        # TTP Analysis by Finding
        findings = [t for t in ttp_analysis if t.get("category") == "finding"]
        if findings:
            report.append("## TTP Mappings by Security Finding")
            report.append("")
            for i, finding in enumerate(findings, 1):
                report.append(f"### Finding {i}: {finding['step_or_finding'][:100]}")
                report.append("")
                report.append(f"- **TTP ID**: {finding['ttp_id']}")
                report.append(f"- **TTP Name**: {finding['ttp_name']}")
                report.append(f"- **Mapping Rationale**: {finding['rationale']}")
                report.append(f"- **MITRE URL**: {finding['mitre_url']}")
                report.append("")
        
        # All Unique TTPs
        if techniques:
            report.append("---")
            report.append("")
            report.append("## All Identified MITRE ATT&CK Techniques")
            report.append("")
            for tech in techniques:
                report.append(f"- **{tech['ttp_id']}**: [{tech['ttp_name']}]({tech['mitre_url']})")
            report.append("")
        
        # Full Analysis Report
        if self.log_data.get("final_report"):
            report.append("---")
            report.append("")
            report.append("## Full Analysis Report")
            report.append("")
            report.append(self.log_data["final_report"])
        
        return "\n".join(report)

