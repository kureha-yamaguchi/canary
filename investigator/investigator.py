"""Investigator Agent - Analyzes failed red-team agent runs to identify root causes"""
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import defaultdict

# Add paths for imports
base_dir = Path(__file__).parent.parent
red_team_dir = base_dir / "red-team-agent"
auditor_dir = base_dir / "auditor"

sys.path.insert(0, str(red_team_dir))
sys.path.insert(0, str(auditor_dir))

from auditor import AuditorAgent


class InvestigatorAgent:
    """Investigates why red-team agents failed to find vulnerabilities"""
    
    def __init__(self, red_team_logs_dir: Optional[str] = None, auditor_logs_dir: Optional[str] = None):
        """
        Initialize the Investigator Agent
        
        Args:
            red_team_logs_dir: Directory containing red-team agent logs (default: ../red-team-agent/logs)
            auditor_logs_dir: Directory containing auditor logs (default: ../auditor/logs)
        """
        self.base_dir = base_dir
        self.red_team_logs_dir = Path(red_team_logs_dir) if red_team_logs_dir else base_dir / "red-team-agent" / "logs"
        self.auditor_logs_dir = Path(auditor_logs_dir) if auditor_logs_dir else base_dir / "auditor" / "logs"
        
        # Ensure directories exist
        self.red_team_logs_dir.mkdir(exist_ok=True, parents=True)
        self.auditor_logs_dir.mkdir(exist_ok=True, parents=True)
    
    def get_recent_runs(self, limit: int = 50) -> List[str]:
        """
        Get list of recent run IDs, sorted by timestamp (most recent first)
        
        Args:
            limit: Maximum number of runs to return
            
        Returns:
            List of run IDs (format: YYYYMMDD_HHMMSS)
        """
        run_dirs = []
        for run_dir in self.red_team_logs_dir.glob("run_*"):
            if run_dir.is_dir():
                run_id = run_dir.name.replace("run_", "")
                # Check if report exists
                report_file = run_dir / "report"
                if report_file.exists():
                    run_dirs.append((run_id, run_dir))
        
        # Sort by run_id (which contains timestamp) descending
        run_dirs.sort(key=lambda x: x[0], reverse=True)
        
        return [run_id for run_id, _ in run_dirs[:limit]]
    
    def load_red_team_report(self, run_id: str) -> Optional[Dict[str, Any]]:
        """
        Load red-team agent report for a given run_id
        
        Args:
            run_id: The run ID to load
            
        Returns:
            Dictionary containing report data, or None if not found
        """
        run_dir = self.red_team_logs_dir / f"run_{run_id}"
        json_file = run_dir / "json"
        
        if not json_file.exists():
            return None
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️  Error loading report for {run_id}: {e}")
            return None
    
    def load_auditor_result(self, run_id: str) -> Optional[Dict[str, Any]]:
        """
        Load auditor result for a given run_id
        
        Args:
            run_id: The run ID to load
            
        Returns:
            Dictionary containing auditor result, or None if not found
        """
        audit_file = self.auditor_logs_dir / f"audit_{run_id}.json"
        
        if not audit_file.exists():
            return None
        
        try:
            with open(audit_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️  Error loading auditor result for {run_id}: {e}")
            return None
    
    def analyze_run(self, run_id: str) -> Dict[str, Any]:
        """
        Analyze a single run to understand why it failed
        
        Args:
            run_id: The run ID to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        report = self.load_red_team_report(run_id)
        auditor_result = self.load_auditor_result(run_id)
        
        if not report:
            return {
                "run_id": run_id,
                "status": "error",
                "error": "Report not found",
                "analysis": {}
            }
        
        # Extract key information
        website_url = report.get("website_url", "N/A")
        model = report.get("model", "N/A")
        expected_vulnerability = report.get("vulnerability") or {}
        vuln_name = expected_vulnerability.get("vulnerability_name", "Unknown") if expected_vulnerability else "Unknown"
        vuln_id = expected_vulnerability.get("vulnerability_id") if expected_vulnerability else None
        
        # Check if vulnerability was found
        vulnerability_found = False
        if auditor_result:
            audit_result = auditor_result.get("audit_result", {})
            vulnerability_found = audit_result.get("vulnerability_found", False)
        
        # Analyze why it failed (if it did)
        analysis = {
            "run_id": run_id,
            "website_url": website_url,
            "model": model,
            "expected_vulnerability": vuln_name,
            "vulnerability_id": vuln_id,
            "vulnerability_found": vulnerability_found,
            "status": "success" if vulnerability_found else "failed",
            "issues": [],
            "tools_used": [],
            "tools_missing": [],
            "technical_problems": [],
            "testing_coverage": {},
            "recommendations": []
        }
        
        if vulnerability_found:
            analysis["analysis"] = "Vulnerability was successfully found"
            return analysis
        
        # Analyze why it failed
        structured_report = report.get("structured_report", {})
        findings = structured_report.get("findings", [])
        verification_steps = structured_report.get("verification_steps", [])
        tool_calls = report.get("tool_calls", [])
        final_report = report.get("final_report", "")
        
        # Check for technical problems
        if "error" in final_report.lower() or "exception" in final_report.lower():
            analysis["technical_problems"].append("Errors or exceptions in final report")
        
        # Analyze tool usage
        tools_used = set()
        tool_failures = []
        for tool_call in tool_calls:
            tool_name = tool_call.get("tool", "unknown")
            tools_used.add(tool_name)
            result = tool_call.get("result", "")
            if "error" in str(result).lower() or "failed" in str(result).lower():
                tool_failures.append({
                    "tool": tool_name,
                    "issue": str(result)[:200]
                })
        
        analysis["tools_used"] = list(tools_used)
        
        if tool_failures:
            analysis["technical_problems"].extend([f"Tool failure: {f['tool']}" for f in tool_failures])
        
        # Check for missing critical tools based on vulnerability type
        if vuln_id == 1:  # SQL Injection
            critical_tools = ["test_sql_injection", "discover_api_endpoints"]
            missing = [t for t in critical_tools if t not in tools_used]
            if missing:
                analysis["tools_missing"] = missing
                analysis["issues"].append(f"Missing critical tools for SQL injection testing: {', '.join(missing)}")
        elif "xss" in vuln_name.lower():
            critical_tools = ["test_xss", "check_page_content"]
            missing = [t for t in critical_tools if t not in tools_used]
            if missing:
                analysis["tools_missing"] = missing
                analysis["issues"].append(f"Missing critical tools for XSS testing: {', '.join(missing)}")
        elif "api" in vuln_name.lower() or "key" in vuln_name.lower():
            critical_tools = ["check_information_disclosure", "check_page_content"]
            missing = [t for t in critical_tools if t not in tools_used]
            if missing:
                analysis["tools_missing"] = missing
                analysis["issues"].append(f"Missing critical tools for API key detection: {', '.join(missing)}")
        
        # Check testing coverage
        analysis["testing_coverage"] = {
            "verification_steps_count": len(verification_steps),
            "findings_count": len(findings),
            "tool_calls_count": len(tool_calls),
            "final_report_length": len(final_report)
        }
        
        # Check if agent actually tested the vulnerability
        if vuln_id == 1:  # SQL Injection
            sql_tested = any("sql" in str(tool_call).lower() for tool_call in tool_calls)
            if not sql_tested:
                analysis["issues"].append("SQL injection testing was not performed")
        elif "xss" in vuln_name.lower():
            xss_tested = any("xss" in str(tool_call).lower() for tool_call in tool_calls)
            if not xss_tested:
                analysis["issues"].append("XSS testing was not performed")
        
        # Check if findings mention the vulnerability but didn't match
        if auditor_result:
            audit_result = auditor_result.get("audit_result", {})
            non_matching = audit_result.get("non_matching_findings", [])
            if non_matching:
                analysis["issues"].append(f"Found {len(non_matching)} findings but they didn't match expected vulnerability")
        
        # Generate recommendations
        if analysis["tools_missing"]:
            analysis["recommendations"].append(f"Use missing tools: {', '.join(analysis['tools_missing'])}")
        
        if analysis["technical_problems"]:
            analysis["recommendations"].append("Fix technical issues preventing proper testing")
        
        if analysis["testing_coverage"]["tool_calls_count"] < 5:
            analysis["recommendations"].append("Increase testing coverage - too few tool calls")
        
        if not findings:
            analysis["recommendations"].append("Agent did not report any findings - check if testing was actually performed")
        
        return analysis
    
    def investigate(self, num_reports: int = 50) -> Dict[str, Any]:
        """
        Investigate the last N reports to identify patterns in failures
        
        Args:
            num_reports: Number of recent reports to analyze
            
        Returns:
            Dictionary containing investigation results
        """
        print(f"\n🔍 INVESTIGATOR AGENT")
        print("=" * 70)
        print(f"Analyzing last {num_reports} reports...\n")
        
        # Get recent runs
        run_ids = self.get_recent_runs(limit=num_reports)
        
        if not run_ids:
            return {
                "status": "error",
                "error": "No reports found",
                "total_reports": 0
            }
        
        print(f"Found {len(run_ids)} reports to analyze\n")
        
        # Analyze each run
        analyses = []
        success_count = 0
        failure_count = 0
        error_count = 0
        
        for i, run_id in enumerate(run_ids, 1):
            print(f"[{i}/{len(run_ids)}] Analyzing {run_id}...", end=" ", flush=True)
            analysis = self.analyze_run(run_id)
            analyses.append(analysis)
            
            if analysis.get("status") == "error":
                error_count += 1
                print("❌ Error")
            elif analysis.get("vulnerability_found"):
                success_count += 1
                print("✅ Success")
            else:
                failure_count += 1
                print("❌ Failed")
        
        # Aggregate findings
        aggregated = self._aggregate_findings(analyses)
        
        # Generate summary
        summary = {
            "total_reports": len(run_ids),
            "successful": success_count,
            "failed": failure_count,
            "errors": error_count,
            "success_rate": (success_count / len(run_ids) * 100) if run_ids else 0,
            "analyses": analyses,
            "aggregated_findings": aggregated
        }
        
        return summary
    
    def _aggregate_findings(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate findings across all analyses to identify patterns"""
        aggregated = {
            "common_issues": defaultdict(int),
            "missing_tools": defaultdict(int),
            "technical_problems": defaultdict(int),
            "vulnerability_types": defaultdict(lambda: {"total": 0, "success": 0, "failed": 0}),
            "model_performance": defaultdict(lambda: {"total": 0, "success": 0, "failed": 0})
        }
        
        for analysis in analyses:
            vuln_type = analysis.get("expected_vulnerability", "Unknown")
            model = analysis.get("model", "Unknown")
            found = analysis.get("vulnerability_found", False)
            
            # Track by vulnerability type
            aggregated["vulnerability_types"][vuln_type]["total"] += 1
            if found:
                aggregated["vulnerability_types"][vuln_type]["success"] += 1
            else:
                aggregated["vulnerability_types"][vuln_type]["failed"] += 1
            
            # Track by model
            aggregated["model_performance"][model]["total"] += 1
            if found:
                aggregated["model_performance"][model]["success"] += 1
            else:
                aggregated["model_performance"][model]["failed"] += 1
            
            # Track common issues
            for issue in analysis.get("issues", []):
                aggregated["common_issues"][issue] += 1
            
            # Track missing tools
            for tool in analysis.get("tools_missing", []):
                aggregated["missing_tools"][tool] += 1
            
            # Track technical problems
            for problem in analysis.get("technical_problems", []):
                aggregated["technical_problems"][problem] += 1
        
        return aggregated
    
    def generate_report(self, investigation_result: Dict[str, Any]) -> str:
        """Generate a human-readable investigation report"""
        report = []
        report.append("# Investigator Agent Report")
        report.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("\n" + "=" * 70 + "\n")
        
        # Summary
        report.append("## Summary")
        report.append(f"- **Total Reports Analyzed:** {investigation_result['total_reports']}")
        report.append(f"- **Successful:** {investigation_result['successful']}")
        report.append(f"- **Failed:** {investigation_result['failed']}")
        report.append(f"- **Errors:** {investigation_result['errors']}")
        report.append(f"- **Success Rate:** {investigation_result['success_rate']:.1f}%")
        report.append("\n")
        
        # Aggregated findings
        aggregated = investigation_result.get("aggregated_findings", {})
        
        # Vulnerability type performance
        report.append("## Performance by Vulnerability Type")
        vuln_types = aggregated.get("vulnerability_types", {})
        for vuln_type, stats in sorted(vuln_types.items(), key=lambda x: x[1]["total"], reverse=True):
            total = stats["total"]
            success = stats["success"]
            failed = stats["failed"]
            success_rate = (success / total * 100) if total > 0 else 0
            report.append(f"- **{vuln_type}**: {success}/{total} ({success_rate:.1f}%)")
        report.append("\n")
        
        # Model performance
        report.append("## Performance by Model")
        models = aggregated.get("model_performance", {})
        for model, stats in sorted(models.items(), key=lambda x: x[1]["total"], reverse=True):
            total = stats["total"]
            success = stats["success"]
            failed = stats["failed"]
            success_rate = (success / total * 100) if total > 0 else 0
            report.append(f"- **{model}**: {success}/{total} ({success_rate:.1f}%)")
        report.append("\n")
        
        # Common issues
        report.append("## Common Issues")
        common_issues = aggregated.get("common_issues", {})
        if common_issues:
            for issue, count in sorted(common_issues.items(), key=lambda x: x[1], reverse=True)[:10]:
                report.append(f"- **{issue}** (appeared in {count} reports)")
        else:
            report.append("- No common issues identified")
        report.append("\n")
        
        # Missing tools
        report.append("## Missing Tools")
        missing_tools = aggregated.get("missing_tools", {})
        if missing_tools:
            for tool, count in sorted(missing_tools.items(), key=lambda x: x[1], reverse=True):
                report.append(f"- **{tool}** (missing in {count} reports)")
        else:
            report.append("- No missing tools identified")
        report.append("\n")
        
        # Technical problems
        report.append("## Technical Problems")
        tech_problems = aggregated.get("technical_problems", {})
        if tech_problems:
            for problem, count in sorted(tech_problems.items(), key=lambda x: x[1], reverse=True)[:10]:
                report.append(f"- **{problem}** (appeared in {count} reports)")
        else:
            report.append("- No technical problems identified")
        report.append("\n")
        
        # Failed runs details
        report.append("## Failed Runs Analysis")
        failed_runs = [a for a in investigation_result.get("analyses", []) if not a.get("vulnerability_found") and a.get("status") != "error"]
        
        if failed_runs:
            report.append(f"\n### Top 10 Failed Runs with Issues:\n")
            for run in failed_runs[:10]:
                run_id = run.get("run_id", "N/A")
                vuln = run.get("expected_vulnerability", "Unknown")
                issues = run.get("issues", [])
                report.append(f"**Run {run_id}** ({vuln}):")
                if issues:
                    for issue in issues[:3]:
                        report.append(f"  - {issue}")
                else:
                    report.append("  - No specific issues identified")
                report.append("")
        else:
            report.append("- No failed runs to analyze")
        
        return "\n".join(report)
    
    def save_report(self, investigation_result: Dict[str, Any], output_file: Optional[Path] = None) -> Path:
        """Save investigation report to file"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = self.base_dir / "investigator" / "logs"
            output_dir.mkdir(exist_ok=True, parents=True)
            output_file = output_dir / f"investigation_{timestamp}.md"
        
        # Generate and save markdown report
        report_text = self.generate_report(investigation_result)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        # Also save JSON
        json_file = output_file.with_suffix('.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(investigation_result, f, indent=2, ensure_ascii=False)
        
        return output_file

