#!/usr/bin/env python3
"""Run auditor and TTP Master on all reports from the last hour"""
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict

# Add paths for imports
base_dir = Path(__file__).parent
auditor_dir = base_dir / "auditor"
ttp_master_dir = base_dir / "ttp-master"
red_team_dir = base_dir / "red-team-agent"

sys.path.insert(0, str(auditor_dir))
sys.path.insert(0, str(ttp_master_dir))

# Import modules
from auditor import AuditorAgent
from auditor import audit_report

# Import TTP Master
TTP_MASTER_AVAILABLE = False
analyze_ttp_report = None
try:
    import importlib.util
    ttp_agent_path = ttp_master_dir / "agent.py"
    if ttp_agent_path.exists():
        ttp_master_path_str = str(ttp_master_dir)
        if ttp_master_path_str in sys.path:
            sys.path.remove(ttp_master_path_str)
        sys.path.insert(0, ttp_master_path_str)
        
        spec = importlib.util.spec_from_file_location("ttp_master_agent", ttp_agent_path)
        ttp_master_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ttp_master_module)
        analyze_ttp_report = ttp_master_module.analyze_report
        TTP_MASTER_AVAILABLE = True
except Exception as e:
    print(f"⚠️  TTP Master import failed: {e}")
    TTP_MASTER_AVAILABLE = False


def parse_run_id(run_id: str) -> datetime:
    """Parse run ID (YYYYMMDD_HHMMSS) to datetime"""
    try:
        return datetime.strptime(run_id, "%Y%m%d_%H%M%S")
    except ValueError:
        return None


def get_recent_run_ids(hours: int = 1) -> List[str]:
    """Get all run IDs from the last N hours"""
    logs_dir = red_team_dir / "logs"
    if not logs_dir.exists():
        return []
    
    cutoff_time = datetime.now() - timedelta(hours=hours)
    recent_runs = []
    
    for run_dir in logs_dir.iterdir():
        if not run_dir.is_dir():
            continue
        
        # Extract run_id from directory name (e.g., "run_20251123_141238" -> "20251123_141238")
        dir_name = run_dir.name
        if not dir_name.startswith("run_"):
            continue
        
        run_id = dir_name[4:]  # Remove "run_" prefix
        run_time = parse_run_id(run_id)
        
        if run_time and run_time >= cutoff_time:
            # Check if report file exists
            report_file = run_dir / "report"
            if report_file.exists():
                recent_runs.append((run_id, run_time))
    
    # Sort by time (most recent first)
    recent_runs.sort(key=lambda x: x[1], reverse=True)
    return [run_id for run_id, _ in recent_runs]


def run_auditor_on_report(run_id: str, red_team_logs_dir: str = None, skip_if_exists: bool = True) -> Dict:
    """Run auditor on a specific report"""
    try:
        # Check if audit already exists
        if skip_if_exists:
            base_dir = Path(__file__).parent
            auditor_logs_dir = base_dir / "auditor" / "logs"
            audit_file = auditor_logs_dir / f"audit_{run_id}.json"
            if audit_file.exists():
                print(f"⏭️  Audit already exists for {run_id}, skipping...")
                import json
                with open(audit_file, 'r', encoding='utf-8') as f:
                    audit_result = json.load(f)
                vulnerability_found = audit_result.get("audit_result", {}).get("vulnerability_found", False)
                return {
                    "success": True,
                    "skipped": True,
                    "vulnerability_found": vulnerability_found,
                    "audit_result": audit_result
                }
        
        print(f"🔍 Auditing: {run_id}")
        
        auditor = AuditorAgent(red_team_logs_dir=red_team_logs_dir)
        audit_result = auditor.audit(run_id, interactive=False)
        
        if audit_result.get("status") == "error":
            print(f"❌ Auditor error: {audit_result.get('error', 'Unknown error')}")
            return {"success": False, "error": audit_result.get('error')}
        
        # Generate and save report (don't print full report for batch processing)
        audit_report_text = auditor.generate_report(audit_result)
        
        # Save audit report
        base_dir = Path(__file__).parent
        auditor_logs_dir = base_dir / "auditor" / "logs"
        auditor_logs_dir.mkdir(exist_ok=True, parents=True)
        
        report_file = auditor_logs_dir / f"audit_{run_id}.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(audit_report_text)
        
        import json
        json_file = auditor_logs_dir / f"audit_{run_id}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(audit_result, f, indent=2, ensure_ascii=False)
        
        vulnerability_found = audit_result.get("audit_result", {}).get("vulnerability_found", False)
        status = "✅ Found" if vulnerability_found else "❌ Not Found"
        print(f"  {status}")
        
        vulnerability_found = audit_result.get("audit_result", {}).get("vulnerability_found", False)
        return {
            "success": True,
            "vulnerability_found": vulnerability_found,
            "audit_result": audit_result
        }
        
    except Exception as e:
        print(f"❌ Error running auditor: {e}")
        import traceback
        traceback.print_exc()
        return {"success": False, "error": str(e)}


def run_ttp_master_on_report(run_id: str, model: str = None, skip_if_exists: bool = True) -> Dict:
    """Run TTP Master on a specific report"""
    if not TTP_MASTER_AVAILABLE or not analyze_ttp_report:
        print("⚠️  TTP Master not available, skipping...")
        return {"success": False, "error": "TTP Master not available"}
    
    try:
        # Check if TTP analysis already exists
        report_dir = red_team_dir / "logs" / f"run_{run_id}"
        if skip_if_exists:
            ttp_file = report_dir / "ttp_analysis.json"
            if ttp_file.exists():
                print(f"⏭️  TTP analysis already exists for {run_id}, skipping...")
                return {"success": True, "skipped": True, "message": "Already exists"}
        
        print(f"\n{'='*70}")
        print(f"🎯 TTP MASTER AGENT - Run ID: {run_id}")
        print(f"{'='*70}")
        
        if not report_dir.exists():
            print(f"⚠️  Report directory not found: {report_dir}")
            return {"success": False, "error": "Report directory not found"}
        
        # Use default model if not specified
        if not model:
            # Try to get model from JSON file
            json_file = report_dir / "json"
            if json_file.exists():
                import json
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    model = data.get("model", "openai/gpt-4o")
            else:
                model = "openai/gpt-4o"
        
        ttp_result = analyze_ttp_report(
            report_path=str(report_dir),
            model=model,
            verbose=False  # Less verbose for batch processing
        )
        
        if ttp_result:
            ttp_count = len(ttp_result.get("structured_ttps", {}).get("techniques", []))
            print(f"✅ TTP Master: {ttp_count} TTPs identified")
            return {
                "success": True,
                "ttp_count": ttp_count,
                "ttp_result": ttp_result
            }
        else:
            return {"success": False, "error": "No TTP result returned"}
        
    except Exception as e:
        print(f"❌ Error running TTP Master: {e}")
        return {"success": False, "error": str(e)}


def main():
    """Main function to run auditor and TTP Master on recent reports"""
    print("=" * 70)
    print("🔍 AUDITOR & TTP MASTER - Recent Reports")
    print("=" * 70)
    
    # Get reports from last hour
    recent_run_ids = get_recent_run_ids(hours=1)
    
    if not recent_run_ids:
        print("\n⚠️  No reports found from the last hour")
        return
    
    print(f"\n📊 Found {len(recent_run_ids)} report(s) from the last hour:")
    for run_id in recent_run_ids:
        run_time = parse_run_id(run_id)
        time_str = run_time.strftime("%Y-%m-%d %H:%M:%S") if run_time else run_id
        print(f"  - {run_id} ({time_str})")
    
    print("\n" + "=" * 70)
    
    # Process each report
    results = []
    for i, run_id in enumerate(recent_run_ids, 1):
        print(f"\n[{i}/{len(recent_run_ids)}] {run_id}")
        
        # Run auditor
        audit_result = run_auditor_on_report(run_id, skip_if_exists=True)
        
        # Run TTP Master (skip if already exists)
        ttp_result = run_ttp_master_on_report(run_id, skip_if_exists=True)
        
        results.append({
            "run_id": run_id,
            "audit": audit_result,
            "ttp": ttp_result
        })
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 SUMMARY")
    print("=" * 70)
    
    successful_audits = sum(1 for r in results if r["audit"].get("success"))
    successful_ttps = sum(1 for r in results if r["ttp"].get("success"))
    vulnerabilities_found = sum(1 for r in results if r["audit"].get("vulnerability_found"))
    
    print(f"Total Reports: {len(recent_run_ids)}")
    print(f"Successful Audits: {successful_audits}/{len(recent_run_ids)}")
    print(f"Successful TTP Analyses: {successful_ttps}/{len(recent_run_ids)}")
    print(f"Vulnerabilities Found: {vulnerabilities_found}/{len(recent_run_ids)}")
    
    print("\nResults by Run ID:")
    print("-" * 70)
    for result in results:
        run_id = result["run_id"]
        audit_success = "✅" if result["audit"].get("success") else "❌"
        ttp_success = "✅" if result["ttp"].get("success") else "❌"
        vuln_found = "✅" if result["audit"].get("vulnerability_found") else "❌"
        
        print(f"  {run_id}:")
        print(f"    Audit: {audit_success} | TTP: {ttp_success} | Vulnerability: {vuln_found}")
    
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

