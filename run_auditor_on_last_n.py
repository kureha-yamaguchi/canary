#!/usr/bin/env python3
"""Run auditor on the last N runs"""
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict

# Add paths for imports
base_dir = Path(__file__).parent
auditor_dir = base_dir / "auditor"
red_team_dir = base_dir / "red-team-agent"

sys.path.insert(0, str(auditor_dir))

# Import modules
from auditor import AuditorAgent


def parse_run_id(run_id: str) -> datetime:
    """Parse run ID (YYYYMMDD_HHMMSS) to datetime"""
    try:
        return datetime.strptime(run_id, "%Y%m%d_%H%M%S")
    except ValueError:
        return None


def get_all_run_ids(limit: int = None) -> List[str]:
    """Get all run IDs, sorted by time (most recent first)"""
    logs_dir = red_team_dir / "logs"
    if not logs_dir.exists():
        return []
    
    all_runs = []
    
    for run_dir in logs_dir.iterdir():
        if not run_dir.is_dir():
            continue
        
        # Extract run_id from directory name (e.g., "run_20251123_141238" -> "20251123_141238")
        dir_name = run_dir.name
        if not dir_name.startswith("run_"):
            continue
        
        run_id = dir_name[4:]  # Remove "run_" prefix
        run_time = parse_run_id(run_id)
        
        if run_time:
            # Check if report file exists
            report_file = run_dir / "report"
            if report_file.exists():
                all_runs.append((run_id, run_time))
    
    # Sort by time (most recent first)
    all_runs.sort(key=lambda x: x[1], reverse=True)
    
    # Return limited number if specified
    if limit:
        return [run_id for run_id, _ in all_runs[:limit]]
    return [run_id for run_id, _ in all_runs]


def run_auditor_on_report(run_id: str, red_team_logs_dir: str = None, skip_if_exists: bool = False) -> Dict:
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


def main():
    """Main function to run auditor on last N runs"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Run auditor on the last N runs",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "-n",
        "--number",
        type=int,
        default=100,
        help="Number of runs to audit (default: 100)"
    )
    
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip runs that already have audit reports"
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print(f"🔍 AUDITOR - Last {args.number} Runs")
    print("=" * 70)
    
    # Get last N run IDs
    run_ids = get_all_run_ids(limit=args.number)
    
    if not run_ids:
        print("\n⚠️  No reports found")
        return
    
    print(f"\n📊 Found {len(run_ids)} report(s) to audit:")
    if len(run_ids) <= 10:
        for run_id in run_ids:
            run_time = parse_run_id(run_id)
            time_str = run_time.strftime("%Y-%m-%d %H:%M:%S") if run_time else run_id
            print(f"  - {run_id} ({time_str})")
    else:
        print(f"  (Showing first 5 and last 5)")
        for run_id in run_ids[:5]:
            run_time = parse_run_id(run_id)
            time_str = run_time.strftime("%Y-%m-%d %H:%M:%S") if run_time else run_id
            print(f"  - {run_id} ({time_str})")
        print(f"  ... ({len(run_ids) - 10} more) ...")
        for run_id in run_ids[-5:]:
            run_time = parse_run_id(run_id)
            time_str = run_time.strftime("%Y-%m-%d %H:%M:%S") if run_time else run_id
            print(f"  - {run_id} ({time_str})")
    
    print("\n" + "=" * 70)
    
    # Process each report
    results = []
    for i, run_id in enumerate(run_ids, 1):
        print(f"\n[{i}/{len(run_ids)}] {run_id}")
        
        # Run auditor
        audit_result = run_auditor_on_report(run_id, skip_if_exists=args.skip_existing)
        
        results.append({
            "run_id": run_id,
            "audit": audit_result
        })
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 SUMMARY")
    print("=" * 70)
    
    successful_audits = sum(1 for r in results if r["audit"].get("success"))
    skipped_audits = sum(1 for r in results if r["audit"].get("skipped", False))
    vulnerabilities_found = sum(1 for r in results if r["audit"].get("vulnerability_found"))
    
    print(f"Total Reports: {len(run_ids)}")
    print(f"Successful Audits: {successful_audits}/{len(run_ids)}")
    if skipped_audits > 0:
        print(f"Skipped (already existed): {skipped_audits}/{len(run_ids)}")
    print(f"Vulnerabilities Found: {vulnerabilities_found}/{len(run_ids)}")
    print(f"Success Rate: {(vulnerabilities_found/len(run_ids)*100):.1f}%")
    
    print("\nResults by Run ID:")
    print("-" * 70)
    for result in results[:20]:  # Show first 20
        run_id = result["run_id"]
        audit_success = "✅" if result["audit"].get("success") else "❌"
        skipped = "⏭️" if result["audit"].get("skipped") else ""
        vuln_found = "✅" if result["audit"].get("vulnerability_found") else "❌"
        
        print(f"  {run_id}: {audit_success} {skipped} Vulnerability: {vuln_found}")
    
    if len(results) > 20:
        print(f"  ... ({len(results) - 20} more results)")
    
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

