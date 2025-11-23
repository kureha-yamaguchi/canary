#!/usr/bin/env python3
"""View the runs tracker status"""
import json
import sys
from pathlib import Path
from datetime import datetime

TRACKER_FILE = Path(__file__).parent / "data" / "runs_tracker.json"


def view_tracker():
    """Display tracker status"""
    if not TRACKER_FILE.exists():
        print("❌ Tracker file not found. Run the batch script first.")
        sys.exit(1)
    
    with open(TRACKER_FILE, 'r') as f:
        tracker = json.load(f)
    
    print("\n" + "=" * 100)
    print("📊 RUNS TRACKER STATUS")
    print("=" * 100)
    
    summary = tracker["summary"]
    total_models = len(tracker["models"])
    total_runs = sum(len(urls) for urls in tracker["models"].values())
    
    print(f"Started: {tracker.get('started_at', 'N/A')}")
    print(f"Last Updated: {tracker.get('last_updated', 'N/A')}")
    print(f"\nTotal Models: {total_models}")
    print(f"Total Runs: {total_runs}")
    print(f"Completed: {summary['completed']}/{total_runs}")
    print(f"Failed: {summary['failed']}/{total_runs}")
    print(f"Vulnerabilities Found: {summary['vulnerabilities_found']}")
    
    if total_runs > 0:
        progress = (summary['completed'] + summary['failed']) / total_runs * 100
        print(f"Progress: {progress:.1f}%")
    
    print("\n" + "-" * 100)
    print("Status by Model:")
    print("-" * 100)
    
    for model, urls in sorted(tracker["models"].items()):
        completed = sum(1 for u in urls.values() if u["status"] == "completed")
        failed = sum(1 for u in urls.values() if u["status"] == "failed")
        running = sum(1 for u in urls.values() if u["status"] == "running")
        pending = sum(1 for u in urls.values() if u["status"] == "pending")
        vulns = sum(1 for u in urls.values() if u.get("vulnerability_found", False))
        
        status_icon = "🔄" if running > 0 else "✅" if completed == len(urls) and failed == 0 else "⏳"
        print(f"\n{status_icon} {model}")
        print(f"   Completed: {completed}/{len(urls)} | Failed: {failed} | Running: {running} | Pending: {pending} | Vulns: {vulns}")
        
        # Show URL statuses
        for url, info in sorted(urls.items()):
            icon = {
                "completed": "✅",
                "running": "🔄",
                "failed": "❌",
                "pending": "⏳"
            }.get(info["status"], "❓")
            
            vuln_icon = "🔓" if info.get("vulnerability_found") else ""
            elapsed = f" ({info.get('elapsed_seconds', 0):.1f}s)" if info.get("elapsed_seconds") else ""
            error = f" - {info['error']}" if info.get("error") else ""
            
            started = info.get("started_at")
            if started:
                try:
                    start_dt = datetime.fromisoformat(started)
                    started_str = start_dt.strftime("%H:%M:%S")
                except:
                    started_str = started
            else:
                started_str = ""
            
            print(f"      {icon} {vuln_icon} {url}{elapsed}{error}")
            if started_str:
                print(f"         Started: {started_str}")
    
    print("\n" + "=" * 100)
    print(f"📄 Tracker file: {TRACKER_FILE}")
    print("=" * 100)


if __name__ == "__main__":
    try:
        view_tracker()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

