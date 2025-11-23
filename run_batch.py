#!/usr/bin/env python3
"""Batch runner for red-team agent across multiple URLs with status tracking"""
import json
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from threading import Lock

# Add paths for orchestrator
base_dir = Path(__file__).parent
orchestrator_dir = base_dir / "orchestrator"
sys.path.insert(0, str(orchestrator_dir))

from orchestrator import run_orchestrator

# Status tracking
status_lock = Lock()
statuses: Dict[str, Dict] = {}


def print_status_bar(urls: List[str], model: str):
    """Print a status bar showing progress for each URL"""
    print("\n" + "=" * 100)
    print(f"BATCH RUNNER - Model: {model}")
    print("=" * 100)
    print(f"Total URLs: {len(urls)}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 100)
    
    for i, url in enumerate(urls, 1):
        status = statuses.get(url, {})
        status_icon = status.get("icon", "⏳")
        status_text = status.get("text", "Pending")
        elapsed = status.get("elapsed", "")
        error = status.get("error", "")
        
        # Truncate URL for display
        display_url = url[:70] + "..." if len(url) > 70 else url
        
        line = f"{i:2d}/{len(urls)} {status_icon} {display_url:<73} {status_text}"
        if elapsed:
            line += f" ({elapsed})"
        print(line)
        
        if error:
            print(f"    ❌ Error: {error[:80]}")
    
    print("-" * 100)


def update_status(url: str, icon: str, text: str, error: Optional[str] = None, elapsed: Optional[str] = None):
    """Update status for a URL"""
    with status_lock:
        statuses[url] = {
            "icon": icon,
            "text": text,
            "error": error or "",
            "elapsed": elapsed or ""
        }


def format_elapsed(seconds: float) -> str:
    """Format elapsed time"""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"


def run_single_url(url: str, model: str, include_hints: bool = False, task: Optional[str] = None) -> Dict:
    """Run orchestrator for a single URL"""
    start_time = time.time()
    
    try:
        update_status(url, "🔄", "Running...")
        
        result = run_orchestrator(
            website_url=url,
            model=model,
            task=task,
            open_browser=False,
            playwright=False,
            skip_audit=False,
            save_audit_report=True,
            include_hints=include_hints
        )
        
        elapsed = time.time() - start_time
        
        # Check if result is valid
        if result is None:
            update_status(url, "❌", "No Result", elapsed=format_elapsed(elapsed))
            return {
                "success": False,
                "error": "Orchestrator returned None",
                "elapsed": elapsed
            }
        
        # Check if vulnerability was found
        # The orchestrator returns vulnerability_found at the top level
        # Also check nested structure as fallback
        vulnerability_found = result.get("vulnerability_found", False)
        if not vulnerability_found:
            audit_result = result.get("auditor_result") or {}
            if isinstance(audit_result, dict):
                vulnerability_found = audit_result.get("audit_result", {}).get("vulnerability_found", False)
        
        if vulnerability_found:
            update_status(url, "✅", "Vulnerability Found", elapsed=format_elapsed(elapsed))
        else:
            update_status(url, "❌", "No Vulnerability", elapsed=format_elapsed(elapsed))
        
        return {
            "success": True,
            "result": result,
            "elapsed": elapsed,
            "vulnerability_found": vulnerability_found
        }
        
    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        update_status(url, "⚠️", "Interrupted", elapsed=format_elapsed(elapsed))
        raise
    except Exception as e:
        elapsed = time.time() - start_time
        error_msg = str(e)[:100]
        update_status(url, "❌", "Failed", error=error_msg, elapsed=format_elapsed(elapsed))
        return {
            "success": False,
            "error": str(e),
            "elapsed": elapsed
        }


def run_batch(runs_plan_path: str, model: str, include_hints: bool = False, task: Optional[str] = None, use_local: bool = False):
    """Run batch processing for all URLs in runs plan"""
    # Load runs plan
    runs_plan_file = Path(runs_plan_path)
    if not runs_plan_file.exists():
        print(f"❌ Error: Runs plan file not found: {runs_plan_path}")
        sys.exit(1)
    
    with open(runs_plan_file, 'r') as f:
        runs_plan = json.load(f)
    
    # Use localurls if requested, otherwise use urls
    if use_local:
        urls = runs_plan.get("localurls", [])
        if not urls:
            print("❌ Error: No localurls found in runs plan")
            sys.exit(1)
    else:
        urls = runs_plan.get("urls", [])
        if not urls:
            print("❌ Error: No URLs found in runs plan")
            sys.exit(1)
    
    # Initialize statuses
    for url in urls:
        statuses[url] = {"icon": "⏳", "text": "Pending", "error": "", "elapsed": ""}
    
    # Print initial status
    print_status_bar(urls, model)
    if include_hints:
        print("💡 Hints: ENABLED")
    else:
        print("💡 Hints: DISABLED")
    if task:
        print(f"📝 Custom Task: {task[:80]}..." if len(task) > 80 else f"📝 Custom Task: {task}")
    
    # Run each URL
    results = {}
    total_start = time.time()
    
    for i, url in enumerate(urls, 1):
        print(f"\n[{i}/{len(urls)}] Starting: {url}")
        print("-" * 100)
        
        result = run_single_url(url, model, include_hints=include_hints, task=task)
        results[url] = result
        
        # Print updated status after each run
        print_status_bar(urls, model)
        
        # Small delay between runs
        if i < len(urls):
            time.sleep(2)
    
    total_elapsed = time.time() - total_start
    
    # Print final summary
    print("\n" + "=" * 100)
    print("FINAL SUMMARY")
    print("=" * 100)
    
    successful = sum(1 for r in results.values() if r.get("success"))
    vulnerabilities_found = sum(1 for r in results.values() if r.get("vulnerability_found"))
    
    print(f"Total URLs: {len(urls)}")
    print(f"Successful: {successful}/{len(urls)}")
    print(f"Vulnerabilities Found: {vulnerabilities_found}/{len(urls)}")
    print(f"Total Time: {format_elapsed(total_elapsed)}")
    print("\nResults by URL:")
    print("-" * 100)
    
    for url, result in results.items():
        if result.get("success"):
            vuln_status = "✅ Found" if result.get("vulnerability_found") else "❌ Not Found"
            print(f"  {vuln_status} | {url} ({format_elapsed(result.get('elapsed', 0))})")
        else:
            print(f"  ❌ Failed | {url} - {result.get('error', 'Unknown error')}")
    
    print("=" * 100)
    
    return results


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Run red-team agent batch processing on all URLs from runs plan",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--runs-plan",
        default="data/runs-plan.json",
        help="Path to runs plan JSON file (default: data/runs-plan.json)"
    )
    
    parser.add_argument(
        "--model",
        default="meta-llama/llama-3.3-70b-instruct",
        help="Model to use (default: meta-llama/llama-3.3-70b-instruct)"
    )
    
    parser.add_argument(
        "--hints",
        action="store_true",
        help="Include systematic testing hints in the red-team agent prompt"
    )
    
    parser.add_argument(
        "--task",
        default=None,
        help="Custom task/prompt for the red-team agent"
    )
    
    parser.add_argument(
        "--use-local",
        action="store_true",
        help="Use localurls from runs plan instead of urls"
    )
    
    args = parser.parse_args()
    
    try:
        run_batch(args.runs_plan, args.model, include_hints=args.hints, task=args.task, use_local=args.use_local)
    except KeyboardInterrupt:
        print("\n\n⚠️  Batch run interrupted by user")
        print_status_bar(list(statuses.keys()), args.model)
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

