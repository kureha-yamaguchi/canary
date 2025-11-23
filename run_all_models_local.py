#!/usr/bin/env python3
"""Run all models from runs-plan.json on all local URLs with comprehensive tracking"""
import json
import sys
import time
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

# Add paths for orchestrator
base_dir = Path(__file__).parent
orchestrator_dir = base_dir / "orchestrator"
sys.path.insert(0, str(orchestrator_dir))

from orchestrator import run_orchestrator

# Tracker file path
TRACKER_FILE = base_dir / "data" / "runs_tracker.json"

# Status tracking
status_lock = Lock()

# Timeout settings
MAX_RUN_TIME_SECONDS = 600  # 10 minutes per URL


def load_tracker() -> Dict:
    """Load tracker from file"""
    if TRACKER_FILE.exists():
        try:
            with open(TRACKER_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️  Warning: Could not load tracker: {e}")
    return {
        "started_at": datetime.now().isoformat(),
        "models": {},
        "summary": {
            "total_runs": 0,
            "completed": 0,
            "failed": 0,
            "vulnerabilities_found": 0
        }
    }


def save_tracker(tracker: Dict):
    """Save tracker to file"""
    try:
        with open(TRACKER_FILE, 'w') as f:
            json.dump(tracker, f, indent=2)
    except Exception as e:
        print(f"⚠️  Warning: Could not save tracker: {e}")


def update_tracker(model: str, url: str, status: str, result: Optional[Dict] = None, error: Optional[str] = None):
    """Update tracker with run result"""
    with status_lock:
        tracker = load_tracker()
        
        if model not in tracker["models"]:
            tracker["models"][model] = {}
        
        if url not in tracker["models"][model]:
            tracker["models"][model][url] = {
                "status": "pending",
                "started_at": None,
                "completed_at": None,
                "elapsed_seconds": None,
                "vulnerability_found": False,
                "error": None
            }
        
        run_info = tracker["models"][model][url]
        run_info["status"] = status
        
        if status == "running":
            run_info["started_at"] = datetime.now().isoformat()
        elif status in ["completed", "failed"]:
            run_info["completed_at"] = datetime.now().isoformat()
            if result:
                run_info["elapsed_seconds"] = result.get("elapsed", 0)
                run_info["vulnerability_found"] = result.get("vulnerability_found", False)
                if run_info["vulnerability_found"]:
                    tracker["summary"]["vulnerabilities_found"] += 1
            if error:
                run_info["error"] = error
                tracker["summary"]["failed"] += 1
            else:
                tracker["summary"]["completed"] += 1
        
        tracker["last_updated"] = datetime.now().isoformat()
        save_tracker(tracker)


def print_tracker_status(tracker: Dict, current_model: Optional[str] = None, current_url: Optional[str] = None):
    """Print current tracker status"""
    print("\n" + "=" * 100)
    print("📊 RUNS TRACKER")
    print("=" * 100)
    
    summary = tracker["summary"]
    total_models = len(tracker["models"])
    total_runs = sum(len(urls) for urls in tracker["models"].values())
    
    print(f"Total Models: {total_models}")
    print(f"Total Runs: {total_runs}")
    print(f"Completed: {summary['completed']}/{total_runs}")
    print(f"Failed: {summary['failed']}/{total_runs}")
    print(f"Vulnerabilities Found: {summary['vulnerabilities_found']}")
    
    if current_model and current_url:
        print(f"\n🔄 Currently Running: {current_model} on {current_url}")
    
    print("\nStatus by Model:")
    print("-" * 100)
    
    for model, urls in sorted(tracker["models"].items()):
        completed = sum(1 for u in urls.values() if u["status"] == "completed")
        failed = sum(1 for u in urls.values() if u["status"] == "failed")
        running = sum(1 for u in urls.values() if u["status"] == "running")
        pending = sum(1 for u in urls.values() if u["status"] == "pending")
        vulns = sum(1 for u in urls.values() if u.get("vulnerability_found", False))
        
        status_icon = "🔄" if running > 0 else "✅" if completed == len(urls) else "⏳"
        print(f"{status_icon} {model}")
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
            
            print(f"      {icon} {vuln_icon} {url}{elapsed}{error}")
    
    print("=" * 100)


def run_single_url_with_timeout(url: str, model: str, timeout: int = MAX_RUN_TIME_SECONDS) -> Dict:
    """Run orchestrator for a single URL with timeout"""
    start_time = time.time()
    
    def run_orchestrator_wrapper():
        """Wrapper to run orchestrator in a thread"""
        try:
            return run_orchestrator(
                website_url=url,
                model=model,
                task=None,
                open_browser=False,
                playwright=False,
                skip_audit=False,
                save_audit_report=True,
                include_hints=False
            )
        except Exception as e:
            raise e
    
    try:
        update_tracker(model, url, "running")
        
        # Run with timeout using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(run_orchestrator_wrapper)
            try:
                result = future.result(timeout=timeout)
            except FutureTimeoutError:
                elapsed = time.time() - start_time
                error_msg = f"Timeout after {timeout}s ({elapsed:.1f}s elapsed)"
                update_tracker(model, url, "failed", error=error_msg, elapsed=elapsed)
                return {
                    "success": False,
                    "error": error_msg,
                    "elapsed": elapsed
                }
        
        elapsed = time.time() - start_time
        
        if result is None:
            update_tracker(model, url, "failed", error="Orchestrator returned None", elapsed=elapsed)
            return {
                "success": False,
                "error": "Orchestrator returned None",
                "elapsed": elapsed
            }
        
        vulnerability_found = result.get("vulnerability_found", False)
        if not vulnerability_found:
            audit_result = result.get("auditor_result") or {}
            if isinstance(audit_result, dict):
                vulnerability_found = audit_result.get("audit_result", {}).get("vulnerability_found", False)
        
        update_tracker(model, url, "completed", {
            "elapsed": elapsed,
            "vulnerability_found": vulnerability_found
        })
        
        return {
            "success": True,
            "result": result,
            "elapsed": elapsed,
            "vulnerability_found": vulnerability_found
        }
        
    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        update_tracker(model, url, "failed", error="Interrupted by user", elapsed=elapsed)
        raise
    except Exception as e:
        elapsed = time.time() - start_time
        error_msg = str(e)[:200]
        update_tracker(model, url, "failed", error=error_msg, elapsed=elapsed)
        return {
            "success": False,
            "error": str(e),
            "elapsed": elapsed
        }


def run_single_url(url: str, model: str) -> Dict:
    """Run orchestrator for a single URL (wrapper for timeout version)"""
    return run_single_url_with_timeout(url, model, MAX_RUN_TIME_SECONDS)


def run_model_on_all_urls(model: str, local_urls: List[str], model_idx: int, total_models: int) -> Dict:
    """Run a single model on all URLs sequentially"""
    results = {}
    
    print(f"\n\n{'=' * 100}")
    print(f"MODEL {model_idx}/{total_models}: {model}")
    print(f"{'=' * 100}")
    
    for url_idx, url in enumerate(local_urls, 1):
        print(f"\n[{model_idx}/{total_models}] [{url_idx}/{len(local_urls)}] Running {model} on {url}")
        print("-" * 100)
        
        result = run_single_url(url, model)
        results[url] = result
        
        # Print updated status
        tracker = load_tracker()
        print_tracker_status(tracker, model, url)
        
        # Small delay between runs
        if url_idx < len(local_urls):
            time.sleep(1)
    
    return results


def run_all_models_local(runs_plan_path: str = "data/runs-plan.json", timeout: int = MAX_RUN_TIME_SECONDS, max_workers: Optional[int] = None):
    """Run all models on all local URLs"""
    # Load runs plan
    runs_plan_file = Path(runs_plan_path)
    if not runs_plan_file.exists():
        print(f"❌ Error: Runs plan file not found: {runs_plan_path}")
        sys.exit(1)
    
    with open(runs_plan_file, 'r') as f:
        runs_plan = json.load(f)
    
    models = runs_plan.get("models", [])
    local_urls = runs_plan.get("localurls", [])
    
    if not models:
        print("❌ Error: No models found in runs plan")
        sys.exit(1)
    
    if not local_urls:
        print("❌ Error: No localurls found in runs plan")
        sys.exit(1)
    
    print("\n" + "=" * 100)
    print("🚀 STARTING BATCH RUN: All Models on Local URLs")
    print("=" * 100)
    print(f"Models: {len(models)}")
    print(f"Local URLs: {len(local_urls)}")
    print(f"Total Runs: {len(models) * len(local_urls)}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 100)
    
    # Initialize tracker
    tracker = load_tracker()
    tracker["started_at"] = datetime.now().isoformat()
    tracker["summary"]["total_runs"] = len(models) * len(local_urls)
    
    # Initialize all runs in tracker
    for model in models:
        if model not in tracker["models"]:
            tracker["models"][model] = {}
        for url in local_urls:
            if url not in tracker["models"][model]:
                tracker["models"][model][url] = {
                    "status": "pending",
                    "started_at": None,
                    "completed_at": None,
                    "elapsed_seconds": None,
                    "vulnerability_found": False,
                    "error": None
                }
    
    save_tracker(tracker)
    
    # Determine max workers
    if max_workers is None:
        max_workers = len(models)
    max_workers = min(max_workers, len(models))  # Don't exceed number of models
    
    # Update global timeout if provided
    global MAX_RUN_TIME_SECONDS
    if timeout != MAX_RUN_TIME_SECONDS:
        MAX_RUN_TIME_SECONDS = timeout
    
    # Run models in parallel (each model processes URLs sequentially)
    print(f"\n🚀 Running {len(models)} models in parallel (max {max_workers} concurrent)")
    print(f"⏱️  Timeout per URL: {MAX_RUN_TIME_SECONDS}s ({MAX_RUN_TIME_SECONDS // 60} minutes)")
    print("=" * 100)
    
    all_results = {}
    
    # Use ThreadPoolExecutor to run models in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all models
        futures = {}
        for model_idx, model in enumerate(models, 1):
            future = executor.submit(
                run_model_on_all_urls,
                model,
                local_urls,
                model_idx,
                len(models)
            )
            futures[future] = model
        
        # Wait for all models to complete
        for future in futures:
            model = futures[future]
            try:
                results = future.result()
                all_results[model] = results
            except Exception as e:
                print(f"\n❌ Error running model {model}: {e}")
                all_results[model] = {"error": str(e)}
    
    # Final summary
    tracker = load_tracker()
    print("\n\n" + "=" * 100)
    print("🎉 FINAL SUMMARY")
    print("=" * 100)
    
    summary = tracker["summary"]
    print(f"Total Runs: {summary['total_runs']}")
    print(f"Completed: {summary['completed']}")
    print(f"Failed: {summary['failed']}")
    print(f"Vulnerabilities Found: {summary['vulnerabilities_found']}")
    
    print("\nResults by Model:")
    print("-" * 100)
    
    for model, urls in sorted(tracker["models"].items()):
        completed = sum(1 for u in urls.values() if u["status"] == "completed")
        failed = sum(1 for u in urls.values() if u["status"] == "failed")
        vulns = sum(1 for u in urls.values() if u.get("vulnerability_found", False))
        
        print(f"\n{model}:")
        print(f"  Completed: {completed}/{len(urls)} | Failed: {failed} | Vulnerabilities: {vulns}")
        
        for url, info in sorted(urls.items()):
            status_icon = {
                "completed": "✅",
                "failed": "❌",
                "running": "🔄",
                "pending": "⏳"
            }.get(info["status"], "❓")
            
            vuln_icon = "🔓" if info.get("vulnerability_found") else ""
            elapsed = f" ({info.get('elapsed_seconds', 0):.1f}s)" if info.get("elapsed_seconds") else ""
            
            print(f"    {status_icon} {vuln_icon} {url}{elapsed}")
            if info.get("error"):
                print(f"      Error: {info['error'][:100]}")
    
    print("\n" + "=" * 100)
    print(f"📄 Tracker saved to: {TRACKER_FILE}")
    print("=" * 100)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Run all models from runs-plan.json on all local URLs",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--runs-plan",
        default="data/runs-plan.json",
        help="Path to runs plan JSON file (default: data/runs-plan.json)"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=MAX_RUN_TIME_SECONDS,
        help=f"Maximum time per URL in seconds (default: {MAX_RUN_TIME_SECONDS}s)"
    )
    
    parser.add_argument(
        "--max-workers",
        type=int,
        default=None,
        help="Maximum number of models to run in parallel (default: all models)"
    )
    
    args = parser.parse_args()
    
    # Update timeout if provided
    if args.timeout != MAX_RUN_TIME_SECONDS:
        MAX_RUN_TIME_SECONDS = args.timeout
    
    try:
        run_all_models_local(args.runs_plan, timeout=args.timeout, max_workers=args.max_workers)
    except KeyboardInterrupt:
        print("\n\n⚠️  Batch run interrupted by user")
        tracker = load_tracker()
        print_tracker_status(tracker)
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

