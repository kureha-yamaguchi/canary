"""Orchestrator for running red-team agent and auditor sequentially"""
import sys
import os
import argparse
from pathlib import Path
from typing import Optional

# Add paths for imports
base_dir = Path(__file__).parent.parent
red_team_dir = base_dir / "red-team-agent"
auditor_dir = base_dir / "auditor"
ttp_master_dir = base_dir / "ttp-master"

# Import red-team-agent and auditor first (before adding ttp-master to path)
sys.path.insert(0, str(red_team_dir))
sys.path.insert(0, str(auditor_dir))

# Import modules
from agent import activate_agent
from auditor import AuditorAgent

# Import TTP Master (handle import error gracefully) - add to path after other imports
TTP_MASTER_AVAILABLE = False
analyze_ttp_report = None
try:
    # Import from ttp-master/agent.py using importlib
    # Ensure ttp-master is at the very front of sys.path to avoid import conflicts
    import importlib.util
    ttp_agent_path = ttp_master_dir / "agent.py"
    if ttp_agent_path.exists():
        ttp_master_path_str = str(ttp_master_dir)
        
        # Move ttp-master to the very front (index 0) if it exists elsewhere
        if ttp_master_path_str in sys.path:
            sys.path.remove(ttp_master_path_str)
        sys.path.insert(0, ttp_master_path_str)
        
        # Now load the module - it should find its own logger since ttp-master is first
        spec = importlib.util.spec_from_file_location("ttp_master_agent", ttp_agent_path)
        ttp_master_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ttp_master_module)
        analyze_ttp_report = ttp_master_module.analyze_report
        TTP_MASTER_AVAILABLE = True
        # Keep ttp-master in path at front for later use
except Exception as e:
    TTP_MASTER_AVAILABLE = False
    # Show error for debugging but don't fail completely
    # The TTP Master is optional - orchestrator can work without it
    print(f"⚠️  TTP Master import failed: {e}")
    import traceback
    traceback.print_exc()


def extract_run_id_from_report_file(report_file_path: str) -> Optional[str]:
    """
    Extract run_id from report file path
    
    Args:
        report_file_path: Path to the report file (e.g., "logs/run_1763830815685/report")
    
    Returns:
        Run ID string, or None if not found
    """
    try:
        # Extract from path like "logs/run_1763830815685/report"
        path = Path(report_file_path)
        # Get the parent directory name (e.g., "run_1763830815685")
        run_dir_name = path.parent.name
        # Remove "run_" prefix
        if run_dir_name.startswith("run_"):
            return run_dir_name[4:]  # Remove "run_" prefix
        return None
    except Exception:
        return None


def extract_run_id_from_json(json_file_path: str) -> Optional[str]:
    """
    Extract run_id from JSON file
    
    Args:
        json_file_path: Path to the JSON log file
    
    Returns:
        Run ID string, or None if not found
    """
    try:
        import json
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get("run_id")
    except Exception:
        return None


def get_run_id_from_report(report_file: str) -> Optional[str]:
    """
    Get run_id from report file path
    
    Args:
        report_file: Path to report file
    
    Returns:
        Run ID string, or None if not found
    """
    # Try extracting from path first
    run_id = extract_run_id_from_report_file(report_file)
    if run_id:
        return run_id
    
    # Try reading from JSON file in same directory
    report_path = Path(report_file)
    json_file = report_path.parent / "json"
    if json_file.exists():
        return extract_run_id_from_json(str(json_file))
    
    return None


def run_orchestrator(
    website_url: str,
    model: Optional[str] = None,
    task: Optional[str] = None,
    open_browser: bool = False,
    playwright: bool = False,
    skip_audit: bool = False,
    red_team_logs_dir: Optional[str] = None,
    save_audit_report: bool = True,
    include_hints: bool = False
) -> dict:
    """
    Run the orchestrator: execute red-team agent, then auditor
    
    Args:
        website_url: Target website URL to test
        model: Model to use for red-team agent (defaults to config)
        task: Optional specific task/prompt for red-team agent
        open_browser: If True, open website in browser during red-team testing
        playwright: If True and open_browser is True, use Playwright for automation
        skip_audit: If True, skip running the auditor
        red_team_logs_dir: Optional directory containing red-team logs
        save_audit_report: If True, save the audit report to files
        include_hints: If True, include systematic testing hints in the red-team agent prompt
    
    Returns:
        Dictionary containing both red-team and auditor results
    """
    print("\n" + "=" * 70)
    print("🔴 RED-TEAM AGENT")
    print("=" * 70)
    
    # Step 1: Run red-team agent
    try:
        red_team_result = activate_agent(
            website_url=website_url,
            model=model,
            task=task,
            open_browser=open_browser,
            use_playwright=playwright,
            include_hints=include_hints
        )
    except Exception as e:
        print(f"\n❌ Red-team agent failed: {e}")
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "error": f"Red-team agent failed: {e}",
            "red_team_result": None,
            "auditor_result": None
        }
    
    # Extract run_id from result or report file
    run_id = red_team_result.get("run_id")
    if not run_id:
        # Fallback: try to extract from report file path
        report_file = red_team_result.get("report_file", "")
        run_id = get_run_id_from_report(report_file)
    
    if not run_id:
        print("\n⚠️  Warning: Could not extract run_id from report")
        print(f"   Report file: {red_team_result.get('report_file', 'N/A')}")
        return {
            "status": "partial",
            "red_team_result": red_team_result,
            "auditor_result": None,
            "run_id": None
        }
    
    print(f"\n✅ Red-team agent completed. Run ID: {run_id}")
    
    # Step 2: Run auditor if not skipped
    if skip_audit:
        print("\n⏭️  Skipping auditor (--skip-audit flag set)")
        return {
            "status": "success",
            "red_team_result": red_team_result,
            "auditor_result": None,
            "run_id": run_id
        }
    
    print("\n" + "=" * 70)
    print("🔍 AUDITOR AGENT")
    print("=" * 70)
    
    try:
        auditor = AuditorAgent(red_team_logs_dir=red_team_logs_dir)
        # Use non-interactive mode for automated runs
        auditor_result = auditor.audit(run_id, interactive=False)
        
        # Check for errors
        if auditor_result.get("status") == "error":
            print(f"\n❌ Auditor error: {auditor_result.get('error', 'Unknown error')}")
            return {
                "status": "partial",
                "red_team_result": red_team_result,
                "auditor_result": auditor_result,
                "run_id": run_id
            }
        
        # Generate and print audit report
        audit_report_text = auditor.generate_report(auditor_result)
        print("\n" + audit_report_text)
        
        # Save audit report if requested
        if save_audit_report:
            base_dir = Path(__file__).parent.parent
            auditor_logs_dir = base_dir / "auditor" / "logs"
            auditor_logs_dir.mkdir(exist_ok=True, parents=True)
            
            # Save markdown report
            report_file = auditor_logs_dir / f"audit_{run_id}.md"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(audit_report_text)
            
            # Save JSON
            import json
            json_file = auditor_logs_dir / f"audit_{run_id}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(auditor_result, f, indent=2, ensure_ascii=False)
            
            print(f"\n📄 Audit reports saved:")
            print(f"  - {report_file}")
            print(f"  - {json_file}")
        
        # Summary
        vulnerability_found = auditor_result.get("audit_result", {}).get("vulnerability_found", False)
        
        # Step 3: Run TTP Master Agent
        ttp_result = None
        if TTP_MASTER_AVAILABLE and analyze_ttp_report:
            print("\n" + "=" * 70)
            print("🎯 TTP MASTER AGENT")
            print("=" * 70)
            
            try:
                # Find the report directory
                if red_team_logs_dir:
                    report_dir = Path(red_team_logs_dir) / f"run_{run_id}"
                else:
                    report_dir = base_dir / "red-team-agent" / "logs" / f"run_{run_id}"
                
                if report_dir.exists():
                    ttp_result = analyze_ttp_report(
                        report_path=str(report_dir),
                        model=model,  # Use same model as red-team agent
                        verbose=True
                    )
                    
                    print(f"\n✅ TTP Master analysis completed")
                    if ttp_result:
                        ttp_count = len(ttp_result.get("structured_ttps", {}).get("techniques", []))
                        print(f"📊 Identified {ttp_count} MITRE ATT&CK TTPs")
                else:
                    print(f"\n⚠️  Warning: Report directory not found: {report_dir}")
            except Exception as e:
                print(f"\n⚠️  TTP Master Agent failed: {e}")
                import traceback
                traceback.print_exc()
        
        print("\n" + "=" * 70)
        print("📊 SUMMARY")
        print("=" * 70)
        print(f"✅ Red-team agent completed: Run ID {run_id}")
        print(f"{'✅' if vulnerability_found else '❌'} Auditor result: Vulnerability {'FOUND' if vulnerability_found else 'NOT FOUND'}")
        if ttp_result:
            ttp_count = len(ttp_result.get("structured_ttps", {}).get("techniques", []))
            print(f"✅ TTP Master: Identified {ttp_count} MITRE ATT&CK TTPs")
        elif TTP_MASTER_AVAILABLE:
            print("⚠️  TTP Master: Analysis not completed")
        print("=" * 70 + "\n")
        
        return {
            "status": "success",
            "red_team_result": red_team_result,
            "auditor_result": auditor_result,
            "ttp_result": ttp_result,
            "run_id": run_id,
            "vulnerability_found": vulnerability_found
        }
        
    except Exception as e:
        print(f"\n❌ Auditor failed: {e}")
        import traceback
        traceback.print_exc()
        return {
            "status": "partial",
            "red_team_result": red_team_result,
            "auditor_result": None,
            "run_id": run_id,
            "error": f"Auditor failed: {e}"
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Orchestrator: Run red-team agent and auditor sequentially",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python orchestrator.py --website http://localhost:3000/
  python orchestrator.py --website http://localhost:3000/ --model openai/gpt-4o
  python orchestrator.py --website http://localhost:3000/ --skip-audit
  python orchestrator.py --website http://localhost:3000/ --open-browser
        """
    )
    
    parser.add_argument(
        "--website",
        required=True,
        help="Website URL to test"
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model to use for red-team agent (e.g., 'openai/gpt-4o', 'openai/o3-mini'). Defaults to config default"
    )
    parser.add_argument(
        "--task",
        default=None,
        help="Optional specific task/prompt for red-team agent"
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Open website in browser during red-team testing"
    )
    parser.add_argument(
        "--playwright",
        action="store_true",
        help="Use Playwright for browser automation (requires --open-browser)"
    )
    parser.add_argument(
        "--skip-audit",
        action="store_true",
        help="Skip running the auditor after red-team agent"
    )
    parser.add_argument(
        "--red-team-logs-dir",
        help="Directory containing red-team agent logs (default: ../red-team-agent/logs)"
    )
    parser.add_argument(
        "--no-save-audit",
        action="store_true",
        help="Don't save the audit report to files"
    )
    parser.add_argument(
        "--hints",
        action="store_true",
        help="Include systematic testing hints in the red-team agent prompt"
    )
    
    args = parser.parse_args()
    
    try:
        result = run_orchestrator(
            website_url=args.website,
            model=args.model,
            task=args.task,
            open_browser=args.open_browser,
            playwright=args.playwright,
            skip_audit=args.skip_audit,
            red_team_logs_dir=args.red_team_logs_dir,
            save_audit_report=not args.no_save_audit,
            include_hints=args.hints
        )
        
        # Exit with appropriate code
        if result.get("status") == "error":
            sys.exit(1)
        elif result.get("status") == "partial":
            sys.exit(1)
        else:
            # Exit based on whether vulnerability was found
            vulnerability_found = result.get("vulnerability_found", False)
            sys.exit(0 if vulnerability_found else 1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

