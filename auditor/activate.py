"""Simple activation script for Auditor Agent"""
import sys
import os
import argparse
from pathlib import Path

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = Path(current_dir).parent
sys.path.insert(0, current_dir)
sys.path.insert(0, str(base_dir / "ttp-master"))

from auditor import audit_report, AuditorAgent

# Import TTP Master (handle import error gracefully)
TTP_MASTER_AVAILABLE = False
analyze_ttp_report = None
try:
    import importlib.util
    ttp_master_dir = base_dir / "ttp-master"
    ttp_agent_path = ttp_master_dir / "agent.py"
    if ttp_agent_path.exists():
        spec = importlib.util.spec_from_file_location("ttp_master_agent", ttp_agent_path)
        ttp_master_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ttp_master_module)
        analyze_ttp_report = ttp_master_module.analyze_report
        TTP_MASTER_AVAILABLE = True
except Exception:
    TTP_MASTER_AVAILABLE = False


def run(run_id: str = None, red_team_logs_dir: str = None, save_report: bool = True):
    """
    Run the auditor agent
    
    Args:
        run_id: The run ID to audit (e.g., "1763830815685")
        red_team_logs_dir: Optional directory containing red-team logs
        save_report: If True, save the audit report to a file
    """
    if not run_id:
        print("❌ Error: Run ID is required")
        print("\nUsage: python activate.py <run_id>")
        print("Example: python activate.py 1763830815685")
        sys.exit(1)
    
    print(f"\n🔍 Auditing Run ID: {run_id}")
    print("─" * 60)
    
    try:
        # Create auditor and audit (with interactive mode for user validation)
        auditor = AuditorAgent(red_team_logs_dir=red_team_logs_dir)
        audit_result = auditor.audit(run_id, interactive=True)
        
        # Check for errors
        if audit_result.get("status") == "error":
            print(f"\n❌ Error: {audit_result.get('error', 'Unknown error')}")
            sys.exit(1)
        
        # Generate and print report
        report_text = auditor.generate_report(audit_result)
        print("\n" + report_text)
        
        # Save report if requested
        if save_report:
            # Create auditor logs directory
            base_dir = Path(__file__).parent.parent
            auditor_logs_dir = base_dir / "auditor" / "logs"
            auditor_logs_dir.mkdir(exist_ok=True, parents=True)
            
            # Save report
            report_file = auditor_logs_dir / f"audit_{run_id}.md"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            
            # Save JSON
            import json
            json_file = auditor_logs_dir / f"audit_{run_id}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(audit_result, f, indent=2, ensure_ascii=False)
            
        print(f"\n📄 Reports saved:")
        print(f"  - {report_file}")
        print(f"  - {json_file}")
        
        # Step 3: Run TTP Master Agent
        if TTP_MASTER_AVAILABLE:
            print("\n" + "─" * 60)
            print("🎯 TTP MASTER AGENT")
            print("─" * 60)
            
            try:
                # Find the report directory
                if red_team_logs_dir:
                    report_dir = Path(red_team_logs_dir) / f"run_{run_id}"
                else:
                    report_dir = base_dir / "red-team-agent" / "logs" / f"run_{run_id}"
                
                if report_dir.exists():
                    ttp_result = analyze_ttp_report(
                        report_path=str(report_dir),
                        model=None,  # Use default model
                        verbose=True
                    )
                    
                    if ttp_result:
                        ttp_count = len(ttp_result.get("structured_ttps", {}).get("techniques", []))
                        print(f"\n✅ TTP Master: Identified {ttp_count} MITRE ATT&CK TTPs")
                else:
                    print(f"\n⚠️  Warning: Report directory not found: {report_dir}")
            except Exception as e:
                print(f"\n⚠️  TTP Master Agent failed: {e}")
                import traceback
                traceback.print_exc()
        
        print("\n" + "─" * 60 + "\n")
        
        # Exit with appropriate code
        vulnerability_found = audit_result.get("audit_result", {}).get("vulnerability_found", False)
        sys.exit(0 if vulnerability_found else 1)
        
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        print("\nMake sure the run_id exists in the red-team-agent logs.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Auditor Agent - Compare red-team findings to actual vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python activate.py 1763830815685                    # Audit a specific run
  python activate.py 1763830815685 --no-save          # Don't save report to file
        """
    )
    
    parser.add_argument(
        "run_id",
        nargs="?",
        help="Run ID to audit (e.g., '1763830815685')"
    )
    parser.add_argument(
        "--red-team-logs-dir",
        help="Directory containing red-team agent logs (default: ../red-team-agent/logs)"
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Don't save the audit report to a file"
    )
    
    args = parser.parse_args()
    
    try:
        run(
            run_id=args.run_id,
            red_team_logs_dir=args.red_team_logs_dir,
            save_report=not args.no_save
        )
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)

