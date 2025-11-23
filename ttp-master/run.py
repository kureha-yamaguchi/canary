"""Simple run function for the TTP Master Agent"""
import sys
import os
import argparse
from pathlib import Path
from typing import Optional

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from agent import analyze_report


def find_latest_report(red_team_logs_dir: Optional[str] = None) -> Optional[Path]:
    """
    Find the latest red-team-agent report
    
    Args:
        red_team_logs_dir: Directory containing red-team-agent logs. 
                          Defaults to ../red-team-agent/logs
    
    Returns:
        Path to the latest report directory, or None if not found
    """
    if red_team_logs_dir is None:
        # Default to red-team-agent logs directory
        red_team_logs_dir = Path(__file__).parent.parent / "red-team-agent" / "logs"
    else:
        red_team_logs_dir = Path(red_team_logs_dir)
    
    if not red_team_logs_dir.exists():
        return None
    
    # Find all run directories
    run_dirs = [d for d in red_team_logs_dir.iterdir() if d.is_dir() and d.name.startswith("run_")]
    
    if not run_dirs:
        return None
    
    # Sort by name (which includes timestamp) and get the latest
    latest = sorted(run_dirs, key=lambda x: x.name, reverse=True)[0]
    
    # Check if it has a json file
    json_file = latest / "json"
    if json_file.exists():
        return latest
    
    return None


def run(report_path: str = None, model: str = None, latest: bool = False) -> dict:
    """
    Run the TTP Master Agent to analyze a red-team-agent report
    
    Args:
        report_path: Path to red-team-agent report (JSON file or directory). 
                    If None and latest=True, uses latest report.
        model: Model to use (e.g., 'openai/gpt-4o', 'openai/o3-mini'). Defaults to config default
        latest: If True and report_path is None, analyze the latest red-team-agent report
    
    Returns:
        Analysis result dictionary
    """
    # Determine report path
    if report_path is None:
        if latest:
            report_path = find_latest_report()
            if report_path is None:
                print("❌ No red-team-agent reports found")
                return None
            print(f"📂 Using latest report: {report_path}")
        else:
            print("❌ Please provide a report path or use --latest flag")
            return None
    
    report_path = Path(report_path)
    
    # Minimal header
    print(f"\n🎯 TTP Master Agent")
    print(f"📄 Report: {report_path}")
    print(f"🤖 Model: {model or 'default'}\n")
    
    result = analyze_report(
        report_path=str(report_path),
        model=model,
        verbose=True
    )
    
    # Clean results output
    print("\n" + "─" * 60)
    print("✅ TTP ANALYSIS RESULTS")
    print("─" * 60)
    
    structured = result.get("structured_ttps", {})
    techniques = structured.get("techniques", [])
    sub_techniques = structured.get("sub_techniques", [])
    
    # Print summary
    print(f"\n📊 Summary:")
    print(f"  Total TTPs: {len(techniques)}")
    print(f"  Sub-techniques: {len(sub_techniques)}")
    
    # Print all TTPs
    if techniques:
        print(f"\n🎯 Identified MITRE ATT&CK Techniques:")
        for tech in techniques:
            print(f"  • {tech['ttp_id']}: {tech['ttp_name']}")
    
    if sub_techniques:
        print(f"\n🎯 Most Specific TTPs (Sub-techniques):")
        for st in sub_techniques:
            print(f"  • {st['ttp_id']}: {st['ttp_name']}")
    
    print(f"\n📄 Full report: {result.get('report_file', 'Not saved')}")
    print("─" * 60 + "\n")
    
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run TTP Master Agent to analyze red-team reports and map to MITRE ATT&CK TTPs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py --latest                                    # Analyze latest red-team report
  python run.py --report ../red-team-agent/logs/run_20251122_204639
  python run.py --report ../red-team-agent/logs/run_20251122_204639/json
  python run.py --latest --model openai/o3-mini            # Use o3-mini with latest report
        """
    )
    
    parser.add_argument(
        "--report",
        default=None,
        help="Path to red-team-agent report (JSON file or directory containing 'json' file)"
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Analyze the latest red-team-agent report (ignores --report if set)"
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model to use (e.g., 'openai/gpt-4o', 'openai/o3-mini'). Defaults to config default"
    )
    
    args = parser.parse_args()
    
    try:
        run(
            report_path=args.report,
            model=args.model,
            latest=args.latest
        )
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

