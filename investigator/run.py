#!/usr/bin/env python3
"""Script to activate the Investigator Agent"""
import argparse
import sys
from pathlib import Path

# Add paths for imports
base_dir = Path(__file__).parent.parent
investigator_dir = base_dir / "investigator"
sys.path.insert(0, str(investigator_dir))

from investigator import InvestigatorAgent


def main():
    parser = argparse.ArgumentParser(
        description="Investigator Agent - Analyzes failed red-team agent runs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python investigator/run.py --num-reports 50
  python investigator/run.py --num-reports 100 --red-team-logs-dir custom/path
        """
    )
    
    parser.add_argument(
        "--num-reports",
        type=int,
        default=50,
        help="Number of recent reports to analyze (default: 50)"
    )
    
    parser.add_argument(
        "--red-team-logs-dir",
        default=None,
        help="Directory containing red-team agent logs (default: ../red-team-agent/logs)"
    )
    
    parser.add_argument(
        "--auditor-logs-dir",
        default=None,
        help="Directory containing auditor logs (default: ../auditor/logs)"
    )
    
    parser.add_argument(
        "--output",
        default=None,
        help="Output file path for the investigation report (default: investigator/logs/investigation_TIMESTAMP.md)"
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize investigator
        investigator = InvestigatorAgent(
            red_team_logs_dir=args.red_team_logs_dir,
            auditor_logs_dir=args.auditor_logs_dir
        )
        
        # Run investigation
        result = investigator.investigate(num_reports=args.num_reports)
        
        # Save report
        output_file = Path(args.output) if args.output else None
        report_file = investigator.save_report(result, output_file)
        
        # Print summary
        print("\n" + "=" * 70)
        print("📊 INVESTIGATION SUMMARY")
        print("=" * 70)
        print(f"Total Reports: {result['total_reports']}")
        print(f"Successful: {result['successful']}")
        print(f"Failed: {result['failed']}")
        print(f"Errors: {result['errors']}")
        print(f"Success Rate: {result['success_rate']:.1f}%")
        print("\n" + "=" * 70)
        
        # Print aggregated findings
        aggregated = result.get("aggregated_findings", {})
        
        # Top issues
        common_issues = aggregated.get("common_issues", {})
        if common_issues:
            print("\n🔴 Top Issues:")
            for issue, count in sorted(common_issues.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  - {issue} ({count} reports)")
        
        # Missing tools
        missing_tools = aggregated.get("missing_tools", {})
        if missing_tools:
            print("\n🔧 Missing Tools:")
            for tool, count in sorted(missing_tools.items(), key=lambda x: x[1], reverse=True):
                print(f"  - {tool} ({count} reports)")
        
        print(f"\n📄 Full report saved to: {report_file}")
        print("=" * 70 + "\n")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Investigation interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

