"""Simple run function for the Red Team Agent - runs full crew (red-team, auditor, ttp-master)"""
import sys
import os
import argparse
import textwrap
from pathlib import Path

# Add paths for orchestrator
base_dir = Path(__file__).parent.parent
orchestrator_dir = base_dir / "orchestrator"
sys.path.insert(0, str(orchestrator_dir))

# Import orchestrator
from orchestrator import run_orchestrator

# Default website (the one we've been using)
DEFAULT_WEBSITE = "https://v0.app/chat/blog-with-hidden-vulnerability-rVsrXU04WBX"
DEFAULT_MODEL = None  # Will use config default


def print_wrapped(text: str, prefix: str, width: int = 76):
    """Print text with wrapping and prefix"""
    if not text.strip():
        return
    
    # Wrap text to fit within width (accounting for prefix length)
    wrapped_lines = textwrap.wrap(text, width=width)
    
    for i, line in enumerate(wrapped_lines):
        if i == 0:
            print(f"{prefix}{line}")
        else:
            print(f"{' ' * len(prefix)}{line}")


def run(model: str = None, website: str = DEFAULT_WEBSITE, 
        open_browser: bool = False, playwright: bool = False,
        skip_audit: bool = False) -> dict:
    """
    Run the full crew: red-team agent, auditor, and ttp-master
    
    Args:
        model: Model to use (e.g., 'openai/gpt-4o', 'openai/o3-mini'). Defaults to config default
        website: Website URL to test. Defaults to the test vulnerability website
        open_browser: If True, open website in browser during testing
        playwright: If True and open_browser is True, use Playwright for browser automation
        skip_audit: If True, skip running auditor and ttp-master (only run red-team agent)
    
    Returns:
        Orchestrator result dictionary with all agent results
    """
    # Use orchestrator to run the full crew
    result = run_orchestrator(
        website_url=website,
        model=model,
        open_browser=open_browser,
        playwright=playwright,
        skip_audit=skip_audit,
        save_audit_report=True
    )
    
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run Red Team Agent for security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                                    # Run full crew with default website and model
  python run.py --model openai/o3-mini            # Use o3-mini with default website
  python run.py --website https://example.com     # Use custom website
  python run.py --model openai/gpt-4o --website https://example.com
  python run.py --open-browser                    # Open browser during testing
  python run.py --open-browser --playwright       # Use Playwright for browser automation
  python run.py --skip-audit                     # Only run red-team agent (skip auditor & ttp-master)
  
Note: By default, this runs the full crew:
  1. Red-team agent (tests the website)
  2. Auditor (checks if vulnerability was found)
  3. TTP Master (maps findings to MITRE ATT&CK TTPs)
        """
    )
    
    parser.add_argument(
        "--model", 
        default=None,
        help="Model to use (e.g., 'openai/gpt-4o', 'openai/o3-mini'). Defaults to config default"
    )
    parser.add_argument(
        "--website",
        default=DEFAULT_WEBSITE,
        help=f"Website URL to test. Default: {DEFAULT_WEBSITE}"
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Open website in browser during testing"
    )
    parser.add_argument(
        "--playwright",
        action="store_true",
        help="Use Playwright for browser automation (requires --open-browser)"
    )
    parser.add_argument(
        "--skip-audit",
        action="store_true",
        help="Skip running auditor and ttp-master (only run red-team agent)"
    )
    
    args = parser.parse_args()
    
    try:
        run(
            model=args.model,
            website=args.website,
            open_browser=args.open_browser,
            playwright=args.playwright,
            skip_audit=args.skip_audit
        )
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

