"""Simple run function for the Red Team Agent"""
import sys
import os
import argparse
import textwrap

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from agent import activate_agent

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
        open_browser: bool = False, playwright: bool = False) -> dict:
    """
    Simple function to run the red team agent
    
    Args:
        model: Model to use (e.g., 'openai/gpt-4o', 'openai/o3-mini'). Defaults to config default
        website: Website URL to test. Defaults to the test vulnerability website
        open_browser: If True, open website in browser during testing
        playwright: If True and open_browser is True, use Playwright for browser automation
    
    Returns:
        Agent execution result dictionary
    """
    # Minimal header
    print(f"\n🔴 Testing: {website}")
    print(f"🤖 Model: {model or 'default'}\n")
    
    result = activate_agent(
        website_url=website,
        model=model,
        open_browser=open_browser,
        use_playwright=playwright
    )
    
    # Clean results output
    print("\n" + "─" * 60)
    print("✅ RESULTS")
    print("─" * 60)
    
    structured = result.get("structured", {})
    verification_steps = structured.get("verification_steps", [])
    findings = structured.get("findings", [])
    recommendations = structured.get("recommendations", [])
    
    # Print all Verification Steps
    if verification_steps:
        print(f"\n📋 Verification Steps ({len(verification_steps)}):")
        for i, step in enumerate(verification_steps, 1):
            step_text = step.strip()
            if step_text:
                print_wrapped(step_text, f"  {i}. ", width=76)
    else:
        print("\n📋 Verification Steps: None extracted")
    
    # Print all Findings
    if findings:
        print(f"\n🔍 Findings ({len(findings)}):")
        for i, finding in enumerate(findings, 1):
            finding_text = finding.strip()
            if finding_text:
                print_wrapped(finding_text, f"  {i}. ", width=76)
    else:
        print("\n🔍 Findings: None detected")
    
    # Print all Recommendations
    if recommendations:
        print(f"\n💡 Recommendations ({len(recommendations)}):")
        for i, rec in enumerate(recommendations, 1):
            rec_text = rec.strip()
            if rec_text:
                print_wrapped(rec_text, f"  {i}. ", width=76)
    
    print(f"\n📄 Full report: {result.get('report_file', 'Not saved')}")
    print("─" * 60 + "\n")
    
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run Red Team Agent for security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                                    # Use default website and model
  python run.py --model openai/o3-mini            # Use o3-mini with default website
  python run.py --website https://example.com     # Use custom website
  python run.py --model openai/gpt-4o --website https://example.com
  python run.py --open-browser                    # Open browser during testing
  python run.py --open-browser --playwright       # Use Playwright for browser automation
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
    
    args = parser.parse_args()
    
    try:
        run(
            model=args.model,
            website=args.website,
            open_browser=args.open_browser,
            playwright=args.playwright
        )
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

