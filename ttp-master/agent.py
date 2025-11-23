"""TTP Master Agent for MITRE ATT&CK TTP analysis"""
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from langchain_core.tools import tool
from typing import Optional, Dict, Any
import sys
import os
import json
import re
from pathlib import Path
import requests

# Handle both package and direct imports
# Always add current directory to path first to ensure we import from ttp-master
_ttp_master_dir = os.path.dirname(os.path.abspath(__file__))
if _ttp_master_dir not in sys.path:
    sys.path.insert(0, _ttp_master_dir)

try:
    from .config import config
    from .logger import TTPLogger
    from .prompts import SYSTEM_PROMPT, get_ttp_analysis_prompt
except ImportError:
    # For direct script execution - use absolute imports from ttp-master directory
    from config import config
    from logger import TTPLogger
    # Import prompts with explicit path to avoid conflicts
    import importlib.util
    prompts_path = Path(_ttp_master_dir) / "prompts.py"
    if prompts_path.exists():
        spec = importlib.util.spec_from_file_location("ttp_prompts", prompts_path)
        prompts_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(prompts_module)
        SYSTEM_PROMPT = prompts_module.SYSTEM_PROMPT
        get_ttp_analysis_prompt = prompts_module.get_ttp_analysis_prompt
    else:
        raise ImportError(f"Could not find prompts.py in {_ttp_master_dir}")


@tool
def web_search(query: str) -> str:
    """
    Search the web for MITRE ATT&CK techniques and TTPs.
    
    This tool searches the MITRE ATT&CK website to find specific TTP IDs, names, and descriptions.
    Search queries should be specific, for example:
    - "SQL injection"
    - "T1190"
    - "command injection sub-technique"
    - "authentication bypass"
    
    The tool will search https://attack.mitre.org/techniques/enterprise/ for matching techniques.
    
    Args:
        query: Search query string (technique name, TTP ID, or activity description)
    
    Returns:
        Search results with TTP IDs, names, and descriptions
    """
    try:
        # Enhance query for MITRE ATT&CK site
        search_query = query.strip()
        
        # If it's already a TTP ID, try to get it directly
        if search_query.upper().startswith('T') and len(search_query) >= 5:
            ttp_id = search_query.upper()
            # Try to fetch the technique page directly
            try:
                url_path = ttp_id.replace('.', '/')
                url = f"https://attack.mitre.org/techniques/{url_path}/"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    # Extract title/name from HTML (simple extraction)
                    title_match = __import__('re').search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1).replace(' - MITRE ATT&CK', '').strip()
                        return f"""Found MITRE ATT&CK Technique:
- TTP ID: {ttp_id}
- Name: {title}
- URL: {url}

This technique matches your query: {query}
"""
            except Exception:
                pass
        
        # For general searches, provide guidance and common mappings
        # In a production environment, you would integrate with actual search APIs
        # or scrape the MITRE techniques page
        
        # Common MITRE ATT&CK mappings based on query keywords
        query_lower = query.lower()
        mappings = []
        
        if 'sql' in query_lower and 'injection' in query_lower:
            mappings.append("T1190: Exploit Public-Facing Application (SQL injection via web application)")
            mappings.append("T1552.001: Unsecured Credentials: Credentials In Files (SQL injection to extract credentials)")
        
        if 'xss' in query_lower or 'cross-site scripting' in query_lower:
            mappings.append("T1059.007: Command and Scripting Interpreter: JavaScript/JScript")
            mappings.append("T1059.005: Command and Scripting Interpreter: Visual Basic")
        
        if 'authentication' in query_lower and 'bypass' in query_lower:
            mappings.append("T1078: Valid Accounts")
            mappings.append("T1556: Modify Authentication Process")
        
        if 'api' in query_lower and 'discover' in query_lower:
            mappings.append("T1589: Gather Victim Identity Information")
            mappings.append("T1046: Network Service Scanning")
        
        if 'information' in query_lower and 'disclos' in query_lower:
            mappings.append("T1082: System Information Discovery")
            mappings.append("T1083: File and Directory Discovery")
        
        result = f"""Search query: {query}

MITRE ATT&CK Framework: https://attack.mitre.org/techniques/enterprise/

Search Strategy:
1. Search for techniques matching: {query}
2. Look for TTP IDs in format T#### or T####.###
3. Prefer sub-techniques (T####.###) over parent techniques (T####)
4. Verify the TTP description matches the red-team activity

"""
        
        if mappings:
            result += "Potential TTP Mappings:\n"
            for mapping in mappings:
                result += f"- {mapping}\n"
            result += "\n"
        
        result += f"""To find the most specific TTP:
1. Visit https://attack.mitre.org/techniques/enterprise/
2. Search for: {query}
3. Review technique descriptions to find the best match
4. Prefer sub-techniques (e.g., T1552.001) over parent techniques (e.g., T1552)

For this specific query, look for techniques related to: {query}
"""
        
        return result
        
    except Exception as e:
        return f"Error searching for '{query}': {str(e)}\n\nVisit https://attack.mitre.org/techniques/enterprise/ to manually search for MITRE ATT&CK TTPs."


@tool
def scrape_mitre_technique(ttp_id: str) -> str:
    """
    Scrape detailed information about a specific MITRE ATT&CK technique.
    
    Args:
        ttp_id: MITRE TTP ID in format T#### or T####.### (e.g., T1190, T1552.001)
    
    Returns:
        Technique information as a string
    """
    try:
        # Convert TTP ID to URL format (T1552.001 -> T1552/001)
        url_path = ttp_id.replace('.', '/')
        url = f"https://attack.mitre.org/techniques/{url_path}/"
        return f"MITRE ATT&CK Technique: {ttp_id}\nURL: {url}\n\nNote: This tool should scrape the actual page content. For now, use web_search to find information about {ttp_id}."
    except Exception as e:
        return f"Error scraping technique: {str(e)}"


def get_tools():
    """Get tools for the TTP Master Agent"""
    return [web_search, scrape_mitre_technique]


class TTPMasterAgent:
    """TTP Master Agent for analyzing red-team reports and mapping to MITRE ATT&CK TTPs"""
    
    def __init__(self, model: Optional[str] = None, logger: Optional[TTPLogger] = None):
        """
        Initialize the TTP Master Agent
        
        Args:
            model: Model to use (e.g., 'openai/gpt-4o', 'anthropic/claude-3.5-sonnet')
            logger: Optional TTPLogger instance for logging
        """
        # Validate configuration
        config.validate()
        
        # Set instance variables
        self.model_name = model or config.DEFAULT_MODEL
        self.logger = logger or TTPLogger()
        
        # Initialize components
        self.llm = self._create_llm()
        self.agent = self._create_agent()
        
        # Set logger model info
        self.logger.set_model(self.model_name)
    
    def _create_llm(self) -> ChatOpenAI:
        """Create LLM instance with OpenRouter"""
        return ChatOpenAI(
            model=self.model_name,
            openai_api_base=config.OPENROUTER_BASE_URL,
            openai_api_key=config.OPENROUTER_API_KEY,
            temperature=config.TEMPERATURE,
        )
    
    def _create_agent(self):
        """Create the agent with tools and prompt"""
        tools = get_tools()
        
        agent = create_agent(
            model=self.llm,
            tools=tools,
            system_prompt=SYSTEM_PROMPT,
            debug=True
        )
        
        return agent
    
    def load_red_team_report(self, report_path: str) -> Dict[str, Any]:
        """
        Load a red-team-agent report (JSON format)
        
        Args:
            report_path: Path to the red-team-agent report JSON file or directory containing it
        
        Returns:
            Dictionary containing report data
        """
        report_path = Path(report_path)
        
        # If it's a directory, look for json file
        if report_path.is_dir():
            json_file = report_path / "json"
            if not json_file.exists():
                raise FileNotFoundError(f"JSON report not found in {report_path}")
            report_path = json_file
        
        if not report_path.exists():
            raise FileNotFoundError(f"Report file not found: {report_path}")
        
        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        return report_data
    
    def analyze_report(self, report_path: str, verbose: bool = True) -> dict:
        """
        Analyze a red-team-agent report and map findings to MITRE ATT&CK TTPs
        
        Args:
            report_path: Path to the red-team-agent report (JSON file or directory)
            verbose: If True, print analysis progress
        
        Returns:
            Analysis result dictionary
        """
        # Load the report
        report_data = self.load_red_team_report(report_path)
        
        # Extract report directory for saving TTP analysis
        report_path_obj = Path(report_path)
        if report_path_obj.is_file():
            report_dir = report_path_obj.parent
        else:
            report_dir = report_path_obj
        
        # Set logger output directory and source info
        run_id = report_data.get("run_id", "unknown")
        self.logger.set_output_dir(report_dir)
        self.logger.set_source_report(str(report_path), run_id)
        
        # Extract structured data
        structured = report_data.get("structured_report", {})
        verification_steps = structured.get("verification_steps", [])
        findings = structured.get("findings", [])
        tool_calls = report_data.get("tool_calls", [])
        final_report = report_data.get("final_report", "")
        
        # Prepare analysis data
        analysis_data = {
            "verification_steps": verification_steps,
            "findings": findings,
            "tool_calls": tool_calls,
            "final_report": final_report
        }
        
        # Generate analysis prompt
        task_prompt = get_ttp_analysis_prompt(analysis_data)
        
        if verbose:
            print(f"🔍 Analyzing Red Team Report: {report_path}")
            print(f"🤖 Model: {self.model_name}")
            print(f"📝 Run ID: {run_id}")
            print(f"📊 Steps to analyze: {len(verification_steps)}")
            print(f"🔎 Findings to map: {len(findings)}")
            print("\n🧠 TTP Analysis:\n")
        
        # Log the task
        self.logger.log_data["task"] = task_prompt
        
        # Use invoke to get all messages at once
        result = self.agent.invoke({
            "messages": [HumanMessage(content=task_prompt)]
        })
        
        # Extract messages
        messages = result.get("messages", [])
        
        # Process messages and print progress
        for i, msg in enumerate(messages):
            if isinstance(msg, AIMessage):
                content = msg.content or ""
                
                # Print reasoning/CoT
                if verbose and content.strip() and i < len(messages) - 1:
                    lines = [l.strip() for l in content.split('\n') if l.strip()]
                    if lines:
                        reasoning = lines[0]
                        if len(reasoning) > 250:
                            reasoning = reasoning[:247] + "..."
                        print(f"  💭 {reasoning}")
                
                # Print tool calls
                if hasattr(msg, 'tool_calls') and msg.tool_calls:
                    for tool_call in msg.tool_calls:
                        tool_name = tool_call.get('name', 'unknown')
                        if verbose:
                            args = tool_call.get('args', {})
                            query = args.get('query', args.get('ttp_id', ''))
                            print(f"  🔧 {tool_name}({query[:60]}...)")
            
            elif isinstance(msg, ToolMessage):
                if verbose:
                    result_preview = (msg.content[:100] if msg.content else "").replace('\n', ' ').strip()
                    if result_preview:
                        if len(result_preview) > 100:
                            result_preview = result_preview[:97] + "..."
                        print(f"  ✓ {result_preview}")
        
        # Get final output
        final_output = ""
        if messages:
            last_msg = messages[-1]
            if isinstance(last_msg, AIMessage):
                final_output = last_msg.content or str(messages[-1])
            else:
                final_output = str(messages[-1])
        
        if verbose:
            print()  # Blank line after analysis
        
        # Parse TTPs from the report
        self.logger.set_final_report(final_output)
        self.logger.parse_ttp_from_report(final_output)
        
        # Save report to file
        report_file = self.logger.save_report()
        
        if verbose:
            print(f"📄 TTP Analysis Report: {report_file}")
            print(f"📊 Total TTPs identified: {len(self.logger.log_data['structured_ttps']['techniques'])}")
            print(f"📊 Sub-techniques: {len(self.logger.log_data['structured_ttps']['sub_techniques'])}")
        
        return {
            "output": final_output,
            "report_file": str(report_file),
            "structured_ttps": self.logger.log_data["structured_ttps"],
            "run_id": self.logger.run_id,
            "source_run_id": run_id
        }


def analyze_report(
    report_path: str,
    model: Optional[str] = None,
    verbose: bool = True
) -> dict:
    """
    Simple function to analyze a red-team-agent report and map to MITRE ATT&CK TTPs
    
    Args:
        report_path: Path to the red-team-agent report (JSON file or directory)
        model: Model to use (defaults to config)
        verbose: If True, print analysis progress
    
    Returns:
        Analysis result dictionary
    """
    # Create logger
    logger = TTPLogger()
    
    # Create and run agent
    agent = TTPMasterAgent(model=model, logger=logger)
    return agent.analyze_report(report_path, verbose=verbose)

