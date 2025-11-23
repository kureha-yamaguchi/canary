"""Red Team Agent for security testing"""
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage
from typing import Optional
import sys
import os

# Handle both package and direct imports
try:
    from .config import config
    from .tools import get_tools
    from .prompts import get_default_task_prompt, SYSTEM_PROMPT, get_system_prompt
    from .logger import AgentLogger
except ImportError:
    # For direct script execution
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from config import config
    from tools import get_tools
    from prompts import get_default_task_prompt, SYSTEM_PROMPT, get_system_prompt
    from logger import AgentLogger


class RedTeamAgent:
    """Red Team Agent for security testing websites"""
    
    def __init__(self, model: Optional[str] = None, website_url: Optional[str] = None, logger: Optional[AgentLogger] = None, include_hints: bool = False):
        """
        Initialize the Red Team Agent
        
        Args:
            model: Model to use (e.g., 'openai/gpt-4o', 'anthropic/claude-3.5-sonnet')
            website_url: Target website URL to test
            logger: Optional AgentLogger instance for logging
            include_hints: If True, include systematic testing hints in the prompt
        """
        # Validate configuration
        config.validate()
        
        # Set instance variables
        self.model_name = model or config.DEFAULT_MODEL
        self.website_url = website_url
        self.logger = logger or AgentLogger()
        self.include_hints = include_hints
        
        # Initialize components
        self.llm = self._create_llm()
        self.agent = self._create_agent()
        
        # Set logger run info
        if website_url:
            self.logger.set_run_info(website_url, self.model_name, "")
    
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
        
        # Get system prompt with optional hints
        system_prompt = get_system_prompt(include_hints=self.include_hints)
        
        agent = create_agent(
            model=self.llm,
            tools=tools,
            system_prompt=system_prompt,
            debug=True
        )
        
        return agent
    
    def activate(self, task: Optional[str] = None, verbose: bool = True) -> dict:
        """
        Activate the agent to test the website
        
        Args:
            task: Optional specific task/prompt. If None, uses default security testing prompt.
            verbose: If True, print Chain of Thought during execution
        
        Returns:
            Agent execution result dictionary
        """
        if not self.website_url:
            raise ValueError(
                "Website URL not provided. "
                "Set it during initialization: RedTeamAgent(website_url='https://example.com')"
            )
        
        # Update logger with task (this also detects vulnerability)
        self.logger.set_run_info(self.website_url, self.model_name, task or "")
        
        # Get vulnerability info to customize prompt
        vulnerability = self.logger.log_data.get('vulnerability')
        vulnerability_id = vulnerability.get('vulnerability_id') if vulnerability else None
        
        # If custom task is provided, enhance it with website URL and tool usage instructions
        if task:
            task_prompt = f"""{task}

CRITICAL: You MUST use the available tools to test the website at {self.website_url}. Do not just describe what you would do - actually call the tools!

Start by using these tools:
1. scan_website(url="{self.website_url}") - to check basic information and headers
2. check_page_content(url="{self.website_url}") - to see the actual page and find forms/input fields
3. discover_api_endpoints(base_url="{self.website_url}") - to find API endpoints
4. check_information_disclosure(url="{self.website_url}") - to look for exposed sensitive data

Then use other tools as needed based on what you discover. You MUST actually call the tools, not just describe them!"""
        else:
            task_prompt = get_default_task_prompt(self.website_url, vulnerability_id)
        
        self.logger.log_message("human", task_prompt)
        
        if verbose:
            # Print run information
            print(f"🔍 Testing Website: {self.website_url}")
            vulnerability = self.logger.log_data.get('vulnerability')
            if vulnerability:
                vuln_name = vulnerability.get('vulnerability_name', 'Unknown')
                vuln_id = vulnerability.get('vulnerability_id', 'N/A')
                print(f"🎯 Expected Vulnerability: {vuln_name} (ID: {vuln_id})")
                if vulnerability.get('description'):
                    print(f"   Description: {vulnerability['description']}")
            else:
                print(f"⚠️  Vulnerability: Not detected from URL")
            print(f"🤖 Model: {self.model_name}")
            print(f"📝 Run ID: {self.logger.run_id}")
            print("\n🧠 Chain of Thought:\n")
        
        # Use invoke to get all messages at once
        result = self.agent.invoke({
            "messages": [HumanMessage(content=task_prompt)]
        })
        
        # Extract messages
        messages = result.get("messages", [])
        
        # Process messages and print CoT
        step_num = 0
        for i, msg in enumerate(messages):
            if isinstance(msg, AIMessage):
                content = msg.content or ""
                
                # Log message
                if content.strip():
                    self.logger.log_message("ai", content)
                
                # Print reasoning/CoT (all AI messages except the very last one are reasoning steps)
                is_final = (i == len(messages) - 1 or 
                           (i < len(messages) - 1 and 
                            not any(isinstance(messages[j], ToolMessage) for j in range(i+1, min(i+3, len(messages))))))
                
                if verbose and content.strip() and not is_final:
                    # Extract first meaningful sentence/line
                    lines = [l.strip() for l in content.split('\n') if l.strip()]
                    if lines:
                        reasoning = lines[0]
                        # Truncate if too long
                        if len(reasoning) > 250:
                            reasoning = reasoning[:247] + "..."
                        print(f"  💭 {reasoning}")
                
                # Print tool calls
                if hasattr(msg, 'tool_calls') and msg.tool_calls:
                    for tool_call in msg.tool_calls:
                        tool_name = tool_call.get('name', 'unknown')
                        if verbose:
                            step_num += 1
                            args = tool_call.get('args', {})
                            # Format args nicely
                            if args:
                                key_vals = list(args.items())[:1]  # Show first arg only
                                args_parts = [f"{k}='{str(v)[:40]}...'" if len(str(v)) > 40 else f"{k}='{v}'" 
                                            for k, v in key_vals]
                                args_str = ', '.join(args_parts)
                            else:
                                args_str = ""
                            print(f"  🔧 Step {step_num}: {tool_name}({args_str})")
                        self.logger.log_tool_call(tool_name, tool_call.get('args', {}), "pending")
            
            elif isinstance(msg, ToolMessage):
                tool_name = getattr(msg, 'name', 'unknown')
                tool_result = msg.content[:100] if msg.content else ""
                if verbose and tool_result:
                    result_preview = tool_result.replace('\n', ' ').strip()
                    if len(result_preview) > 100:
                        result_preview = result_preview[:97] + "..."
                    print(f"  ✓ {result_preview}")
                self.logger.log_tool_call(tool_name, {}, msg.content[:1000] if msg.content else "")
        
        # Get final output
        final_output = ""
        if messages:
            last_msg = messages[-1]
            if isinstance(last_msg, AIMessage):
                final_output = last_msg.content or str(messages[-1])
            else:
                final_output = str(messages[-1])
        
        if verbose:
            print()  # Blank line after CoT
        
        # Parse structured report
        self.logger.parse_and_extract_structured_report(final_output)
        
        # Save report to file
        report_file = self.logger.save_report()
        
        return {
            "output": final_output,
            "report_file": str(report_file),
            "structured": self.logger.log_data["structured_report"],
            "run_id": self.logger.run_id
        }


def activate_agent(
    website_url: str,
    model: Optional[str] = None,
    task: Optional[str] = None,
    open_browser: bool = False,
    use_playwright: bool = False,
    include_hints: bool = False
) -> dict:
    """
    Simple function to activate the red team agent
    
    Args:
        website_url: Target website URL
        model: Model to use (defaults to config)
        task: Optional specific task/prompt
        open_browser: If True, open website in browser
        use_playwright: If True and open_browser is True, use Playwright for automation
        include_hints: If True, include systematic testing hints in the prompt
    
    Returns:
        Agent execution result dictionary
    """
    # Create logger
    logger = AgentLogger()
    
    # Open browser if requested
    if open_browser:
        try:
            try:
                from .browser_automation import open_website_in_browser
            except ImportError:
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                from browser_automation import open_website_in_browser
            open_website_in_browser(website_url, use_playwright=use_playwright, headless=False)
        except Exception as e:
            print(f"⚠️  Could not open browser: {e}")
    
    # Create and activate agent
    agent = RedTeamAgent(model=model, website_url=website_url, logger=logger, include_hints=include_hints)
    return agent.activate(task=task)
