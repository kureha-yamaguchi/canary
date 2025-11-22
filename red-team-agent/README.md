# Red Team Agent

A simple, modular LangChain-based red team agent for security testing websites.

## Structure

The agent is organized into clear, readable modules:

- **`config.py`** - Configuration management with .env loading from multiple locations
- **`tools.py`** - Security testing tools (website scanner, endpoint checker, etc.)
- **`prompts.py`** - Agent prompts and task templates
- **`agent.py`** - Main RedTeamAgent class and activation function
- **`activate.py`** - Command-line interface

## Setup

1. Install dependencies:
```bash
pip install -r ../requirements.txt
```

2. Set up environment variables:

The agent automatically loads `.env` files from multiple locations:
- Project root (`/canary/.env`)
- Red team agent directory (`/canary/red-team-agent/.env`)
- Current working directory

Values are merged, with later files taking precedence. Create a `.env` file in either location:

```bash
# .env file example
OPENROUTER_API_KEY=your_openrouter_api_key_here
DEFAULT_MODEL=openai/gpt-4o
AGENT_TEMPERATURE=0.7
REQUEST_TIMEOUT=10
```

## Usage

### Python API

```python
from red_team_agent import activate_agent, RedTeamAgent

# Simple activation function
result = activate_agent(
    website_url="https://example.com",
    model="openai/gpt-4o"
)

# Using the class directly
agent = RedTeamAgent(
    website_url="https://example.com",
    model="anthropic/claude-3.5-sonnet"
)

# With custom task
result = agent.activate(
    task="Test for SQL injection vulnerabilities specifically"
)
```

### Command Line

**Easy Run (Recommended):**
```bash
cd red-team-agent

# Use default website and model
python run.py

# Use custom model with default website
python run.py --model openai/o3-mini

# Use custom website
python run.py --website https://example.com

# Use custom model and website
python run.py --model openai/gpt-4o --website https://example.com

# With browser visualization
python run.py --open-browser

# With Playwright automation
python run.py --open-browser --playwright
```

**Or use the activate script:**
```bash
python activate.py https://example.com openai/gpt-4o

# With browser visualization (optional)
python activate.py https://example.com openai/gpt-4o --open-browser

# With Playwright automation (requires --open-browser)
python activate.py https://example.com openai/gpt-4o --open-browser --playwright
```

## Configuration

Environment variables (loaded from `.env` files):

- `OPENROUTER_API_KEY` (required) - Your OpenRouter API key
- `DEFAULT_MODEL` (optional) - Default model to use (default: `openai/gpt-4o`)
- `AGENT_TEMPERATURE` (optional) - LLM temperature (default: `0.7`)
- `REQUEST_TIMEOUT` (optional) - HTTP request timeout in seconds (default: `10`)

## Available Models (OpenRouter)

- `openai/gpt-4o`
- `openai/gpt-4-turbo`
- `anthropic/claude-3.5-sonnet`
- `google/gemini-pro`
- And many more via [OpenRouter](https://openrouter.ai/models)

## Features

- **Modular Structure** - Clean separation of concerns for easy maintenance
- **Multiple .env Support** - Automatically loads and merges .env files
- **Extensible Tools** - Easy to add new security testing tools
- **Customizable Prompts** - Modify prompts in `prompts.py`
- **Type Hints** - Full type annotations for better IDE support
- **Comprehensive Logging** - Each run creates detailed logs with Chain of Thought (CoT) reasoning
- **Structured Reports** - Automatically extracts Verification Steps, Findings, and Recommendations
- **Browser Visualization** - Optional browser automation to visualize the testing process
- **Playwright Browser Toolkit** - Full browser automation with navigate, click, fill, extract, screenshot
- **Browser-use Integration** - Advanced browser interaction capabilities

## Logging and Reports

Each agent run automatically creates a per-run folder (`logs/run_<numeric_id>/`) containing:

- **`json`** - Complete execution log with all messages, tool calls, and reasoning
- **`report`** - Human-readable report with:
  - Verification Steps performed
  - Findings discovered
  - Recommendations for fixes
  - Full security assessment
  - Chain of Thought reasoning
  - **Prompt Version** - Git commit hash and prompt content hash for tracking prompt changes

The report includes prompt versioning information (git commit hash and prompt file hash) to track which version of the prompts was used for each run.

Reports are saved in the `logs/` directory within the `red-team-agent` folder.
