# Hints System

The hints system allows you to optionally provide additional testing guidance to the red team agent.

## Files

- **`hints.py`**: Contains all systematic testing hints and strategies
- **`prompts.py`**: Updated to optionally include hints via `get_base_prompt(include_hints=True)`

## Usage

### Including Hints in Prompts

By default, hints are **not** included. To include hints:

```python
from red_team_agent.prompts import get_base_prompt

# Include all hints
prompt_template = get_base_prompt(include_hints=True)

# Include hints for a specific vulnerability type
prompt_template = get_base_prompt(include_hints=True, vulnerability_type="idor")
```

### Available Vulnerability Types

- `"idor"` - Insecure Direct Object Reference
- `"jwt"` - JWT algorithm confusion
- `"verbose-errors"` - Verbose error messages
- `"client-side-exposure"` - Client-side data exposure

### Getting Hints Programmatically

```python
from red_team_agent.hints import get_hints, get_hints_for_vulnerability_type

# Get all hints
all_hints = get_hints()

# Get hints for specific vulnerability type
idor_hints = get_hints_for_vulnerability_type("idor")
```

## Current Status

The agent currently uses `SYSTEM_PROMPT` directly without hints. To enable hints:

1. Modify `agent.py` to use `get_base_prompt(include_hints=True)` instead of `SYSTEM_PROMPT`
2. Or update the orchestrator to pass hints flag when creating the agent

## What Hints Cover

The hints provide guidance on:
- Resource enumeration (IDOR testing)
- Error response analysis
- Token discovery and analysis
- JavaScript code analysis
- API discovery
- JWT testing strategies
- Verbose error detection
- Client-side exposure testing

These are general strategies that help the agent discover vulnerabilities using the available tools, rather than specific vulnerability testers.

