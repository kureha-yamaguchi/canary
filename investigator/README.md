# Investigator Agent

The Investigator Agent analyzes failed red-team agent runs to identify root causes of why vulnerabilities were not discovered.

## Overview

The Investigator Agent:
- Analyzes the last N red-team agent reports
- Identifies which runs failed to find expected vulnerabilities
- Investigates root causes including:
  - Missing critical tools
  - Technical problems (errors, exceptions)
  - Incomplete testing coverage
  - Wrong testing approach
  - Tool failures
- Generates aggregated reports showing patterns across multiple runs

## Usage

### Basic Usage

Analyze the last 50 reports:
```bash
python investigator/run.py --num-reports 50
```

### Custom Number of Reports

Analyze the last 100 reports:
```bash
python investigator/run.py --num-reports 100
```

### Custom Log Directories

If your logs are in custom locations:
```bash
python investigator/run.py \
  --num-reports 50 \
  --red-team-logs-dir /path/to/red-team/logs \
  --auditor-logs-dir /path/to/auditor/logs
```

### Custom Output File

Specify a custom output file:
```bash
python investigator/run.py --num-reports 50 --output my_investigation.md
```

## Output

The investigator generates two files:

1. **Markdown Report** (`investigation_TIMESTAMP.md`):
   - Human-readable summary
   - Performance by vulnerability type
   - Performance by model
   - Common issues identified
   - Missing tools
   - Technical problems
   - Failed runs analysis

2. **JSON Report** (`investigation_TIMESTAMP.json`):
   - Complete structured data
   - All analyses for each run
   - Aggregated findings

## What It Analyzes

For each failed run, the investigator checks:

1. **Missing Tools**: Are critical tools for the vulnerability type being used?
   - SQL Injection: `test_sql_injection`, `discover_api_endpoints`
   - XSS: `test_xss`, `check_page_content`
   - API Keys: `check_information_disclosure`, `check_page_content`

2. **Technical Problems**: 
   - Errors or exceptions in reports
   - Tool failures
   - Incomplete executions

3. **Testing Coverage**:
   - Number of verification steps
   - Number of findings
   - Number of tool calls
   - Whether vulnerability-specific testing was performed

4. **Findings Mismatch**:
   - Did the agent find things but not match the expected vulnerability?
   - What findings were reported vs. what was expected?

## Example Output

```
🔍 INVESTIGATOR AGENT
======================================================================
Analyzing last 50 reports...

Found 50 reports to analyze

[1/50] Analyzing 20251123_150617... ❌ Failed
[2/50] Analyzing 20251123_150513... ❌ Failed
...

======================================================================
📊 INVESTIGATION SUMMARY
======================================================================
Total Reports: 50
Successful: 10
Failed: 40
Errors: 0
Success Rate: 20.0%

🔴 Top Issues:
  - XSS testing was not performed (15 reports)
  - Missing critical tools for XSS testing: test_xss (13 reports)
  ...

🔧 Missing Tools:
  - test_xss (15 reports)
  - check_page_content (2 reports)
  ...
```

## Integration

The investigator is designed to be activated manually when you want to analyze patterns in failures. It does not run automatically with the orchestrator.

## Files

- `investigator.py`: Main investigator agent class
- `run.py`: Command-line script to activate the investigator
- `__init__.py`: Package initialization

