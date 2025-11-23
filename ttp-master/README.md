# TTP Master Agent

The TTP Master Agent analyzes red-team-agent security assessment reports and maps findings to specific MITRE ATT&CK TTPs (Tactics, Techniques, and Procedures).

## Features

- **Automatic TTP Mapping**: Analyzes red-team-agent reports and identifies relevant MITRE ATT&CK techniques
- **Sub-technique Preference**: Prioritizes the most specific TTPs (e.g., T1552.001 over T1552)
- **Web Search Integration**: Uses web search to find and verify MITRE ATT&CK TTP IDs and descriptions
- **Structured Reports**: Generates detailed TTP analysis reports with mappings for each step and finding

## Installation

The TTP Master Agent uses the same configuration as the red-team-agent. Ensure you have:

1. Python 3.8+
2. Required dependencies (install from project root):
   ```bash
   pip install -r requirements.txt
   ```

3. Environment variables set (same as red-team-agent):
   - `OPENROUTER_API_KEY`: Your OpenRouter API key

## Usage

### Analyze Latest Red Team Report

```bash
python ttp-master/run.py --latest
```

### Analyze Specific Report

```bash
# By directory
python ttp-master/run.py --report ../red-team-agent/logs/run_20251122_204639

# By JSON file
python ttp-master/run.py --report ../red-team-agent/logs/run_20251122_204639/json
```

### Use Specific Model

```bash
python ttp-master/run.py --latest --model openai/o3-mini
```

## Output

The TTP Master Agent creates two files in the same directory as the source red-team-agent report:

1. **`ttp_analysis.json`**: Complete structured data with all TTP mappings
2. **`ttp_analysis_report`**: Human-readable markdown report with:
   - Summary of identified TTPs
   - TTP mappings by verification step
   - TTP mappings by security finding
   - All unique MITRE ATT&CK techniques identified

## Example Output

```
🎯 TTP Master Agent
📄 Report: ../red-team-agent/logs/run_20251122_204639
🤖 Model: openai/gpt-4o

🧠 TTP Analysis:
  💭 Analyzing verification steps and findings...
  🔧 web_search(SQL injection site:attack.mitre.org...)
  ✓ Found T1190: Exploit Public-Facing Application

📊 Summary:
  Total TTPs: 3
  Sub-techniques: 2

🎯 Identified MITRE ATT&CK Techniques:
  • T1190: Exploit Public-Facing Application
  • T1552.001: Unsecured Credentials: Credentials In Files
  • T1078: Valid Accounts
```

## TTP Mapping Process

1. **Load Report**: Reads the red-team-agent JSON report
2. **Extract Data**: Extracts verification steps, findings, and tool calls
3. **Search MITRE**: Uses web search to find relevant MITRE ATT&CK TTPs
4. **Map Activities**: Maps each step and finding to specific TTPs
5. **Generate Report**: Creates structured TTP analysis report

## Configuration

The agent uses the same configuration system as red-team-agent:

- `OPENROUTER_API_KEY`: Required for LLM access
- `DEFAULT_MODEL`: Default model to use (default: `openai/gpt-4o`)
- `AGENT_TEMPERATURE`: Temperature for TTP matching (default: `0.3` for precision)

## Integration

The TTP Master Agent is designed to work seamlessly with red-team-agent reports. It:

- Automatically finds reports in `red-team-agent/logs/`
- Saves analysis results in the same directory as the source report
- Preserves all metadata from the original report

## MITRE ATT&CK Framework

The agent maps findings to the MITRE ATT&CK Enterprise framework:
- **Techniques**: High-level attack techniques (e.g., T1190)
- **Sub-techniques**: More specific implementations (e.g., T1552.001)

The agent prioritizes sub-techniques when available for more precise mapping.

