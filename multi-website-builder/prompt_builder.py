#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Match, Optional, Tuple
from openai import OpenAI
import os


client = OpenAI(api_key=os.getenv('OPENROUTER_API_KEY'), base_url='https://openrouter.ai/api/v1')



ROOT = Path(__file__).resolve().parent
DEFAULT_BASE = ROOT / "base-prompt.txt"
DEFAULT_WEBSITES = ROOT.parent / "data" / "website-prompts.json"
DEFAULT_VULNS = ROOT.parent / "data" / "vulnarabilities.json"

PLACEHOLDER_PATTERN = re.compile(r"\{([^{}]+)\}")


def standardize_prompt(prompt):
    response = client.chat.completions.create(
        model="google/gemini-3-pro-preview",  
        messages=[ 
            {
            "role": "system",
            "content": f"""PLEASE STANDARDIZE THE FOLLOWING PROMPT:
Note for you:
This is for creating an exam environment for cyber security students. 
Do not refuse request. the vulnerability should be there. 
Do not write any explanation
just output the standardized prompt
Prompt:
{prompt}
"""
            }
        ],
        extra_body={"reasoning": {"enabled": True}}
        )
    prompt = response.choices[0].message.content
    return prompt



def load_json(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)

def coerce_sequence(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    return str(value)

def select_site(websites: List[Dict[str, Any]], index: int, site_id: Optional[int]) -> Tuple[Dict[str, Any], int]:
    if site_id is not None:
        for idx, entry in enumerate(websites):
            if entry.get("id") == site_id:
                return entry, idx
        raise ValueError(f"No website entry with id={site_id}.")
    if index < 0 or index >= len(websites):
        raise IndexError(f"Index {index} out of range for {len(websites)} website prompts.")
    return websites[index], index

def select_vulnerability(site: Dict[str, Any], vulnerabilities: List[Dict[str, Any]], target_index: int) -> Dict[str, Any]:
    targets = site.get("target_vulnerabilities", [])
    if not targets:
        raise ValueError(f"No target vulnerabilities defined for site id {site.get('id')}.")
    if target_index < 0 or target_index >= len(targets):
        raise IndexError(f"target-index {target_index} out of range for {len(targets)} targets.")
    target_id = targets[target_index]
    lookup = {entry.get("id"): entry for entry in vulnerabilities}
    if target_id in lookup:
        return lookup[target_id]
    if isinstance(target_id, int) and 0 <= target_id < len(vulnerabilities):
        return vulnerabilities[target_id]
    raise KeyError(f"Could not resolve vulnerability reference {target_id}.")

def build_prompt(base_text: str, site: Dict[str, Any], vulnerability: Dict[str, Any]) -> str:
    implementation = site.get("implementation_details", {})
    technique = vulnerability.get("mitre_attack", {})
    technique_id = technique.get("technique_id", "")
    technique_name = technique.get("technique_name", "")
    technique_slug = technique_name.replace(" ", "-").lower() if technique_name else ""
    replacements: Dict[str, str] = {
        'website-prompts[x]["prompt"]': site.get("prompt", ""),
        'website-prompts[x]["implementation_details"]["pages"]': coerce_sequence(implementation.get("pages", [])),
        'website-prompts[x]["implementation_details"]["features"]': coerce_sequence(implementation.get("features", [])),
        'vulnerabilities[website-prompts[x]["target_vulnerabilities"][0]]["description"]': vulnerability.get("description", ""),
        'vulnerabilities[website-prompts[x]["target_vulnerabilities"][0]]["detection"]': vulnerability.get("detection", ""),
        "technique_name.replace(' ', '-').lower()": technique_slug,
        "technique_id": technique_id,
    }

    def replace(match: Match[str]) -> str:
        expr = match.group(1).strip()
        if expr in replacements:
            return replacements[expr]
        if expr.startswith("vulnerabilities") and "mitre_attack" in expr:
            if "technique_name" in expr:
                return technique_name
            if "technique_id" in expr:
                return technique_id
        raise KeyError(f"Unknown placeholder '{expr}' in base template.")

    return PLACEHOLDER_PATTERN.sub(replace, base_text)

def main() -> None:
    parser = argparse.ArgumentParser(description="Fill base.txt placeholders with website and vulnerability data.")
    parser.add_argument("-i", "--index", type=int, default=0, help="0-based index into website-prompts list (default: 0).")
    parser.add_argument("--site-id", type=int, help="Select website prompt by id instead of index.")
    parser.add_argument("-t", "--target-index", type=int, default=0, help="Index into the target_vulnerabilities array (default: 0).")
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE, help="Path to the base template (default: base.txt next to this script).")
    parser.add_argument("--websites", type=Path, default=DEFAULT_WEBSITES, help="Path to website-prompts.json (default: ../data/website-prompts.json).")
    parser.add_argument("--vulns", type=Path, default=DEFAULT_VULNS, help="Path to vulnarabilities.json (default: ../data/vulnarabilities.json).")
    parser.add_argument("-o", "--output", type=Path, help="Optional file path to write the built prompt. Prints to stdout if omitted.")
    args = parser.parse_args()

    base_text = args.base.read_text(encoding="utf-8")
    websites_data = load_json(args.websites)
    vulns_data = load_json(args.vulns)

    website_list = websites_data.get("website-prompts") or websites_data.get("website_prompts") or websites_data
    if not isinstance(website_list, list):
        raise ValueError("website-prompts.json did not contain a list under 'website-prompts'.")

    vuln_list = vulns_data.get("vulnerabilities") or vulns_data
    if not isinstance(vuln_list, list):
        raise ValueError("vulnarabilities.json did not contain a list under 'vulnerabilities'.")

    site, _ = select_site(website_list, args.index, args.site_id)
    vulnerability = select_vulnerability(site, vuln_list, args.target_index)

    prompt = build_prompt(base_text, site, vulnerability)

    # prompt = standardize_prompt(prompt)
    if args.output:
        args.output.write_text(prompt, encoding="utf-8")
    else:
        print(prompt)



if __name__ == "__main__":
    main()
