#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="multi-website-builder:latest"
VULN_ID=""
SITE_ID=""

usage() {
  cat <<'EOF'
Usage: ./start.sh --vuln-id VULN_ID --site-id SITE_ID

Generates a prompt via prompt_builder.py, stores it in websites/website-{VULN_ID}-{VULN_NAME}-{SITE_ID}/prompt.txt
along with .env.local, builds the Docker image, and runs the container with the
site folder mounted to /site so changes persist.

Options:
      --vuln-id        Vulnerability ID (required)
      --site-id        Website prompt id (required)
      --list           List available website prompts for the vulnerability and exit
  -h, --help           Show this help message
EOF
}

LIST_ONLY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vuln-id)
      VULN_ID="$2"
      shift 2
      ;;
    --site-id)
      SITE_ID="$2"
      shift 2
      ;;
    --list)
      LIST_ONLY=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$VULN_ID" ]]; then
  echo "Error: --vuln-id is required." >&2
  usage
  exit 1
fi

if [[ "$LIST_ONLY" == true ]]; then
  echo "Listing available website prompts for vulnerability ${VULN_ID}..."
  python3 "${ROOT}/prompt_builder.py" --vuln-id "$VULN_ID" --list-websites
  exit 0
fi

if [[ -z "$SITE_ID" ]]; then
  echo "Error: --site-id is required." >&2
  usage
  exit 1
fi

# Get vulnerability name to create folder name
VULN_NAME=$(python3 -c "
import json
import sys
from pathlib import Path

vulns_path = Path('${ROOT}') / '..' / 'data' / 'vulnarabilities.json'
with open(vulns_path, 'r') as f:
    data = json.load(f)
    
vulns = data.get('vulnerabilities', [])
for vuln in vulns:
    if vuln.get('id') == ${VULN_ID}:
        name = vuln.get('name', 'unknown')
        # Create slug from name
        slug = name.lower().replace(' ', '-').replace('(', '').replace(')', '').replace('--', '-')
        # Remove special characters
        slug = ''.join(c if c.isalnum() or c == '-' else '' for c in slug)
        print(slug)
        sys.exit(0)
print('unknown')
")

SITES_ROOT="${ROOT}/websites"
SITE_DIR="${SITES_ROOT}/website-${VULN_ID}-${VULN_NAME}-${SITE_ID}"
PROMPT_PATH="${SITE_DIR}/prompt.txt"

for file in "${ROOT}/.env" "${ROOT}/.env.local"; do
  if [[ ! -f "$file" ]]; then
    echo "Missing required file: $file" >&2
    exit 1
  fi
done

set -a
source "${ROOT}/.env"
set +a

for var in OPENROUTER_API_KEY ANTHROPIC_API_KEY ANTHROPIC_BASE_URL ANTHROPIC_MODEL; do
  if [[ -z "${!var:-}" ]]; then
    echo "Environment variable $var is not set. Check ${ROOT}/.env." >&2
    exit 1
  fi
done

mkdir -p "$SITE_DIR"

PROMPT_ARGS=(--vuln-id "$VULN_ID" --site-id "$SITE_ID" "-o" "$PROMPT_PATH")

echo "Generating prompt to ${PROMPT_PATH}..."
echo "Vulnerability ID: ${VULN_ID}, Website Prompt ID: ${SITE_ID}"
python3 "${ROOT}/prompt_builder.py" "${PROMPT_ARGS[@]}"

echo "Copying ${ROOT}/.env.local into ${SITE_DIR}..."
cp "${ROOT}/.env.local" "${SITE_DIR}/.env.local"

echo "Building Docker image ${IMAGE_NAME}..."
docker build -t "$IMAGE_NAME" "$ROOT"

echo "Running container with site mounted at /site..."
docker run --rm -i \
  -v "${SITE_DIR}:/site" \
  -p 3012:3000 \
  -e ANTHROPIC_API_KEY \
  -e ANTHROPIC_BASE_URL \
  -e ANTHROPIC_MODEL \
  "$IMAGE_NAME"
