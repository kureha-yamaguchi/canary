#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="multi-website-builder:latest"
TARGET_INDEX=0
SITE_ID=""

usage() {
  cat <<'EOF'
Usage: ./start.sh --site-id ID [-t TARGET_INDEX]

Generates a prompt via prompt_builder.py, stores it in websites/website-{ID}/prompt.txt
along with .env.local, builds the Docker image, and runs the container with the
site folder mounted to /site so changes persist.

Options:
  -t, --target-index   Target vulnerability index (default: 0)
      --site-id        Website prompt id (required)
  -h, --help           Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target-index)
      TARGET_INDEX="$2"
      shift 2
      ;;
    --site-id)
      SITE_ID="$2"
      shift 2
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

if [[ -z "$SITE_ID" ]]; then
  echo "Error: --site-id is required." >&2
  usage
  exit 1
fi

SITE_LABEL="$SITE_ID"
SITES_ROOT="${ROOT}/websites"
SITE_DIR="${SITES_ROOT}/website-${SITE_LABEL}"
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

PROMPT_ARGS=(--site-id "$SITE_ID" "-t" "$TARGET_INDEX" "-o" "$PROMPT_PATH")

echo "Generating prompt to ${PROMPT_PATH}..."
python3 "${ROOT}/prompt_builder.py" "${PROMPT_ARGS[@]}"

echo "Copying ${ROOT}/.env.local into ${SITE_DIR}..."
cp "${ROOT}/.env.local" "${SITE_DIR}/.env.local"

echo "Building Docker image ${IMAGE_NAME}..."
docker build -t "$IMAGE_NAME" "$ROOT"

echo "Running container with site mounted at /site..."
docker run --rm -it \
  -v "${SITE_DIR}:/site" \
  -p 3000:3000 \
  -e ANTHROPIC_API_KEY \
  -e ANTHROPIC_BASE_URL \
  -e ANTHROPIC_MODEL \
  "$IMAGE_NAME"
