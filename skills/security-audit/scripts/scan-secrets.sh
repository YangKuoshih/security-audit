#!/usr/bin/env bash
# scan-secrets.sh — Pattern-based secret and vulnerability scanner
# Part of the security-audit skill (https://github.com/YangKuoshih/security-audit)
# Licensed under Apache 2.0
#
# Usage:
#   scan-secrets.sh <target_dir> <patterns_file> <output_file> [options]
#
# Options:
#   --base-branch <branch>   Incremental mode: only scan files changed vs branch
#   --exclude-dirs <dirs>    Comma-separated directories to exclude (added to defaults)
#
# Output: JSON Lines format, one finding per line:
#   {"file":"path","line":N,"match":"redacted","pattern_id":"id","pattern_name":"name","severity":"LEVEL"}

set -euo pipefail

# ─── Argument parsing ───────────────────────────────────────────────────────

TARGET_DIR=""
PATTERNS_FILE=""
OUTPUT_FILE=""
BASE_BRANCH=""
EXTRA_EXCLUDE_DIRS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-branch)
      BASE_BRANCH="$2"
      shift 2
      ;;
    --exclude-dirs)
      EXTRA_EXCLUDE_DIRS="$2"
      shift 2
      ;;
    *)
      if [[ -z "$TARGET_DIR" ]]; then
        TARGET_DIR="$1"
      elif [[ -z "$PATTERNS_FILE" ]]; then
        PATTERNS_FILE="$1"
      elif [[ -z "$OUTPUT_FILE" ]]; then
        OUTPUT_FILE="$1"
      else
        echo "ERROR: Unknown argument: $1" >&2
        exit 1
      fi
      shift
      ;;
  esac
done

if [[ -z "$TARGET_DIR" || -z "$PATTERNS_FILE" || -z "$OUTPUT_FILE" ]]; then
  echo "Usage: scan-secrets.sh <target_dir> <patterns_file> <output_file> [--base-branch <branch>] [--exclude-dirs <dirs>]" >&2
  exit 1
fi

if [[ ! -d "$TARGET_DIR" && ! -f "$TARGET_DIR" ]]; then
  echo "ERROR: Target not found: $TARGET_DIR" >&2
  exit 1
fi

if [[ ! -f "$PATTERNS_FILE" ]]; then
  echo "ERROR: Patterns file not found: $PATTERNS_FILE" >&2
  exit 1
fi

# ─── Configuration ──────────────────────────────────────────────────────────

DEFAULT_EXCLUDE_DIRS="node_modules|\.git|venv|\.venv|dist|build|__pycache__|\.next|vendor|target|\.tox|\.eggs|\.mypy_cache|\.pytest_cache"
EXCLUDE_DIRS="$DEFAULT_EXCLUDE_DIRS"

if [[ -n "$EXTRA_EXCLUDE_DIRS" ]]; then
  EXTRA_EXCLUDE_DIRS=$(echo "$EXTRA_EXCLUDE_DIRS" | tr ',' '|')
  EXCLUDE_DIRS="${EXCLUDE_DIRS}|${EXTRA_EXCLUDE_DIRS}"
fi

BINARY_EXTENSIONS="\.(png|jpg|jpeg|gif|bmp|ico|svg|woff|woff2|ttf|eot|otf|mp3|mp4|avi|mov|pdf|zip|gz|tar|bz2|7z|rar|jar|war|ear|class|pyc|pyo|so|dylib|dll|exe|bin|dat|db|sqlite|sqlite3|lock|min\.js|min\.css|map|chunk\.js)$"

# ─── Detect grep capabilities ──────────────────────────────────────────────

GREP_MODE="ERE"
if echo "test" | grep -P "test" > /dev/null 2>&1; then
  GREP_MODE="PCRE"
fi

# ─── Helper functions ───────────────────────────────────────────────────────

redact_match() {
  local match="$1"
  local len=${#match}
  if [[ $len -le 8 ]]; then
    echo "****"
  elif [[ $len -le 16 ]]; then
    echo "${match:0:2}...${match: -2}"
  else
    echo "${match:0:4}...${match: -4}"
  fi
}

json_escape() {
  local str="$1"
  str="${str//\\/\\\\}"
  str="${str//\"/\\\"}"
  str="${str//$'\t'/\\t}"
  str="${str//$'\n'/\\n}"
  str="${str//$'\r'/\\r}"
  echo "$str"
}

emit_finding() {
  local file="$1" line="$2" match="$3" pattern_id="$4" pattern_name="$5" severity="$6" output="$7"

  local redacted
  redacted=$(redact_match "$match")

  # Make path relative to target
  local rel_path="$file"
  if [[ "$file" == "${TARGET_DIR}"* ]]; then
    rel_path="${file#${TARGET_DIR%/}/}"
  fi

  local ef ep en ei er
  ef=$(json_escape "$rel_path")
  er=$(json_escape "$redacted")
  en=$(json_escape "$pattern_name")
  ei=$(json_escape "$pattern_id")

  local json="{\"file\":\"${ef}\",\"line\":${line},\"match\":\"${er}\",\"pattern_id\":\"${ei}\",\"pattern_name\":\"${en}\",\"severity\":\"${severity}\"}"

  if [[ "$output" == "/dev/stdout" || "$output" == "-" ]]; then
    echo "$json"
  else
    echo "$json" >> "$output"
  fi
}

# ─── Build file list ───────────────────────────────────────────────────────

FILE_LIST=$(mktemp)
CURRENT_PATTERN_TMP=""
trap 'rm -f "$FILE_LIST" "$FILTERED_LIST" "$CURRENT_PATTERN_TMP" 2>/dev/null' EXIT

if [[ -f "$TARGET_DIR" ]]; then
  # Single file mode
  echo "$TARGET_DIR" > "$FILE_LIST"
elif [[ -n "$BASE_BRANCH" ]] && command -v git > /dev/null 2>&1 && git -C "$TARGET_DIR" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
  # Incremental mode
  echo "Mode: incremental (base: $BASE_BRANCH)" >&2
  git -C "$TARGET_DIR" diff --name-only --diff-filter=ACMR "${BASE_BRANCH}...HEAD" 2>/dev/null | while IFS= read -r f; do
    [[ -f "${TARGET_DIR%/}/$f" ]] && echo "${TARGET_DIR%/}/$f"
  done > "$FILE_LIST"
elif command -v git > /dev/null 2>&1 && git -C "$TARGET_DIR" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
  # Full scan with git ls-files
  echo "Mode: full scan (git)" >&2
  git -C "$TARGET_DIR" ls-files --cached --others --exclude-standard 2>/dev/null | while IFS= read -r f; do
    echo "${TARGET_DIR%/}/$f"
  done > "$FILE_LIST"
else
  # Full scan without git
  echo "Mode: full scan (find)" >&2
  find "$TARGET_DIR" -type f 2>/dev/null > "$FILE_LIST"
fi

# Filter: exclude directories and binary extensions
FILTERED_LIST=$(mktemp)

while IFS= read -r filepath; do
  # Skip excluded directories
  echo "$filepath" | grep -qE "/(${EXCLUDE_DIRS})(/|$)" && continue
  # Skip binary extensions
  echo "$filepath" | grep -qiE "$BINARY_EXTENSIONS" && continue
  echo "$filepath"
done < "$FILE_LIST" > "$FILTERED_LIST"

FILE_COUNT=$(wc -l < "$FILTERED_LIST" | tr -d ' ')
echo "Files to scan: $FILE_COUNT" >&2

# ─── Load patterns ─────────────────────────────────────────────────────────

declare -a P_SEV=() P_ID=() P_NAME=() P_REGEX=()
PATTERN_COUNT=0

while IFS=$'\t' read -r sev pid pname regex; do
  [[ "$sev" =~ ^#.*$ || -z "$sev" ]] && continue
  P_SEV+=("$sev")
  P_ID+=("$pid")
  P_NAME+=("$pname")
  P_REGEX+=("$regex")
  PATTERN_COUNT=$((PATTERN_COUNT + 1))
done < "$PATTERNS_FILE"

echo "Patterns loaded: $PATTERN_COUNT" >&2

# ─── Scan ───────────────────────────────────────────────────────────────────

# Clear output file
if [[ "$OUTPUT_FILE" != "/dev/stdout" && "$OUTPUT_FILE" != "-" ]]; then
  > "$OUTPUT_FILE"
fi

echo "security-audit scanner v0.1.0" >&2
echo "Target: $TARGET_DIR" >&2
echo "Grep mode: $GREP_MODE" >&2

FINDING_COUNT=0

# For each pattern, grep across all files at once (much faster than per-file).
# Use arithmetic loop instead of seq(1) for POSIX portability.
i=0
while [ "$i" -lt "$PATTERN_COUNT" ]; do
  local_sev="${P_SEV[$i]}"
  local_id="${P_ID[$i]}"
  local_name="${P_NAME[$i]}"
  local_regex="${P_REGEX[$i]}"

  # Build grep flags
  grep_flag="-E"
  if [[ "$GREP_MODE" == "PCRE" ]]; then
    grep_flag="-P"
  fi

  # Grep all files for this pattern. -I skips binary, -n shows line numbers, -H shows filename.
  # Store results in temp file to avoid subshell variable scope issues and pipefail exits.
  # Track in CURRENT_PATTERN_TMP so the EXIT trap can clean it up on early exit.
  local_results=$(mktemp)
  CURRENT_PATTERN_TMP="$local_results"
  tr '\n' '\0' < "$FILTERED_LIST" | xargs -0 grep -nIH $grep_flag -- "$local_regex" 2>/dev/null > "$local_results" || true

  while IFS= read -r result; do
    [[ -z "$result" ]] && continue

    # Result format: filepath:linenum:line_content
    local_file="${result%%:*}"
    local_rest="${result#*:}"
    local_linenum="${local_rest%%:*}"
    local_content="${local_rest#*:}"

    # Extract matched text
    local_matched=""
    local_matched=$(echo "$local_content" | grep -o${grep_flag#-} "$local_regex" 2>/dev/null | head -1) || true

    if [[ -z "$local_matched" ]]; then
      local_matched="(pattern match)"
    fi

    emit_finding "$local_file" "$local_linenum" "$local_matched" "$local_id" "$local_name" "$local_sev" "$OUTPUT_FILE"
    FINDING_COUNT=$((FINDING_COUNT + 1))
  done < "$local_results"

  rm -f "$local_results"
  i=$((i + 1))
done

echo "Scan complete. Findings: $FINDING_COUNT" >&2
