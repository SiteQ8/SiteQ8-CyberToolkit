#!/usr/bin/env bash
# lib/utils.sh — Shared utility functions for SiteQ8 Toolkit

source "$(dirname "${BASH_SOURCE[0]}")/colors.sh"

REPORT_DIR="${REPORT_DIR:-$(dirname "${BASH_SOURCE[0]}")/../reports}"

# ─── Logging Helpers ──────────────────────────────────────────────────────────
info()    { echo -e "  ${CYAN}[*]${RESET} $*"; }
success() { echo -e "  ${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "  ${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "  ${RED}[✗]${RESET} $*"; }
section() { echo -e "\n${BOLD}${BLUE}── $* ${RESET}${GRAY}$(printf '─%.0s' {1..40})${RESET}\n"; }
finding() { echo -e "  ${MAGENTA}[→]${RESET} $*"; }

# ─── Target Input ─────────────────────────────────────────────────────────────
get_target() {
  local prompt="${1:-Enter target (domain/IP)}"
  if [[ -n "$DIRECT_TARGET" ]]; then
    TARGET="$DIRECT_TARGET"
    info "Using target: ${BOLD}$TARGET${RESET}"
  else
    echo -ne "  ${BOLD}${WHITE}$prompt: ${RESET}"
    read -r TARGET
  fi
  TARGET="${TARGET// /}"  # strip spaces
  if [[ -z "$TARGET" ]]; then
    error "No target specified."
    exit 1
  fi
  echo "$TARGET"
}

# ─── Tool Check ───────────────────────────────────────────────────────────────
require_tool() {
  if ! command -v "$1" &>/dev/null; then
    error "Required tool '${BOLD}$1${RESET}' not found. Install it and retry."
    return 1
  fi
  return 0
}

optional_tool() {
  if ! command -v "$1" &>/dev/null; then
    warn "'$1' not found — skipping related checks."
    return 1
  fi
  return 0
}

# ─── Report Writer ────────────────────────────────────────────────────────────
init_report() {
  local module="$1"
  local target="$2"
  REPORT_FILE="$REPORT_DIR/${module}_${target//[^a-zA-Z0-9]/_}_$(date +%Y%m%d_%H%M%S).txt"
  mkdir -p "$REPORT_DIR"
  {
    echo "==============================================="
    echo "  SiteQ8 CyberToolkit — Report"
    echo "  Module  : $module"
    echo "  Target  : $target"
    echo "  Date    : $(date)"
    echo "==============================================="
    echo ""
  } > "$REPORT_FILE"
  info "Report will be saved to: ${GRAY}$REPORT_FILE${RESET}"
}

log_report() {
  [[ -n "$REPORT_FILE" ]] && echo -e "$*" >> "$REPORT_FILE"
}

save_report() {
  [[ -n "$REPORT_FILE" ]] && success "Report saved: ${GRAY}$REPORT_FILE${RESET}"
}

# ─── Validation Helpers ───────────────────────────────────────────────────────
is_ip() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_domain() {
  [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]
}

resolve_ip() {
  dig +short "$1" 2>/dev/null | head -1
}

# ─── Progress / Spinner ───────────────────────────────────────────────────────
spinner() {
  local pid=$1
  local msg="${2:-Working...}"
  local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local i=0
  tput civis 2>/dev/null
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  ${CYAN}%s${RESET} %s" "${frames[$i]}" "$msg"
    i=$(( (i + 1) % ${#frames[@]} ))
    sleep 0.1
  done
  printf "\r  ${GREEN}✓${RESET} %-60s\n" "$msg"
  tput cnorm 2>/dev/null
}

# ─── Pretty Table ─────────────────────────────────────────────────────────────
table_row() {
  printf "  ${GRAY}│${RESET} %-24s ${GRAY}│${RESET} %-40s ${GRAY}│${RESET}\n" "$1" "$2"
}

table_sep() {
  echo -e "  ${GRAY}├──────────────────────────┼──────────────────────────────────────────┤${RESET}"
}

table_header() {
  echo -e "  ${GRAY}┌──────────────────────────┬──────────────────────────────────────────┐${RESET}"
  printf "  ${GRAY}│${RESET} ${BOLD}%-24s${RESET} ${GRAY}│${RESET} ${BOLD}%-40s${RESET} ${GRAY}│${RESET}\n" "$1" "$2"
  table_sep
}

table_footer() {
  echo -e "  ${GRAY}└──────────────────────────┴──────────────────────────────────────────┘${RESET}"
}

# ─── Risk Badge ───────────────────────────────────────────────────────────────
risk_badge() {
  case "${1^^}" in
    HIGH)   echo -e "${B_RED}[HIGH]${RESET}" ;;
    MEDIUM) echo -e "${B_YELLOW}[MEDIUM]${RESET}" ;;
    LOW)    echo -e "${B_GREEN}[LOW]${RESET}" ;;
    INFO)   echo -e "${CYAN}[INFO]${RESET}" ;;
    *)      echo -e "${GRAY}[UNKNOWN]${RESET}" ;;
  esac
}
