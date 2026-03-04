#!/usr/bin/env bash
# =============================================================================
#  ██████╗ ██╗████████╗███████╗ ██████╗ █████╗
# ██╔════╝ ██║╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗
# ╚██████╗ ██║   ██║   █████╗  ██║   ██║╚█████╔╝
#  ╚════██╗██║   ██║   ██╔══╝  ██║▄▄ ██║██╔══██╗
#  ██████╔╝██║   ██║   ███████╗╚██████╔╝╚█████╔╝
#  ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚══▀▀═╝  ╚════╝
#
#  SiteQ8 CyberToolkit — by SiteQ8
#  GitHub: https://github.com/SiteQ8
#  License: MIT
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
MOD_DIR="$SCRIPT_DIR/modules"
REPORT_DIR="$SCRIPT_DIR/reports"

source "$LIB_DIR/colors.sh"
source "$LIB_DIR/utils.sh"

VERSION="1.0.0"
AUTHOR="SiteQ8"
GITHUB="https://github.com/SiteQ8"

# ─── Banner ───────────────────────────────────────────────────────────────────
banner() {
  clear
  echo -e "${CYAN}"
  cat << 'EOF'
  ██████╗ ██╗████████╗███████╗ ██████╗ ██████╗
 ██╔════╝ ██║╚══██╔══╝██╔════╝██╔═══██╗╚════██╗
 ╚██████╗ ██║   ██║   █████╗  ██║   ██║ █████╔╝
  ╚════██╗██║   ██║   ██╔══╝  ██║▄▄ ██║██╔═══╝
  ██████╔╝██║   ██║   ███████╗╚██████╔╝███████╗
  ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚══▀▀═╝╚══════╝
EOF
  echo -e "${RESET}"
  echo -e "  ${BOLD}${WHITE}SiteQ8 CyberToolkit v${VERSION}${RESET}"
  echo -e "  ${GRAY}Ethical security assessment suite${RESET}"
  echo -e "  ${GRAY}${GITHUB}${RESET}"
  echo ""
  echo -e "  ${YELLOW}⚠  For authorized testing and educational use only.${RESET}"
  echo ""
}

# ─── Main Menu ────────────────────────────────────────────────────────────────
main_menu() {
  echo -e "${BOLD}${BLUE}╔══════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}${BLUE}║         SELECT A MODULE              ║${RESET}"
  echo -e "${BOLD}${BLUE}╠══════════════════════════════════════╣${RESET}"
  echo -e "${BOLD}${BLUE}║${RESET}  ${GREEN}[1]${RESET}  Network Recon               ${BOLD}${BLUE}║${RESET}"
  echo -e "${BOLD}${BLUE}║${RESET}  ${GREEN}[2]${RESET}  Port Scanner                ${BOLD}${BLUE}║${RESET}"
  echo -e "${BOLD}${BLUE}║${RESET}  ${GREEN}[3]${RESET}  DNS Enumerator              ${BOLD}${BLUE}║${RESET}"
  echo -e "${BOLD}${BLUE}║${RESET}  ${GREEN}[4]${RESET}  SSL/TLS Analyzer            ${BOLD}${BLUE}║${RESET}"
  echo -e "${BOLD}${BLUE}║${RESET}  ${GREEN}[5]${RESET}  HTTP Header Inspector       ${BOLD}${BLUE}║${RESET}"
  echo -e "${BOLD}${BLUE}║${RESET}  ${GREEN}[6]${RESET}  Subdomain Finder            ${BOLD}${BLUE}║${RESET}"
  echo -e "${BOLD}${BLUE}║${RESET}  ${GREEN}[7]${RESET}  Whois & IP Intel            ${BOLD}${BLUE}║${RESET}"
  echo -e "${BOLD}${BLUE}║${RESET}  ${GREEN}[8]${RESET}  Web Tech Fingerprinter      ${BOLD}${BLUE}║${RESET}"
  echo -e "${BOLD}${BLUE}║${RESET}  ${GREEN}[9]${RESET}  Password Auditor            ${BOLD}${BLUE}║${RESET}"
  echo -e "${BOLD}${BLUE}║${RESET}  ${GREEN}[10]${RESET} Log Analyzer                ${BOLD}${BLUE}║${RESET}"
  echo -e "${BOLD}${BLUE}║${RESET}  ${GREEN}[11]${RESET} Full Recon Suite            ${BOLD}${BLUE}║${RESET}"
  echo -e "${BOLD}${BLUE}║${RESET}  ${RED}[0]${RESET}  Exit                        ${BOLD}${BLUE}║${RESET}"
  echo -e "${BOLD}${BLUE}╚══════════════════════════════════════╝${RESET}"
  echo ""
  echo -ne "${BOLD}${WHITE}Select option: ${RESET}"
}

# ─── Module Dispatcher ────────────────────────────────────────────────────────
run_module() {
  case "$1" in
    1)  bash "$MOD_DIR/net_recon.sh" ;;
    2)  bash "$MOD_DIR/port_scanner.sh" ;;
    3)  bash "$MOD_DIR/dns_enum.sh" ;;
    4)  bash "$MOD_DIR/ssl_analyzer.sh" ;;
    5)  bash "$MOD_DIR/http_headers.sh" ;;
    6)  bash "$MOD_DIR/subdomain_finder.sh" ;;
    7)  bash "$MOD_DIR/whois_intel.sh" ;;
    8)  bash "$MOD_DIR/web_fingerprint.sh" ;;
    9)  bash "$MOD_DIR/password_auditor.sh" ;;
    10) bash "$MOD_DIR/log_analyzer.sh" ;;
    11) bash "$MOD_DIR/full_recon.sh" ;;
    0)  echo -e "\n${GREEN}[✓] Exiting SiteQ8 Toolkit. Stay ethical!${RESET}\n"; exit 0 ;;
    *)  warn "Invalid option. Please try again." ;;
  esac
}

# ─── Dependency Check ─────────────────────────────────────────────────────────
check_deps() {
  local deps=(curl wget dig nmap whois openssl ncat)
  local missing=()
  for dep in "${deps[@]}"; do
    command -v "$dep" &>/dev/null || missing+=("$dep")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Optional tools not found: ${missing[*]}"
    warn "Some modules may have limited functionality."
    echo ""
  fi
}

# ─── CLI Flags ────────────────────────────────────────────────────────────────
if [[ "$1" == "--version" || "$1" == "-v" ]]; then
  echo "SiteQ8 CyberToolkit v${VERSION}"
  exit 0
fi

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
  echo "Usage: $0 [--version] [--module <1-11>] [--target <host>]"
  echo ""
  echo "  --module <n>    Run a specific module directly"
  echo "  --target <h>    Pre-fill target for non-interactive use"
  echo "  --version       Show version"
  exit 0
fi

# ─── Direct Module Launch ─────────────────────────────────────────────────────
if [[ "$1" == "--module" && -n "$2" ]]; then
  banner
  export DIRECT_TARGET="$3"
  run_module "$2"
  exit 0
fi

# ─── Interactive Mode ─────────────────────────────────────────────────────────
mkdir -p "$REPORT_DIR"
banner
check_deps

while true; do
  main_menu
  read -r choice
  echo ""
  run_module "$choice"
  echo ""
  echo -e "${GRAY}Press [Enter] to return to menu...${RESET}"
  read -r
  banner
done
