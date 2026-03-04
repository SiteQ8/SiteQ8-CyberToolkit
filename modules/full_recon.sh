#!/usr/bin/env bash
# modules/full_recon.sh — Full Automated Recon Suite

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/utils.sh"

section "Full Recon Suite"

echo -e "  ${YELLOW}This runs all non-invasive recon modules against a single target."
echo -e "  Ensure you have authorization before proceeding.${RESET}"
echo ""
echo -ne "  ${BOLD}${WHITE}I confirm I have authorization for this target [yes/NO]: ${RESET}"
read -r CONFIRM
[[ "${CONFIRM,,}" != "yes" ]] && error "Authorization not confirmed. Aborting." && exit 1

TARGET=$(get_target "Enter target domain")
export DIRECT_TARGET="$TARGET"

MASTER_REPORT="$REPORT_DIR/full_recon_${TARGET//[^a-zA-Z0-9]/_}_$(date +%Y%m%d_%H%M%S).txt"

{
  echo "=================================================="
  echo "  SiteQ8 CyberToolkit — Full Recon Report"
  echo "  Target : $TARGET"
  echo "  Date   : $(date)"
  echo "  Author : SiteQ8 | https://github.com/SiteQ8"
  echo "=================================================="
  echo ""
} > "$MASTER_REPORT"

info "Master report: ${GRAY}$MASTER_REPORT${RESET}"
echo ""

MODULES=(
  "DNS Enumeration:dns_enum.sh"
  "Whois & IP Intel:whois_intel.sh"
  "SSL/TLS Analysis:ssl_analyzer.sh"
  "HTTP Headers:http_headers.sh"
  "Web Fingerprinting:web_fingerprint.sh"
  "Subdomain Discovery:subdomain_finder.sh"
  "Port Scan (Common):port_scanner.sh"
)

TOTAL_MODS=${#MODULES[@]}
DONE=0

for entry in "${MODULES[@]}"; do
  LABEL="${entry%%:*}"
  MOD="${entry#*:}"
  DONE=$((DONE+1))

  echo ""
  echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${BOLD}${BLUE} [${DONE}/${TOTAL_MODS}] ${LABEL}${RESET}"
  echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

  # Run module, capture output, tee to master report
  REPORT_DIR="$REPORT_DIR" bash "$SCRIPT_DIR/modules/$MOD" 2>&1 | tee -a "$MASTER_REPORT"
  echo "" >> "$MASTER_REPORT"
done

echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}${GREEN} Full Recon Complete!${RESET}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
success "Master report saved: ${GRAY}$MASTER_REPORT${RESET}"
echo ""
info "Open the report with: ${GRAY}less $MASTER_REPORT${RESET}"
info "Or grep findings:     ${GRAY}grep '\[FINDING\]' $MASTER_REPORT${RESET}"
