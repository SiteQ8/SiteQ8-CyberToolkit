#!/usr/bin/env bash
# modules/subdomain_finder.sh — Subdomain Discovery Module

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/utils.sh"

section "Subdomain Finder"

require_tool dig || exit 1

TARGET=$(get_target "Enter root domain (e.g. example.com)")
init_report "subdomain" "$TARGET"

# ── Built-in Wordlist ─────────────────────────────────────────────────────────
WORDLIST=(
  www mail ftp ssh api dev staging prod beta admin portal
  vpn remote ns1 ns2 mx smtp pop pop3 imap webmail
  blog shop store media static cdn img images files
  upload uploads download downloads assets js css
  dashboard app apps mobile m wap secure login
  auth oauth sso auth0 ldap ad dc intranet internal
  monitor monitoring status health backup db database
  mysql redis mongo postgres elastic kibana grafana
  jenkins ci cd git svn jira confluence wiki docs
  support helpdesk ticket crm erp billing invoice
  payment payments checkout cart api1 api2 v1 v2
  sandbox test testing qa uat preprod pre-prod
  old legacy new alpha gamma delta phoenix
  mx1 mx2 ns3 ns4 relay mail1 mail2 smtp2
  aws azure gcp cloud server1 server2 srv web1 web2
  cpanel whm plesk webmin phpmyadmin pma adminer
)

FOUND=0
TOTAL=${#WORDLIST[@]}
COUNT=0

echo ""
info "Wordlist: ${BOLD}${TOTAL}${RESET} subdomains | Target: ${BOLD}${TARGET}${RESET}"
echo ""

for sub in "${WORDLIST[@]}"; do
  COUNT=$((COUNT+1))
  FULL="${sub}.${TARGET}"
  printf "\r  ${CYAN}[*]${RESET} Testing: %-45s [%d/%d]" "$FULL" "$COUNT" "$TOTAL"

  IP=$(dig +short "$FULL" A 2>/dev/null | head -1)
  CNAME=$(dig +short "$FULL" CNAME 2>/dev/null | head -1)

  if [[ -n "$IP" ]]; then
    echo ""
    if [[ -n "$CNAME" ]]; then
      success "${BOLD}${FULL}${RESET}  ${GRAY}→ CNAME: ${CNAME}  → IP: ${IP}${RESET}"
      log_report "[FOUND] $FULL | CNAME: $CNAME | IP: $IP"
    else
      success "${BOLD}${FULL}${RESET}  ${GRAY}→ IP: ${IP}${RESET}"
      log_report "[FOUND] $FULL | IP: $IP"
    fi
    FOUND=$((FOUND+1))

    # Quick HTTP check
    HTTP=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "https://$FULL" 2>/dev/null)
    [[ -n "$HTTP" && "$HTTP" != "000" ]] && \
      info "  HTTP Status: ${BOLD}$HTTP${RESET}  (${FULL})"

  elif [[ -n "$CNAME" ]]; then
    echo ""
    warn "${BOLD}${FULL}${RESET}  ${GRAY}→ CNAME: ${CNAME}  (no A record)${RESET}"
    log_report "[CNAME-ONLY] $FULL -> $CNAME"

    # Subdomain takeover indicator
    DANGLING_SVCS="github.io|heroku|s3.amazonaws.com|netlify.app|surge.sh|ghost.io"
    if echo "$CNAME" | grep -qE "$DANGLING_SVCS"; then
      error "  Possible subdomain takeover! CNAME points to external service $(risk_badge HIGH)"
      log_report "[CRITICAL] Potential subdomain takeover: $FULL -> $CNAME"
    fi
    FOUND=$((FOUND+1))
  fi
done

printf "\r%-80s\n" ""
echo ""

# ── Certificate Transparency via crt.sh ──────────────────────────────────────
section "Certificate Transparency (crt.sh)"
if optional_tool curl; then
  info "Querying crt.sh for historical certificates..."
  CT_RESULTS=$(curl -sk "https://crt.sh/?q=%.${TARGET}&output=json" 2>/dev/null | \
    grep -oP '"name_value":"[^"]*"' | \
    cut -d'"' -f4 | \
    sort -u | \
    grep -v "^\*\." | \
    grep "\.$TARGET$")

  if [[ -n "$CT_RESULTS" ]]; then
    CT_COUNT=0
    while IFS= read -r sub; do
      echo -e "  ${CYAN}→${RESET}  $sub"
      log_report "[CT] $sub"
      CT_COUNT=$((CT_COUNT+1))
    done <<< "$CT_RESULTS"
    info "Found ${BOLD}${CT_COUNT}${RESET} unique domains via certificate transparency."
  else
    warn "No additional results from crt.sh (may be rate-limited)."
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
section "Summary"
success "Subdomains discovered: ${BOLD}$FOUND${RESET}"
echo ""
save_report
