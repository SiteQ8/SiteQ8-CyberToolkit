#!/usr/bin/env bash
# modules/whois_intel.sh — Whois & IP Intelligence Module

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/utils.sh"

section "Whois & IP Intelligence"

TARGET=$(get_target "Enter domain or IP")
init_report "whois_intel" "$TARGET"

# ── Resolve IP ────────────────────────────────────────────────────────────────
if is_domain "$TARGET"; then
  IP=$(resolve_ip "$TARGET")
  info "Resolved: ${BOLD}$TARGET${RESET} → ${BOLD}${IP:-N/A}${RESET}"
  DOMAIN="$TARGET"
else
  IP="$TARGET"
  DOMAIN=""
fi

# ── Whois ─────────────────────────────────────────────────────────────────────
section "Domain Whois"
if optional_tool whois; then
  WHOIS_DATA=$(whois "${DOMAIN:-$IP}" 2>/dev/null)

  # Parse key fields
  REGISTRAR=$(echo "$WHOIS_DATA" | grep -iE "^Registrar:" | head -1 | cut -d: -f2- | sed 's/^ //')
  CREATED=$(echo "$WHOIS_DATA"   | grep -iE "Creation Date|Created:" | head -1 | cut -d: -f2- | sed 's/^ //')
  UPDATED=$(echo "$WHOIS_DATA"   | grep -iE "Updated Date|Last Updated:" | head -1 | cut -d: -f2- | sed 's/^ //')
  EXPIRES=$(echo "$WHOIS_DATA"   | grep -iE "Expir" | head -1 | cut -d: -f2- | sed 's/^ //')
  NS_RAW=$(echo "$WHOIS_DATA"    | grep -iE "^Name Server:" | awk '{print $NF}' | sort -u | tr '\n' ' ')
  STATUS=$(echo "$WHOIS_DATA"    | grep -iE "^Domain Status:" | head -3 | cut -d: -f2- | sed 's/^ //' | tr '\n' ', ')
  REGISTRANT=$(echo "$WHOIS_DATA"| grep -iE "Registrant (Org|Name|Email)" | head -3)

  table_header "Field" "Value"
  [[ -n "$REGISTRAR"  ]] && table_row "Registrar"  "${REGISTRAR:0:50}"
  [[ -n "$CREATED"    ]] && table_row "Created"    "${CREATED:0:50}"
  [[ -n "$UPDATED"    ]] && table_row "Updated"    "${UPDATED:0:50}"
  [[ -n "$EXPIRES"    ]] && table_row "Expires"    "${EXPIRES:0:50}"
  [[ -n "$NS_RAW"     ]] && table_row "Nameservers" "${NS_RAW:0:50}"
  [[ -n "$STATUS"     ]] && table_row "Status"     "${STATUS:0:50}"
  table_footer

  log_report "Registrar: $REGISTRAR"
  log_report "Created: $CREATED"
  log_report "Expires: $EXPIRES"

  # Registrant privacy check
  if echo "$WHOIS_DATA" | grep -qi "privacy\|redacted\|proxy"; then
    info "Registrant info is privacy-protected."
  else
    warn "Registrant details may be public — check report for details."
    echo "$REGISTRANT" | while IFS= read -r line; do
      [[ -n "$line" ]] && finding "$line"
    done
  fi

  # clientTransferProhibited
  if echo "$STATUS" | grep -qi "clientTransferProhibited"; then
    success "Domain has transfer lock enabled."
  else
    warn "Transfer lock not detected — domain hijacking may be easier $(risk_badge MEDIUM)"
  fi
fi

# ── IP Geolocation ────────────────────────────────────────────────────────────
section "IP Geolocation & ASN"
if [[ -n "$IP" ]] && optional_tool curl; then
  GEO=$(curl -sk --max-time 8 "https://ipinfo.io/${IP}/json" 2>/dev/null)
  if [[ -n "$GEO" ]]; then
    ORG=$(echo "$GEO"      | grep -oP '"org":\s*"\K[^"]+')
    CITY=$(echo "$GEO"     | grep -oP '"city":\s*"\K[^"]+')
    REGION=$(echo "$GEO"   | grep -oP '"region":\s*"\K[^"]+')
    COUNTRY=$(echo "$GEO"  | grep -oP '"country":\s*"\K[^"]+')
    TZ=$(echo "$GEO"       | grep -oP '"timezone":\s*"\K[^"]+')
    HOSTNAME=$(echo "$GEO" | grep -oP '"hostname":\s*"\K[^"]+')
    LOC=$(echo "$GEO"      | grep -oP '"loc":\s*"\K[^"]+')
    BOGON=$(echo "$GEO"    | grep -oP '"bogon":\s*\K[a-z]+')

    table_header "Field" "Value"
    table_row "IP"        "$IP"
    table_row "Hostname"  "${HOSTNAME:-N/A}"
    table_row "ASN / Org" "${ORG:-N/A}"
    table_row "City"      "${CITY:-N/A}, ${REGION:-N/A}"
    table_row "Country"   "${COUNTRY:-N/A}"
    table_row "Timezone"  "${TZ:-N/A}"
    table_row "Coords"    "${LOC:-N/A}"
    table_footer

    log_report "IP: $IP | Org: $ORG | Location: $CITY, $COUNTRY | ASN: $ORG"

    [[ "$BOGON" == "true" ]] && warn "IP is in a bogon/private range."

    # Hosting/Cloud detection
    if echo "$ORG" | grep -qi "amazon\|AWS\|Azure\|Google\|Cloudflare\|Fastly\|Akamai\|DigitalOcean\|Linode"; then
      info "Hosted on cloud/CDN: ${BOLD}$ORG${RESET}"
      log_report "[CLOUD] $ORG"
    fi
  else
    warn "Could not reach ipinfo.io — try manual lookup."
  fi
fi

# ── Shodan Link ───────────────────────────────────────────────────────────────
section "External Intel Links"
echo -e "  ${CYAN}Shodan:${RESET}    https://www.shodan.io/host/$IP"
echo -e "  ${CYAN}VirusTotal:${RESET} https://www.virustotal.com/gui/ip-address/$IP"
echo -e "  ${CYAN}Censys:${RESET}    https://search.censys.io/hosts/$IP"
echo -e "  ${CYAN}AbuseIPDB:${RESET} https://www.abuseipdb.com/check/$IP"
[[ -n "$DOMAIN" ]] && \
  echo -e "  ${CYAN}SecurityTrails:${RESET} https://securitytrails.com/domain/$DOMAIN/dns"

log_report "Manual lookups: Shodan/VT/Censys/AbuseIPDB for $IP"

echo ""
save_report
