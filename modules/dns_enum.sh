#!/usr/bin/env bash
# modules/dns_enum.sh — DNS Enumeration Module

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/utils.sh"

section "DNS Enumerator"

TARGET=$(get_target "Enter domain to enumerate")
init_report "dns_enum" "$TARGET"

require_tool dig || exit 1

# ── Helper ────────────────────────────────────────────────────────────────────
query() {
  local type="$1" domain="$2"
  dig +short "$type" "$domain" 2>/dev/null
}

query_verbose() {
  local type="$1" domain="$2"
  dig "$type" "$domain" +noall +answer 2>/dev/null
}

print_record() {
  local label="$1" value="$2"
  printf "  ${GREEN}%-8s${RESET}  %s\n" "$label" "$value"
}

# ── A Records ─────────────────────────────────────────────────────────────────
section "A / AAAA Records"
A_RECORDS=$(query A "$TARGET")
if [[ -n "$A_RECORDS" ]]; then
  while IFS= read -r ip; do
    print_record "A" "$ip"
    log_report "[A] $ip"
  done <<< "$A_RECORDS"
else
  warn "No A records found."
fi

AAAA=$(query AAAA "$TARGET")
[[ -n "$AAAA" ]] && while IFS= read -r ip; do
  print_record "AAAA" "$ip"
  log_report "[AAAA] $ip"
done <<< "$AAAA"

# ── MX Records ────────────────────────────────────────────────────────────────
section "Mail (MX) Records"
MX=$(query MX "$TARGET")
if [[ -n "$MX" ]]; then
  while IFS= read -r rec; do
    print_record "MX" "$rec"
    log_report "[MX] $rec"
  done <<< "$MX"
else
  warn "No MX records found."
fi

# ── NS Records ────────────────────────────────────────────────────────────────
section "Name Servers (NS)"
NS=$(query NS "$TARGET")
if [[ -n "$NS" ]]; then
  while IFS= read -r ns; do
    ns_ip=$(query A "$ns")
    print_record "NS" "${ns}  ${GRAY}→ ${ns_ip}${RESET}"
    log_report "[NS] $ns -> $ns_ip"
  done <<< "$NS"
fi

# ── TXT Records ───────────────────────────────────────────────────────────────
section "TXT Records (SPF / DKIM / DMARC)"
TXT=$(query TXT "$TARGET")
if [[ -n "$TXT" ]]; then
  while IFS= read -r rec; do
    print_record "TXT" "$rec"
    log_report "[TXT] $rec"
    # Analyze
    if echo "$rec" | grep -qi "v=spf"; then
      finding "SPF policy found: $(risk_badge INFO)"
    fi
    if echo "$rec" | grep -qi "+all"; then
      finding "SPF uses +all — accepts ALL senders $(risk_badge HIGH)"
      log_report "[FINDING] SPF +all detected — HIGH risk"
    fi
  done <<< "$TXT"
fi

# DMARC
DMARC=$(dig +short TXT "_dmarc.$TARGET" 2>/dev/null)
if [[ -n "$DMARC" ]]; then
  print_record "DMARC" "$DMARC"
  log_report "[DMARC] $DMARC"
  if echo "$DMARC" | grep -q "p=none"; then
    finding "DMARC policy is 'none' — no enforcement $(risk_badge MEDIUM)"
  fi
else
  warn "No DMARC record — spoofing may be possible $(risk_badge HIGH)"
  log_report "[FINDING] No DMARC — spoofing risk"
fi

# ── CNAME Records ─────────────────────────────────────────────────────────────
section "CNAME Records"
CNAME=$(query CNAME "$TARGET")
if [[ -n "$CNAME" ]]; then
  print_record "CNAME" "$CNAME"
  log_report "[CNAME] $CNAME"
else
  info "No CNAME at apex (expected)."
fi

# Common subdomains via CNAME
for sub in www mail ftp api dev staging; do
  C=$(query CNAME "${sub}.${TARGET}" 2>/dev/null)
  [[ -n "$C" ]] && print_record "CNAME" "${sub}.${TARGET} → $C"
done

# ── SOA Record ────────────────────────────────────────────────────────────────
section "Start of Authority (SOA)"
SOA=$(dig SOA "$TARGET" +noall +answer 2>/dev/null | awk '{print $NF, $(NF-1), $(NF-2)}')
[[ -n "$SOA" ]] && info "SOA: $SOA" && log_report "[SOA] $SOA"

# ── Zone Transfer Attempt ─────────────────────────────────────────────────────
section "Zone Transfer (AXFR)"
info "Attempting zone transfer on all nameservers..."
AXFR_FOUND=false
while IFS= read -r ns; do
  ns="${ns%.}" # strip trailing dot
  info "Trying NS: ${BOLD}$ns${RESET}"
  AXFR=$(dig AXFR "$TARGET" "@$ns" 2>/dev/null)
  if echo "$AXFR" | grep -qv "Transfer failed\|REFUSED\|SERVFAIL"; then
    if echo "$AXFR" | grep -q "SOA"; then
      error "Zone transfer SUCCEEDED on $ns — $(risk_badge HIGH)"
      echo "$AXFR" | grep -v "^;" | while IFS= read -r line; do
        [[ -n "$line" ]] && echo -e "  ${RED}$line${RESET}"
      done
      log_report "[CRITICAL] Zone transfer succeeded on $ns"
      AXFR_FOUND=true
    fi
  else
    success "Zone transfer blocked on $ns"
    log_report "[OK] AXFR blocked on $ns"
  fi
done <<< "$(query NS "$TARGET")"
$AXFR_FOUND || success "No zone transfer vulnerability detected."

# ── Reverse DNS ───────────────────────────────────────────────────────────────
section "Reverse DNS Lookup"
for ip in $A_RECORDS; do
  PTR=$(dig +short -x "$ip" 2>/dev/null)
  if [[ -n "$PTR" ]]; then
    print_record "PTR" "$ip → $PTR"
    log_report "[PTR] $ip -> $PTR"
  else
    info "$ip → (no PTR record)"
  fi
done

echo ""
save_report
