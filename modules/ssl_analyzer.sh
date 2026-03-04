#!/usr/bin/env bash
# modules/ssl_analyzer.sh — SSL/TLS Security Analyzer

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/utils.sh"

section "SSL/TLS Analyzer"

require_tool openssl || exit 1

TARGET=$(get_target "Enter domain (e.g. example.com)")
echo -ne "  ${BOLD}${WHITE}Port [default: 443]: ${RESET}"
read -r PORT
PORT="${PORT:-443}"

init_report "ssl_tls" "$TARGET"
log_report "Target: $TARGET:$PORT"

# ── Certificate Info ──────────────────────────────────────────────────────────
section "Certificate Details"
CERT_DATA=$(echo | timeout 5 openssl s_client -connect "${TARGET}:${PORT}" -servername "$TARGET" 2>/dev/null)

if [[ -z "$CERT_DATA" ]]; then
  error "Could not connect to ${TARGET}:${PORT}. Is TLS available?"
  exit 1
fi

# Parse certificate
CERT_PEM=$(echo "$CERT_DATA" | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' | head -30)
CERT_TEXT=$(echo "$CERT_PEM" | openssl x509 -noout -text 2>/dev/null)

# Subject
SUBJECT=$(echo "$CERT_PEM" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')
ISSUER=$(echo "$CERT_PEM"  | openssl x509 -noout -issuer  2>/dev/null | sed 's/issuer=//')
NOT_BEFORE=$(echo "$CERT_PEM" | openssl x509 -noout -startdate 2>/dev/null | cut -d= -f2)
NOT_AFTER=$(echo "$CERT_PEM"  | openssl x509 -noout -enddate   2>/dev/null | cut -d= -f2)
SERIAL=$(echo "$CERT_PEM"  | openssl x509 -noout -serial    2>/dev/null | cut -d= -f2)
SIG_ALG=$(echo "$CERT_TEXT" | grep "Signature Algorithm" | head -1 | awk '{print $NF}')
KEY_LEN=$(echo "$CERT_TEXT" | grep -oP 'Public-Key: \(\K[0-9]+')
SANS=$(echo "$CERT_TEXT" | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/DNS://g' | tr ',' '\n' | sed 's/^ *//')

table_header "Property" "Value"
table_row "Subject"    "$SUBJECT"
table_row "Issuer"     "$ISSUER"
table_row "Not Before" "$NOT_BEFORE"
table_row "Not After"  "$NOT_AFTER"
table_row "Serial"     "$SERIAL"
table_row "Sig Algo"   "$SIG_ALG"
table_row "Key Length" "${KEY_LEN} bits"
table_footer

log_report "Subject: $SUBJECT"
log_report "Issuer: $ISSUER"
log_report "Valid: $NOT_BEFORE -> $NOT_AFTER"
log_report "Key Length: ${KEY_LEN} bits"

# ── Expiry Check ──────────────────────────────────────────────────────────────
section "Certificate Expiry"
EXPIRY_DATE=$(echo "$CERT_PEM" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY_DATE" +%s 2>/dev/null)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

if [[ "$DAYS_LEFT" -lt 0 ]]; then
  error "Certificate is EXPIRED (${DAYS_LEFT#-} days ago) $(risk_badge HIGH)"
  log_report "[FINDING] Certificate EXPIRED"
elif [[ "$DAYS_LEFT" -lt 14 ]]; then
  error "Certificate expires in ${DAYS_LEFT} days $(risk_badge HIGH)"
  log_report "[FINDING] Certificate expires in $DAYS_LEFT days — CRITICAL"
elif [[ "$DAYS_LEFT" -lt 30 ]]; then
  warn "Certificate expires in ${DAYS_LEFT} days $(risk_badge MEDIUM)"
  log_report "[FINDING] Certificate expires in $DAYS_LEFT days — WARNING"
else
  success "Certificate valid for ${BOLD}${DAYS_LEFT}${RESET} more days."
  log_report "[OK] Certificate expires in $DAYS_LEFT days"
fi

# ── SAN Domains ───────────────────────────────────────────────────────────────
section "Subject Alternative Names (SANs)"
if [[ -n "$SANS" ]]; then
  while IFS= read -r san; do
    [[ -z "${san// }" ]] && continue
    echo -e "  ${CYAN}→${RESET}  $san"
    log_report "[SAN] $san"
  done <<< "$SANS"
else
  warn "No SAN entries found."
fi

# ── Protocol Support ──────────────────────────────────────────────────────────
section "TLS Protocol Support"
for proto in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
  result=$(echo | timeout 5 openssl s_client -connect "${TARGET}:${PORT}" -${proto} 2>&1)
  if echo "$result" | grep -q "CONNECTED"; then
    case "$proto" in
      ssl2|ssl3|tls1|tls1_1)
        error "${BOLD}${proto^^}${RESET} — ENABLED  $(risk_badge HIGH)  ← Deprecated/insecure protocol"
        log_report "[FINDING] $proto is ENABLED — DEPRECATED"
        ;;
      tls1_2|tls1_3)
        success "${BOLD}${proto^^}${RESET} — Supported  $(risk_badge INFO)"
        log_report "[OK] $proto supported"
        ;;
    esac
  else
    info "${BOLD}${proto^^}${RESET} — Not supported / blocked"
  fi
done

# ── Cipher Analysis ───────────────────────────────────────────────────────────
section "Active Cipher Suite"
CIPHER=$(echo "$CERT_DATA" | grep "Cipher is" | awk '{print $NF}')
PROTO_USED=$(echo "$CERT_DATA" | grep "Protocol  :" | awk '{print $NF}')
info "Negotiated Protocol: ${BOLD}$PROTO_USED${RESET}"
info "Negotiated Cipher:   ${BOLD}$CIPHER${RESET}"

# Weak cipher check
WEAK_CIPHERS="RC4|DES|3DES|NULL|EXPORT|MD5|anon|RC2"
if echo "$CIPHER" | grep -qE "$WEAK_CIPHERS"; then
  error "Weak cipher detected: $CIPHER $(risk_badge HIGH)"
  log_report "[FINDING] Weak cipher: $CIPHER"
else
  success "Cipher appears acceptable."
fi

# ── Security Findings Summary ─────────────────────────────────────────────────
section "Security Observations"

# Self-signed?
if echo "$SUBJECT" | grep -q "$(echo "$ISSUER" | awk -F'CN=' '{print $2}' | head -1)"; then
  warn "Certificate appears self-signed $(risk_badge MEDIUM)"
  log_report "[FINDING] Possible self-signed certificate"
fi

# Weak key
if [[ -n "$KEY_LEN" && "$KEY_LEN" -lt 2048 ]]; then
  error "Key length ${KEY_LEN} bits is below minimum 2048 $(risk_badge HIGH)"
  log_report "[FINDING] Weak key: ${KEY_LEN} bits"
fi

# SHA1 signature
if echo "$SIG_ALG" | grep -qi sha1; then
  error "SHA-1 signature algorithm detected $(risk_badge HIGH)"
  log_report "[FINDING] SHA-1 signature — deprecated"
fi

echo ""
save_report
