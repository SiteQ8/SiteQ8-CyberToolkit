#!/usr/bin/env bash
# modules/http_headers.sh — HTTP Security Headers Inspector

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/utils.sh"

section "HTTP Header Inspector"

require_tool curl || exit 1

TARGET=$(get_target "Enter URL (e.g. https://example.com)")
[[ "$TARGET" != http* ]] && TARGET="https://$TARGET"

init_report "http_headers" "$TARGET"
log_report "Target: $TARGET"

# ── Fetch Headers ─────────────────────────────────────────────────────────────
info "Fetching headers from ${BOLD}$TARGET${RESET} ..."
HEADERS=$(curl -sk -I --max-time 10 -L \
  -A "Mozilla/5.0 (SiteQ8 SecurityScanner/1.0)" \
  "$TARGET" 2>/dev/null)

if [[ -z "$HEADERS" ]]; then
  error "Failed to connect to target."
  exit 1
fi

# ── Response Line ─────────────────────────────────────────────────────────────
section "Response Status"
STATUS=$(echo "$HEADERS" | head -1)
echo -e "  ${BOLD}${CYAN}$STATUS${RESET}"
log_report "Status: $STATUS"

HTTP_CODE=$(echo "$STATUS" | awk '{print $2}')
case "${HTTP_CODE:0:1}" in
  2) success "2xx Success response" ;;
  3) info "3xx Redirect" ;;
  4) warn "4xx Client Error — $(risk_badge MEDIUM)" ;;
  5) error "5xx Server Error — $(risk_badge HIGH)" ;;
esac

# ── All Headers ───────────────────────────────────────────────────────────────
section "Raw Response Headers"
echo "$HEADERS" | while IFS= read -r line; do
  if echo "$line" | grep -qiE "server:|x-powered-by:|via:"; then
    echo -e "  ${YELLOW}$line${RESET}"
  elif echo "$line" | grep -qiE "strict-transport|content-security|x-frame|x-xss"; then
    echo -e "  ${GREEN}$line${RESET}"
  else
    echo -e "  ${GRAY}$line${RESET}"
  fi
  log_report "$line"
done

# ── Security Header Checks ────────────────────────────────────────────────────
section "Security Header Audit"

declare -A SEC_HEADERS=(
  ["Strict-Transport-Security"]="Enforces HTTPS — prevents protocol downgrade"
  ["Content-Security-Policy"]="Prevents XSS and data injection"
  ["X-Frame-Options"]="Prevents clickjacking"
  ["X-Content-Type-Options"]="Prevents MIME-type sniffing"
  ["Referrer-Policy"]="Controls Referrer header leakage"
  ["Permissions-Policy"]="Controls browser feature access"
  ["X-XSS-Protection"]="Legacy XSS filter (deprecated but informational)"
  ["Cross-Origin-Opener-Policy"]="Isolation from cross-origin pages"
  ["Cross-Origin-Resource-Policy"]="Controls cross-origin resource loading"
)

SCORE=0
TOTAL=0

for header in "${!SEC_HEADERS[@]}"; do
  TOTAL=$((TOTAL+1))
  VALUE=$(echo "$HEADERS" | grep -i "^${header}:" | cut -d: -f2- | sed 's/^ //')
  if [[ -n "$VALUE" ]]; then
    success "${BOLD}${header}${RESET}  ${GRAY}${VALUE:0:60}${RESET}"
    SCORE=$((SCORE+1))
    log_report "[PRESENT] $header: $VALUE"
  else
    error "Missing: ${BOLD}${header}${RESET}  ${GRAY}→ ${SEC_HEADERS[$header]}${RESET}"
    log_report "[MISSING] $header"
  fi
done

# ── Score Card ────────────────────────────────────────────────────────────────
section "Security Score"
PCT=$((SCORE * 100 / TOTAL))
BAR_FULL=$((SCORE * 20 / TOTAL))
BAR_EMPTY=$((20 - BAR_FULL))

printf "  ["
for ((i=0;i<BAR_FULL;i++)); do printf "${GREEN}█${RESET}"; done
for ((i=0;i<BAR_EMPTY;i++)); do printf "${GRAY}░${RESET}"; done
printf "]  ${BOLD}%d/%d${RESET} headers present (%d%%)\n" "$SCORE" "$TOTAL" "$PCT"

if [[ $PCT -lt 50 ]]; then
  error "Poor security header posture $(risk_badge HIGH)"
elif [[ $PCT -lt 80 ]]; then
  warn "Moderate security header posture $(risk_badge MEDIUM)"
else
  success "Good security header posture"
fi

log_report "Security score: $SCORE/$TOTAL ($PCT%)"

# ── Information Disclosure ────────────────────────────────────────────────────
section "Information Disclosure"

SERVER=$(echo "$HEADERS" | grep -i "^Server:" | cut -d: -f2- | sed 's/^ //')
POWERED=$(echo "$HEADERS" | grep -i "^X-Powered-By:" | cut -d: -f2- | sed 's/^ //')
VIA=$(echo "$HEADERS" | grep -i "^Via:" | cut -d: -f2- | sed 's/^ //')

if [[ -n "$SERVER" ]]; then
  warn "Server banner disclosed: ${BOLD}$SERVER${RESET}  $(risk_badge LOW)"
  log_report "[FINDING] Server header: $SERVER"
fi

if [[ -n "$POWERED" ]]; then
  warn "X-Powered-By disclosed: ${BOLD}$POWERED${RESET}  $(risk_badge MEDIUM)"
  log_report "[FINDING] X-Powered-By: $POWERED"
fi

if [[ -n "$VIA" ]]; then
  info "Proxy/CDN detected: ${BOLD}$VIA${RESET}"
fi

# ── Cookie Analysis ───────────────────────────────────────────────────────────
section "Cookie Security"
echo "$HEADERS" | grep -i "^Set-Cookie:" | while IFS= read -r cookie; do
  name=$(echo "$cookie" | cut -d: -f2- | cut -d= -f1 | sed 's/^ //')
  echo -e "  ${CYAN}Cookie:${RESET} $name"

  if ! echo "$cookie" | grep -qi "HttpOnly"; then
    error "  Missing ${BOLD}HttpOnly${RESET} flag — accessible via JS $(risk_badge HIGH)"
    log_report "[FINDING] Cookie $name missing HttpOnly"
  else
    success "  HttpOnly ✓"
  fi

  if ! echo "$cookie" | grep -qi "Secure"; then
    error "  Missing ${BOLD}Secure${RESET} flag — sent over HTTP $(risk_badge MEDIUM)"
    log_report "[FINDING] Cookie $name missing Secure"
  else
    success "  Secure ✓"
  fi

  if ! echo "$cookie" | grep -qi "SameSite"; then
    warn "  Missing ${BOLD}SameSite${RESET} flag — CSRF risk $(risk_badge MEDIUM)"
    log_report "[FINDING] Cookie $name missing SameSite"
  else
    success "  SameSite ✓"
  fi
  echo ""
done

echo ""
save_report
