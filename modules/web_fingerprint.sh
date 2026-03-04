#!/usr/bin/env bash
# modules/web_fingerprint.sh — Web Technology Fingerprinter

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/utils.sh"

section "Web Technology Fingerprinter"

require_tool curl || exit 1

TARGET=$(get_target "Enter URL (e.g. https://example.com)")
[[ "$TARGET" != http* ]] && TARGET="https://$TARGET"

DOMAIN=$(echo "$TARGET" | awk -F/ '{print $3}')
init_report "web_fingerprint" "$DOMAIN"
log_report "Target: $TARGET"

# ── Fetch Full Response ───────────────────────────────────────────────────────
info "Fetching response from ${BOLD}$TARGET${RESET} ..."
RESP=$(curl -sk --max-time 15 -L \
  -A "Mozilla/5.0 (SiteQ8 SecurityScanner/1.0)" \
  -D /tmp/sq8_headers.txt \
  "$TARGET" 2>/dev/null)

HEADERS=$(cat /tmp/sq8_headers.txt 2>/dev/null)

if [[ -z "$RESP" ]]; then
  error "No response from target."
  exit 1
fi

success "Got response (${#RESP} bytes)"

# ── Server Stack ──────────────────────────────────────────────────────────────
section "Server & Platform"

detect() {
  local label="$1" pattern="$2" source="${3:-both}"
  local found=""
  if [[ "$source" == "headers" || "$source" == "both" ]]; then
    found=$(echo "$HEADERS" | grep -iE "$pattern" | head -1 | sed 's/\r//')
  fi
  if [[ -z "$found" && ( "$source" == "body" || "$source" == "both" ) ]]; then
    found=$(echo "$RESP" | grep -ioE "$pattern" | head -1)
  fi
  if [[ -n "$found" ]]; then
    success "${BOLD}${label}${RESET}:  ${GRAY}${found:0:80}${RESET}"
    log_report "[DETECTED] $label: $found"
    return 0
  fi
  return 1
}

# Server
detect "Web Server"    "^server:.*" "headers"
detect "Powered By"   "^x-powered-by:.*" "headers"

# CMS detection
declare -A CMS_PATTERNS=(
  ["WordPress"]="wp-content|wp-includes|wordpress"
  ["Joomla"]="joomla|/components/com_"
  ["Drupal"]="drupal|/sites/default/files"
  ["Magento"]="magento|Mage.Cookies|/skin/frontend"
  ["Shopify"]="shopify|cdn.shopify.com"
  ["Wix"]="wix.com|wixstatic"
  ["Squarespace"]="squarespace|static.squarespace.com"
  ["Ghost"]="ghost.io|/ghost/api"
  ["Typo3"]="typo3|typo3conf"
  ["DotNetNuke"]="DotNetNuke|dnn_"
  ["Laravel"]="laravel_session|laravel"
  ["Django"]="csrfmiddlewaretoken|django"
  ["Ruby on Rails"]="X-Runtime.*Ruby|rails-|Rack"
  ["ASP.NET"]="ASP.NET|__VIEWSTATE|AspNet"
)

section "CMS & Framework Detection"
CMS_FOUND=()
for cms in "${!CMS_PATTERNS[@]}"; do
  PAT="${CMS_PATTERNS[$cms]}"
  if echo "$RESP $HEADERS" | grep -iqE "$PAT"; then
    success "Detected: ${BOLD}$cms${RESET}"
    log_report "[CMS] $cms detected"
    CMS_FOUND+=("$cms")
  fi
done
[[ ${#CMS_FOUND[@]} -eq 0 ]] && info "No common CMS fingerprinted."

# ── JavaScript Libraries ──────────────────────────────────────────────────────
section "JavaScript Libraries"
declare -A JS_PATTERNS=(
  ["jQuery"]="jquery[-/]([0-9]+\.[0-9]+\.[0-9]+)"
  ["React"]="react[-./]([0-9]+\.[0-9]+\.[0-9]+)|__react"
  ["Angular"]="angular[-./]([0-9]+\.[0-9]+)|ng-version"
  ["Vue.js"]="vue[-./]([0-9]+\.[0-9]+)"
  ["Bootstrap"]="bootstrap[-./]([0-9]+\.[0-9]+)"
  ["Lodash"]="lodash[-./]([0-9]+\.[0-9]+)"
  ["Moment.js"]="moment[-./]([0-9]+\.[0-9]+)"
  ["Chart.js"]="chart[-./]([0-9]+\.[0-9]+)"
  ["Webpack"]="webpack"
  ["Next.js"]="__next|_next/static"
  ["Nuxt.js"]="__nuxt|_nuxt/"
  ["HTMX"]="htmx[@/]([0-9]+)"
)

for lib in "${!JS_PATTERNS[@]}"; do
  PAT="${JS_PATTERNS[$lib]}"
  if echo "$RESP" | grep -iqE "$PAT"; then
    VER=$(echo "$RESP" | grep -ioE "$PAT" | head -1 | grep -oP '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    echo -e "  ${GREEN}[JS]${RESET}  ${BOLD}${lib}${RESET}  ${GRAY}${VER:+v$VER}${RESET}"
    log_report "[JS] $lib ${VER:+v$VER}"
  fi
done

# ── CDN / Cloud Detection ─────────────────────────────────────────────────────
section "CDN & Cloud Detection"
CDN_HEADERS="cf-ray|x-amz-cf|x-fastly|x-cache|x-azure|x-cdn"
CDN=$(echo "$HEADERS" | grep -iE "$CDN_HEADERS" | head -5)
if [[ -n "$CDN" ]]; then
  echo "$CDN" | while IFS= read -r h; do
    echo -e "  ${CYAN}[CDN]${RESET}  $h"
    log_report "[CDN] $h"
  done
  if echo "$CDN" | grep -qi "cf-ray"; then
    info "Cloudflare detected — real IP may be hidden."
  fi
else
  info "No CDN headers detected."
fi

# ── Security Indicators ───────────────────────────────────────────────────────
section "Security Indicators"

# WAF detection
WAF_INDICATORS="x-sucuri|x-protected-by|x-waf|server:.*cloudflare|x-mod-security|x-firewall"
if echo "$HEADERS" | grep -iqE "$WAF_INDICATORS"; then
  success "WAF / Protection layer detected $(risk_badge INFO)"
  log_report "[WAF] Detected"
else
  warn "No WAF indicators detected $(risk_badge INFO)"
fi

# Debug mode
if echo "$RESP $HEADERS" | grep -iqE "debug=true|APP_DEBUG|Traceback|stack trace|SQL error|Fatal error|Parse error"; then
  error "Debug information may be exposed $(risk_badge HIGH)"
  log_report "[FINDING] Debug/error info exposed"
fi

# Sensitive files hint
for path in robots.txt sitemap.xml .git/HEAD .env crossdomain.xml phpinfo.php; do
  CODE=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${TARGET%/}/$path" 2>/dev/null)
  if [[ "$CODE" == "200" ]]; then
    warn "Accessible: ${BOLD}${TARGET%/}/$path${RESET}  $(risk_badge MEDIUM)"
    log_report "[ACCESSIBLE] $path"
  fi
done

# ── Meta Info ─────────────────────────────────────────────────────────────────
section "Page Metadata"
TITLE=$(echo "$RESP" | grep -ioP '(?<=<title>)[^<]+' | head -1)
GENERATOR=$(echo "$RESP" | grep -ioP '(?<=name="generator" content=")[^"]+' | head -1)
DESCRIPTION=$(echo "$RESP" | grep -ioP '(?<=name="description" content=")[^"]+' | head -1 | cut -c1-80)

[[ -n "$TITLE" ]]       && info "Title:       ${BOLD}$TITLE${RESET}"
[[ -n "$GENERATOR" ]]   && info "Generator:   ${BOLD}$GENERATOR${RESET}" && log_report "[META] Generator: $GENERATOR"
[[ -n "$DESCRIPTION" ]] && info "Description: $DESCRIPTION"

echo ""
save_report
