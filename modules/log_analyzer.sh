#!/usr/bin/env bash
# modules/log_analyzer.sh — Security Log Analyzer

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/utils.sh"

section "Security Log Analyzer"

echo -e "  Analyze web/auth logs for attacks, anomalies, and suspicious patterns."
echo ""
echo -e "  ${GREEN}[1]${RESET}  Analyze web server log (Apache/Nginx)"
echo -e "  ${GREEN}[2]${RESET}  Analyze auth/syslog (/var/log/auth.log)"
echo -e "  ${GREEN}[3]${RESET}  Custom log file"
echo -e "  ${GREEN}[4]${RESET}  Demo (generate sample analysis)"
echo ""
echo -ne "  ${BOLD}${WHITE}Choose: ${RESET}"
read -r MODE

case "$MODE" in
  1)
    CANDIDATES=("/var/log/apache2/access.log" "/var/log/nginx/access.log"
                "/var/log/httpd/access_log" "/usr/local/apache2/logs/access_log")
    LOG_FILE=""
    for f in "${CANDIDATES[@]}"; do
      [[ -f "$f" ]] && LOG_FILE="$f" && break
    done
    if [[ -z "$LOG_FILE" ]]; then
      echo -ne "  ${BOLD}${WHITE}Enter web log path: ${RESET}"
      read -r LOG_FILE
    fi
    LOG_TYPE="web"
    ;;
  2)
    CANDIDATES=("/var/log/auth.log" "/var/log/secure" "/var/log/syslog")
    LOG_FILE=""
    for f in "${CANDIDATES[@]}"; do
      [[ -f "$f" ]] && LOG_FILE="$f" && break
    done
    if [[ -z "$LOG_FILE" ]]; then
      echo -ne "  ${BOLD}${WHITE}Enter auth log path: ${RESET}"
      read -r LOG_FILE
    fi
    LOG_TYPE="auth"
    ;;
  3)
    echo -ne "  ${BOLD}${WHITE}Enter log file path: ${RESET}"
    read -r LOG_FILE
    LOG_TYPE="web"
    ;;
  4)
    # Demo mode
    LOG_FILE="/tmp/sq8_demo_access.log"
    LOG_TYPE="web"
    cat > "$LOG_FILE" << 'DEMO'
192.168.1.100 - - [01/Mar/2024:10:00:01 +0000] "GET /index.php HTTP/1.1" 200 1234
10.0.0.1 - - [01/Mar/2024:10:00:02 +0000] "GET /../../../etc/passwd HTTP/1.1" 404 567
10.0.0.1 - - [01/Mar/2024:10:00:03 +0000] "GET /../../../etc/shadow HTTP/1.1" 404 567
45.33.32.156 - - [01/Mar/2024:10:00:04 +0000] "GET /admin/config.php HTTP/1.1" 403 123
45.33.32.156 - - [01/Mar/2024:10:00:05 +0000] "POST /login.php HTTP/1.1" 401 89
45.33.32.156 - - [01/Mar/2024:10:00:06 +0000] "POST /login.php HTTP/1.1" 401 89
45.33.32.156 - - [01/Mar/2024:10:00:07 +0000] "POST /login.php HTTP/1.1" 401 89
45.33.32.156 - - [01/Mar/2024:10:00:08 +0000] "POST /login.php HTTP/1.1" 401 89
45.33.32.156 - - [01/Mar/2024:10:00:09 +0000] "POST /login.php HTTP/1.1" 200 1500
203.0.113.42 - - [01/Mar/2024:10:01:00 +0000] "GET /wp-admin/admin-ajax.php?action=<script>alert(1)</script> HTTP/1.1" 200 450
203.0.113.42 - - [01/Mar/2024:10:01:01 +0000] "GET /page?id=1+UNION+SELECT+1,2,3-- HTTP/1.1" 200 890
203.0.113.42 - - [01/Mar/2024:10:01:02 +0000] "GET /page?id=1;DROP+TABLE+users;-- HTTP/1.1" 500 102
198.51.100.7 - - [01/Mar/2024:10:02:00 +0000] "GET /.env HTTP/1.1" 200 345
198.51.100.7 - - [01/Mar/2024:10:02:01 +0000] "GET /config.php.bak HTTP/1.1" 200 2200
198.51.100.7 - - [01/Mar/2024:10:02:02 +0000] "GET /.git/HEAD HTTP/1.1" 200 100
192.168.1.5  - - [01/Mar/2024:10:03:00 +0000] "GET /page HTTP/1.1" 200 4321
DEMO
    info "Demo log created: $LOG_FILE"
    ;;
  *)
    error "Invalid mode."
    exit 1
    ;;
esac

[[ ! -f "$LOG_FILE" ]] && error "File not found: $LOG_FILE" && exit 1

LINES=$(wc -l < "$LOG_FILE")
info "Analyzing: ${BOLD}$LOG_FILE${RESET}  (${BOLD}$LINES${RESET} lines)"
init_report "log_analyzer" "$(basename "$LOG_FILE")"

# ── Web Log Analysis ──────────────────────────────────────────────────────────
if [[ "$LOG_TYPE" == "web" ]]; then

  # ── Status Codes ────────────────────────────────────────────────────────
  section "HTTP Status Code Distribution"
  awk '{print $9}' "$LOG_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -20 | \
  while read -r count code; do
    case "${code:0:1}" in
      2) COLOR="$GREEN" ;;
      3) COLOR="$CYAN" ;;
      4) COLOR="$YELLOW" ;;
      5) COLOR="$RED" ;;
      *) COLOR="$GRAY" ;;
    esac
    printf "  ${COLOR}%-6s${RESET}  %6s requests\n" "$code" "$count"
    log_report "HTTP $code: $count requests"
  done

  # ── Top IPs ──────────────────────────────────────────────────────────────
  section "Top Requesting IPs"
  awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -15 | \
  while read -r count ip; do
    if [[ $count -gt 100 ]]; then
      echo -e "  ${RED}[HIGH]${RESET}  $ip  ${BOLD}$count${RESET} requests"
    elif [[ $count -gt 20 ]]; then
      echo -e "  ${YELLOW}[MED]${RESET}   $ip  ${BOLD}$count${RESET} requests"
    else
      echo -e "  ${GRAY}[LOW]${RESET}   $ip  ${BOLD}$count${RESET} requests"
    fi
    log_report "IP $ip: $count requests"
  done

  # ── Attack Pattern Detection ─────────────────────────────────────────────
  section "Attack Pattern Detection"

  SCAN_PATTERNS=(
    "SQL Injection:UNION.SELECT|SELECT.FROM|DROP.TABLE|INSERT.INTO|UPDATE.*SET|OR.1=1|AND.1=1|sqlmap|SLEEP\(|BENCHMARK\("
    "XSS:<script|javascript:|onerror=|onload=|alert\(|document\.cookie|<img.*onerror"
    "Path Traversal:\.\./|%2e%2e|etc/passwd|etc/shadow|boot\.ini|win\.ini"
    "Sensitive Files:\.env|\.git/|config\.php|backup\.|\.bak|phpinfo|\.htpasswd|web\.config"
    "Scanner/Bot:nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirsearch|gobuster|ffuf|wfuzz"
    "Shell/RCE:cmd=|exec\(|system\(|passthru|eval\(|base64_decode|php://|data://"
    "Brute Force (401):\" 401 "
    "Server Errors (5xx):\" 5[0-9][0-9] "
  )

  for pattern_entry in "${SCAN_PATTERNS[@]}"; do
    label="${pattern_entry%%:*}"
    pattern="${pattern_entry#*:}"
    COUNT=$(grep -icE "$pattern" "$LOG_FILE" 2>/dev/null || echo 0)
    if [[ "$COUNT" -gt 0 ]]; then
      if [[ "$COUNT" -gt 50 ]]; then
        error "${BOLD}${label}${RESET}: ${RED}$COUNT${RESET} events detected $(risk_badge HIGH)"
      elif [[ "$COUNT" -gt 10 ]]; then
        warn "${BOLD}${label}${RESET}: ${YELLOW}$COUNT${RESET} events detected $(risk_badge MEDIUM)"
      else
        warn "${BOLD}${label}${RESET}: ${GRAY}$COUNT${RESET} events $(risk_badge LOW)"
      fi
      log_report "[ATTACK] $label: $COUNT events"

      # Show sample lines
      grep -iE "$pattern" "$LOG_FILE" 2>/dev/null | head -3 | while IFS= read -r sample; do
        echo -e "    ${GRAY}↳ ${sample:0:120}${RESET}"
      done
    fi
  done

  # ── Brute Force Detection ────────────────────────────────────────────────
  section "Brute-Force Detection (401 floods)"
  awk '$9 == "401" {print $1}' "$LOG_FILE" 2>/dev/null | sort | uniq -c | sort -rn | \
  awk '$1 > 5' | while read -r count ip; do
    error "Possible brute force from ${BOLD}$ip${RESET}: $count failed auth attempts $(risk_badge HIGH)"
    log_report "[BRUTE-FORCE] $ip: $count 401 responses"
  done

# ── Auth Log Analysis ─────────────────────────────────────────────────────────
else
  section "Failed Login Attempts"
  grep -iE "Failed password|authentication failure|Invalid user" "$LOG_FILE" 2>/dev/null | \
    awk '{
      for(i=1;i<=NF;i++) {
        if ($i == "from") { ip=$(i+1) }
        if ($i == "user" || $i == "for") { usr=$(i+1) }
      }
      print ip, usr
    }' | sort | uniq -c | sort -rn | head -20 | while read -r count ip user; do
    echo -e "  ${RED}[$count attempts]${RESET}  IP: ${BOLD}$ip${RESET}  User: ${GRAY}$user${RESET}"
    log_report "[FAILED-AUTH] $ip user=$user count=$count"
  done

  section "Successful Logins"
  grep -iE "Accepted password|Accepted publickey|session opened" "$LOG_FILE" 2>/dev/null | \
    tail -20 | while IFS= read -r line; do
    echo -e "  ${GREEN}→${RESET}  $line"
    log_report "[AUTH-OK] $line"
  done

  section "Sudo Activity"
  grep -i "sudo:" "$LOG_FILE" 2>/dev/null | tail -15 | while IFS= read -r line; do
    echo -e "  ${YELLOW}→${RESET}  $line"
    log_report "[SUDO] $line"
  done
fi

# ── Summary ───────────────────────────────────────────────────────────────────
section "Analysis Complete"
success "Log file processed: ${BOLD}$LINES${RESET} lines"
echo ""
save_report
