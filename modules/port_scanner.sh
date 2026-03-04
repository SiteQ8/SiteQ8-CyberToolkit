#!/usr/bin/env bash
# modules/port_scanner.sh — Advanced Port Scanner Module

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/utils.sh"

section "Port Scanner"

TARGET=$(get_target "Enter target IP or domain")
init_report "port_scanner" "$TARGET"

echo -ne "  ${BOLD}${WHITE}Scan mode [1=Common 2=Full 3=Custom]: ${RESET}"
read -r MODE

case "$MODE" in
  2) PORT_RANGE="1-65535" ; label="Full (1–65535)" ;;
  3) echo -ne "  ${BOLD}${WHITE}Enter port range (e.g. 20-1000): ${RESET}"; read -r PORT_RANGE; label="Custom ($PORT_RANGE)" ;;
  *) PORT_RANGE="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1723,3306,3389,5900,8080,8443,8888,27017"; label="Common Ports" ;;
esac

info "Scan mode: ${BOLD}$label${RESET}"
log_report "Target: $TARGET"
log_report "Scan mode: $label"
echo ""

# ─── Nmap Primary Scanner ────────────────────────────────────────────────────
if optional_tool nmap; then
  section "Nmap Scan"
  info "Running nmap — this may take a moment..."
  echo ""

  if [[ "$MODE" == "2" ]]; then
    NMAP_ARGS="-T4 -p-"
  else
    NMAP_ARGS="-T4 -p $PORT_RANGE"
  fi

  nmap $NMAP_ARGS -sV --open -oG - "$TARGET" 2>/dev/null | \
  while IFS= read -r line; do
    if echo "$line" | grep -q "open"; then
      port=$(echo "$line" | grep -oP '\d+/open' | head -1)
      svc=$(echo "$line" | grep -oP '(?<=open/)[^\s]+' | head -1)
      echo -e "  ${GREEN}[OPEN]${RESET}  Port ${BOLD}${port%%/*}${RESET}  ${GRAY}$svc${RESET}"
      log_report "[OPEN] $port $svc"
    fi
  done

  echo ""
  info "Running service version detection..."
  nmap $NMAP_ARGS -sV --version-intensity 5 "$TARGET" 2>/dev/null | \
    grep -E "^[0-9]+/|open|filtered" | while IFS= read -r line; do
    echo -e "  ${GRAY}$line${RESET}"
    log_report "$line"
  done

else
  # ─── Fallback: Bash /dev/tcp Scanner ─────────────────────────────────────
  section "TCP Port Scan (bash fallback)"
  warn "nmap not found — using built-in bash scanner (slower)."
  echo ""

  OPEN_COUNT=0

  scan_port() {
    local host="$1" port="$2"
    (echo >/dev/tcp/"$host"/"$port") &>/dev/null && return 0 || return 1
  }

  # Parse comma-separated or range
  if [[ "$PORT_RANGE" == *"-"* && "$PORT_RANGE" != *","* ]]; then
    START="${PORT_RANGE%-*}"
    END="${PORT_RANGE#*-}"
    PORTS=($(seq "$START" "$END"))
  else
    IFS=',' read -ra PORTS <<< "$PORT_RANGE"
  fi

  total=${#PORTS[@]}
  count=0

  for port in "${PORTS[@]}"; do
    count=$((count+1))
    printf "\r  ${CYAN}[*]${RESET} Scanning port %-6s  [%d/%d]" "$port" "$count" "$total"
    if scan_port "$TARGET" "$port" 2>/dev/null; then
      echo ""
      BANNER=$(timeout 2 bash -c "echo '' > /dev/tcp/$TARGET/$port && cat < /dev/tcp/$TARGET/$port" 2>/dev/null | head -2 | tr -d '\r\n')
      echo -e "  ${GREEN}[OPEN]${RESET}  Port ${BOLD}$port${RESET}  ${GRAY}${BANNER:0:60}${RESET}"
      log_report "[OPEN] Port $port | Banner: ${BANNER:0:60}"
      OPEN_COUNT=$((OPEN_COUNT+1))
    fi
  done

  printf "\r%-80s\n" ""
  echo ""
  success "Scan complete. Open ports found: ${BOLD}$OPEN_COUNT${RESET}"
fi

# ─── Service Risk Summary ─────────────────────────────────────────────────────
section "Known Service Risk Reference"
declare -A RISKY_PORTS=(
  [21]="FTP — Often allows anonymous login; use SFTP instead"
  [23]="Telnet — Unencrypted; credentials sent in plaintext"
  [25]="SMTP — Check for open relay vulnerability"
  [3389]="RDP — High-value brute-force target; restrict access"
  [1433]="MSSQL — Restrict to internal network only"
  [3306]="MySQL — Should never be publicly exposed"
  [27017]="MongoDB — Notorious for public exposure incidents"
  [5900]="VNC — Weak auth by default; often exploited"
  [445]="SMB — EternalBlue/WannaCry vector; patch immediately"
)

for p in "${!RISKY_PORTS[@]}"; do
  echo -e "  ${YELLOW}Port $p${RESET}  →  ${GRAY}${RISKY_PORTS[$p]}${RESET}"
done

echo ""
save_report
