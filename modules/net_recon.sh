#!/usr/bin/env bash
# modules/net_recon.sh — Network Reconnaissance Module

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/utils.sh"

section "Network Reconnaissance"

TARGET=$(get_target "Enter target IP or domain")
init_report "net_recon" "$TARGET"

# Resolve if domain
if is_domain "$TARGET"; then
  IP=$(resolve_ip "$TARGET")
  info "Resolved ${BOLD}$TARGET${RESET} → ${BOLD}${IP:-could not resolve}${RESET}"
  log_report "Domain: $TARGET"
  log_report "Resolved IP: ${IP:-N/A}"
else
  IP="$TARGET"
  log_report "Target IP: $IP"
fi

echo ""

# ── 1. Ping Test ──────────────────────────────────────────────────────────────
section "Ping & Reachability"
if ping -c 3 -W 2 "$TARGET" &>/dev/null; then
  RTT=$(ping -c 3 "$TARGET" 2>/dev/null | tail -1 | awk -F '/' '{print $5}' 2>/dev/null)
  success "Host is reachable  ${GRAY}(avg RTT: ${RTT}ms)${RESET}"
  log_report "[REACHABILITY] Host UP — avg RTT: ${RTT}ms"
else
  warn "Host appears unreachable or ICMP is blocked."
  log_report "[REACHABILITY] Host DOWN or ICMP blocked"
fi

# ── 2. Traceroute ─────────────────────────────────────────────────────────────
section "Route Tracing"
if optional_tool traceroute; then
  info "Tracing route (max 15 hops)..."
  echo ""
  traceroute -m 15 -w 2 "$TARGET" 2>/dev/null | while IFS= read -r line; do
    echo -e "  ${GRAY}$line${RESET}"
    log_report "$line"
  done
else
  info "Trying tracepath fallback..."
  tracepath -m 15 "$TARGET" 2>/dev/null | head -20 | while IFS= read -r line; do
    echo -e "  ${GRAY}$line${RESET}"
  done
fi

# ── 3. ARP Table ─────────────────────────────────────────────────────────────
section "Local ARP Table"
arp -a 2>/dev/null | while IFS= read -r line; do
  echo -e "  ${GRAY}$line${RESET}"
  log_report "$line"
done

# ── 4. Network Interfaces ─────────────────────────────────────────────────────
section "Active Network Interfaces"
ip addr show 2>/dev/null | grep -E "inet|^[0-9]+" | while IFS= read -r line; do
  if [[ "$line" =~ ^[0-9]+ ]]; then
    echo -e "  ${BOLD}${CYAN}$line${RESET}"
  else
    echo -e "    ${GREEN}$line${RESET}"
  fi
  log_report "$line"
done

# ── 5. Routing Table ─────────────────────────────────────────────────────────
section "Routing Table"
ip route 2>/dev/null | while IFS= read -r line; do
  echo -e "  ${GRAY}$line${RESET}"
  log_report "$line"
done

# ── 6. Open Connections ───────────────────────────────────────────────────────
section "Active Network Connections"
ss -tunp 2>/dev/null | head -30 | while IFS= read -r line; do
  if echo "$line" | grep -q "ESTABLISHED"; then
    echo -e "  ${GREEN}$line${RESET}"
  elif echo "$line" | grep -q "LISTEN"; then
    echo -e "  ${YELLOW}$line${RESET}"
  else
    echo -e "  ${GRAY}$line${RESET}"
  fi
  log_report "$line"
done

echo ""
save_report
