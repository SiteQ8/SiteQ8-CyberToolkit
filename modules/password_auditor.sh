#!/usr/bin/env bash
# modules/password_auditor.sh — Password Strength & Policy Auditor

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/utils.sh"

section "Password Auditor"

echo -e "  ${GRAY}Analyze password strength, entropy, policy compliance, and"
echo -e "  check common breach patterns — no data leaves your machine.${RESET}"
echo ""

# ── Common Passwords List (top 100) ──────────────────────────────────────────
COMMON_PASSWORDS=(
  "123456" "password" "123456789" "12345678" "12345" "1234567" "1234567890"
  "qwerty" "abc123" "111111" "123123" "admin" "letmein" "welcome" "monkey"
  "1234" "dragon" "master" "sunshine" "princess" "hello" "shadow" "superman"
  "michael" "football" "baseball" "trustno1" "password1" "iloveyou" "login"
  "pass" "test" "guest" "root" "toor" "admin123" "pass123" "changeme"
  "default" "secret" "hunter2" "access" "batman" "qwerty123" "passw0rd"
  "password123" "p@ssword" "p@ss123" "P@ssword" "Passw0rd!" "Welcome1"
)

# ── Analyze Single Password ───────────────────────────────────────────────────
analyze_password() {
  local PASS="$1"
  local SCORE=0
  local MAX=10
  local ISSUES=()
  local PASSES=()

  LEN=${#PASS}

  echo ""
  section "Password Analysis"

  # Common check
  IS_COMMON=false
  for cp in "${COMMON_PASSWORDS[@]}"; do
    if [[ "${PASS,,}" == "${cp,,}" ]]; then
      IS_COMMON=true; break
    fi
  done

  if $IS_COMMON; then
    error "Password found in common password list $(risk_badge HIGH)"
    echo ""
    return
  fi

  # ── Length ────────────────────────────────────────────────────────────────
  if [[ $LEN -lt 8 ]]; then
    ISSUES+=("Too short (${LEN} chars; min recommended: 12)")
  elif [[ $LEN -lt 12 ]]; then
    SCORE=$((SCORE+2))
    ISSUES+=("Length acceptable but 12+ chars strongly recommended")
  elif [[ $LEN -lt 16 ]]; then
    SCORE=$((SCORE+3))
    PASSES+=("Good length (${LEN} chars)")
  else
    SCORE=$((SCORE+4))
    PASSES+=("Excellent length (${LEN} chars)")
  fi

  # ── Character Classes ────────────────────────────────────────────────────
  HAS_LOWER=false; HAS_UPPER=false; HAS_DIGIT=false; HAS_SPECIAL=false
  [[ "$PASS" =~ [a-z] ]] && HAS_LOWER=true  && SCORE=$((SCORE+1)) && PASSES+=("Contains lowercase")
  [[ "$PASS" =~ [A-Z] ]] && HAS_UPPER=true  && SCORE=$((SCORE+1)) && PASSES+=("Contains uppercase")
  [[ "$PASS" =~ [0-9] ]] && HAS_DIGIT=true  && SCORE=$((SCORE+1)) && PASSES+=("Contains digits")
  [[ "$PASS" =~ [^a-zA-Z0-9] ]] && HAS_SPECIAL=true && SCORE=$((SCORE+2)) && PASSES+=("Contains special characters")

  $HAS_LOWER   || ISSUES+=("No lowercase letters")
  $HAS_UPPER   || ISSUES+=("No uppercase letters")
  $HAS_DIGIT   || ISSUES+=("No digits")
  $HAS_SPECIAL || ISSUES+=("No special characters — add !, @, #, $ etc.")

  # ── Entropy Estimate ─────────────────────────────────────────────────────
  CHARSET=0
  $HAS_LOWER   && CHARSET=$((CHARSET+26))
  $HAS_UPPER   && CHARSET=$((CHARSET+26))
  $HAS_DIGIT   && CHARSET=$((CHARSET+10))
  $HAS_SPECIAL && CHARSET=$((CHARSET+32))

  if [[ $CHARSET -gt 0 ]]; then
    # entropy = len * log2(charset) ≈ len * ln(charset)/ln(2)
    # Using awk for float
    ENTROPY=$(awk "BEGIN {printf \"%.1f\", $LEN * log($CHARSET)/log(2)}")
    info "Estimated entropy: ${BOLD}${ENTROPY} bits${RESET}"
    if awk "BEGIN {exit ($ENTROPY < 40) ? 0 : 1}"; then
      ISSUES+=("Low entropy (${ENTROPY} bits) — easily brute-forced")
    elif awk "BEGIN {exit ($ENTROPY < 60) ? 0 : 1}"; then
      PASSES+=("Moderate entropy (${ENTROPY} bits)")
      SCORE=$((SCORE+1))
    else
      PASSES+=("High entropy (${ENTROPY} bits)")
      SCORE=$((SCORE+2))
    fi
  fi

  # ── Pattern Detection ────────────────────────────────────────────────────
  if echo "$PASS" | grep -qiE "^(qwerty|asdf|zxcv|abc|123|111|000)"; then
    ISSUES+=("Starts with keyboard pattern — predictable")
    SCORE=$((SCORE-1))
  fi
  if echo "$PASS" | grep -qiE "(password|passwd|pass|admin|user|login|secure|qwerty)"; then
    ISSUES+=("Contains dictionary word — weaker against dictionary attacks")
    SCORE=$((SCORE-1))
  fi
  if echo "$PASS" | grep -qE "(.)\1{2,}"; then
    ISSUES+=("Repeated characters detected (e.g. 'aaa')")
    SCORE=$((SCORE-1))
  fi

  # ── Score Bar ────────────────────────────────────────────────────────────
  SCORE=$(( SCORE < 0 ? 0 : SCORE > MAX ? MAX : SCORE ))
  PCT=$((SCORE * 100 / MAX))
  BAR_FULL=$((SCORE * 20 / MAX))
  BAR_EMPTY=$((20 - BAR_FULL))

  echo ""
  printf "  Strength: ["
  if [[ $SCORE -le 3 ]]; then
    for ((i=0;i<BAR_FULL;i++)); do printf "${RED}█${RESET}"; done
  elif [[ $SCORE -le 6 ]]; then
    for ((i=0;i<BAR_FULL;i++)); do printf "${YELLOW}█${RESET}"; done
  else
    for ((i=0;i<BAR_FULL;i++)); do printf "${GREEN}█${RESET}"; done
  fi
  for ((i=0;i<BAR_EMPTY;i++)); do printf "${GRAY}░${RESET}"; done
  printf "]  ${BOLD}%d/%d${RESET}\n\n" "$SCORE" "$MAX"

  if [[ $SCORE -le 3 ]]; then
    error "Strength: ${BOLD}WEAK${RESET} $(risk_badge HIGH)"
  elif [[ $SCORE -le 6 ]]; then
    warn "Strength: ${BOLD}MODERATE${RESET} $(risk_badge MEDIUM)"
  elif [[ $SCORE -le 8 ]]; then
    success "Strength: ${BOLD}STRONG${RESET}"
  else
    success "Strength: ${BOLD}VERY STRONG${RESET}"
  fi

  # ── Positive Indicators ──────────────────────────────────────────────────
  if [[ ${#PASSES[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${GREEN}Positive Indicators:${RESET}"
    for p in "${PASSES[@]}"; do
      echo -e "  ${GREEN}  ✓${RESET}  $p"
    done
  fi

  # ── Issues ───────────────────────────────────────────────────────────────
  if [[ ${#ISSUES[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${RED}Issues Found:${RESET}"
    for issue in "${ISSUES[@]}"; do
      echo -e "  ${RED}  ✗${RESET}  $issue"
    done
  fi

  # ── Crack Time Estimate ──────────────────────────────────────────────────
  section "Estimated Crack Time"
  if [[ -n "$ENTROPY" ]]; then
    # guesses/sec at different speeds
    awk -v e="$ENTROPY" 'BEGIN {
      combos = 2^e
      printf "  Online attack  (1K/s):   "
      secs = combos / 1000
      if (secs < 60) printf "%.0f seconds\n", secs
      else if (secs < 3600) printf "%.1f minutes\n", secs/60
      else if (secs < 86400) printf "%.1f hours\n", secs/3600
      else if (secs < 2592000) printf "%.1f days\n", secs/86400
      else if (secs < 31536000) printf "%.1f months\n", secs/2592000
      else printf "%.1f years\n", secs/31536000

      printf "  Offline attack (1B/s):   "
      secs = combos / 1000000000
      if (secs < 60) printf "%.0f seconds\n", secs
      else if (secs < 3600) printf "%.1f minutes\n", secs/60
      else if (secs < 86400) printf "%.1f hours\n", secs/3600
      else if (secs < 2592000) printf "%.1f days\n", secs/86400
      else if (secs < 31536000) printf "%.1f months\n", secs/2592000
      else printf "%.1f years\n", secs/31536000

      printf "  GPU cluster    (1T/s):   "
      secs = combos / 1000000000000
      if (secs < 60) printf "%.0f seconds\n", secs
      else if (secs < 3600) printf "%.1f minutes\n", secs/60
      else if (secs < 86400) printf "%.1f hours\n", secs/3600
      else if (secs < 2592000) printf "%.1f days\n", secs/86400
      else if (secs < 31536000) printf "%.1f months\n", secs/2592000
      else printf "%.1f years\n", secs/31536000
    }'
  fi
}

# ── Batch File Audit ──────────────────────────────────────────────────────────
batch_audit() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    error "File not found: $file"
    return
  fi

  section "Batch Password Audit: $file"
  WEAK=0; MOD=0; STRONG=0; TOTAL_B=0

  while IFS= read -r pass; do
    [[ -z "$pass" || "$pass" == "#"* ]] && continue
    TOTAL_B=$((TOTAL_B+1))
    LEN=${#pass}
    HAS_SPECIAL=false; HAS_UPPER=false; HAS_DIGIT=false
    [[ "$pass" =~ [A-Z] ]] && HAS_UPPER=true
    [[ "$pass" =~ [0-9] ]] && HAS_DIGIT=true
    [[ "$pass" =~ [^a-zA-Z0-9] ]] && HAS_SPECIAL=true

    S=0
    [[ $LEN -ge 12 ]] && S=$((S+3)) || [[ $LEN -ge 8 ]] && S=$((S+1))
    $HAS_UPPER   && S=$((S+1))
    $HAS_DIGIT   && S=$((S+1))
    $HAS_SPECIAL && S=$((S+2))

    if [[ $S -le 3 ]]; then
      error "WEAK:   $pass"
      WEAK=$((WEAK+1))
    elif [[ $S -le 6 ]]; then
      warn "MEDIUM: $pass"
      MOD=$((MOD+1))
    else
      success "STRONG: $pass"
      STRONG=$((STRONG+1))
    fi
  done < "$file"

  echo ""
  info "Total: $TOTAL_B  |  Weak: ${RED}$WEAK${RESET}  |  Medium: ${YELLOW}$MOD${RESET}  |  Strong: ${GREEN}$STRONG${RESET}"
}

# ── Mode Select ───────────────────────────────────────────────────────────────
echo -e "  ${BOLD}Mode:${RESET}"
echo -e "  ${GREEN}[1]${RESET}  Analyze a single password"
echo -e "  ${GREEN}[2]${RESET}  Audit a password list file"
echo -ne "\n  ${BOLD}${WHITE}Choose: ${RESET}"
read -r MODE

case "$MODE" in
  2)
    echo -ne "  ${BOLD}${WHITE}Path to password file: ${RESET}"
    read -r PFILE
    batch_audit "$PFILE"
    ;;
  *)
    echo -ne "  ${BOLD}${WHITE}Enter password to analyze: ${RESET}"
    read -rs PWORD
    echo ""
    analyze_password "$PWORD"
    ;;
esac

echo ""
