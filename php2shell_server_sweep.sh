#!/usr/bin/env bash
# php2shell_server_sweep.sh - READ-ONLY host triage for PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619) and Nextcloud Collabora CODE
# (CVE-2026-110447) exploitation.
#
# Apache access logs cannot see a PHP2Shell exploit (it rides in the POST body,
# before any app code) and cannot confirm command execution for the Nextcloud
# flaw. This script looks on the host itself, where those answers live.
#
# SAFE TO RUN ON PRODUCTION: it only reads. It never deletes, kills, quarantines,
# modifies a file, or changes configuration. Every "action" is a suggestion
# printed for a human to carry out. Run it as root (or via sudo) for complete
# results; as a normal user it still runs but skips checks it has no rights for.
#
# Usage:
#   sudo ./php2shell_server_sweep.sh                      # auto-detect everything
#   sudo ./php2shell_server_sweep.sh --nc-path /var/www/nextcloud
#   sudo ./php2shell_server_sweep.sh --webroot /var/www --since 2026-09-01
#   sudo ./php2shell_server_sweep.sh --no-occ             # skip Nextcloud occ calls
#   sudo ./php2shell_server_sweep.sh --json report.json   # also write JSON
#
# Exit code: 0 = nothing flagged, 1 = review items (WARN), 2 = likely
#            compromise (CRIT), 3 = usage error.
#
# Tune the window with --since (default 2026-09-01, the start of the
# CVE-2026-110447 campaign). "Recently modified" checks use it as the cutoff.

set -u
LC_ALL=C
export LC_ALL

VERSION="1.1 (2026-10-23)"

# ----------------------------------------------------------------- settings --
SINCE="2026-09-01"
NC_PATH=""
WEBROOT=""
DO_OCC=1
DO_INTEGRITY=1
JSON=""
# Fixed PHP versions that carry the PHP2Shell patch, per branch.
FIXED_8_5="8.5.12"; FIXED_8_4="8.4.27"; FIXED_8_3="8.3.36"; FIXED_8_2="8.2.35"

# Common Nextcloud install roots (same list the exploit dropper sprayed).
NC_CANDIDATES="/var/www/nextcloud /var/www/html/nextcloud /var/www/html \
/var/www/cloud /var/www/html/cloud /opt/nextcloud /usr/share/nextcloud \
/var/snap/nextcloud/current/nextcloud /data/web/nextcloud /home/www/nextcloud \
/srv/nextcloud /srv/www/nextcloud"
# Temp/stage dirs that should never hold web-served PHP.
TMP_DIRS="/tmp /var/tmp /dev/shm"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-3}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --nc-path) NC_PATH="${2:-}"; shift 2 ;;
    --webroot) WEBROOT="${2:-}"; shift 2 ;;
    --since) SINCE="${2:-}"; shift 2 ;;
    --no-occ) DO_OCC=0; shift ;;
    --no-integrity) DO_INTEGRITY=0; shift ;;
    --json) JSON="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 3 ;;
  esac
done

# --------------------------------------------------------------- output ------
if [ -t 1 ]; then
  C_CRIT=$'\033[1;31m'; C_WARN=$'\033[1;33m'; C_OK=$'\033[1;32m'
  C_INFO=$'\033[1;34m'; C_HDR=$'\033[1;36m'; C_0=$'\033[0m'
else
  C_CRIT=""; C_WARN=""; C_OK=""; C_INFO=""; C_HDR=""; C_0=""
fi
n_crit=0; n_warn=0; n_info=0
JOUT=""

jadd() { # jadd SEVERITY RULE "message"
  [ -n "$JSON" ] || return 0
  local sev="$1" rule="$2" msg="$3"
  msg=$(printf '%s' "$msg" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' ')
  JOUT="${JOUT}{\"severity\":\"${sev}\",\"rule\":\"${rule}\",\"message\":\"${msg}\"},"
}
crit() { n_crit=$((n_crit+1)); printf '%s[CRIT]%s %s\n' "$C_CRIT" "$C_0" "$2"; jadd CRIT "$1" "$2"; }
warn() { n_warn=$((n_warn+1)); printf '%s[WARN]%s %s\n' "$C_WARN" "$C_0" "$2"; jadd WARN "$1" "$2"; }
info() { n_info=$((n_info+1)); printf '%s[INFO]%s %s\n' "$C_INFO" "$C_0" "$2"; jadd INFO "$1" "$2"; }
okay() { printf '%s[ OK ]%s %s\n' "$C_OK" "$C_0" "$1"; }
note() { printf '       %s\n' "$1"; }
section() { printf '\n%s== %s ==%s\n' "$C_HDR" "$1" "$C_0"; }

have() { command -v "$1" >/dev/null 2>&1; }

printf '%sphp2shell_server_sweep %s%s\n' "$C_HDR" "$VERSION" "$C_0"
printf 'host: %s   date: %s   window since: %s\n' "$(hostname 2>/dev/null)" "$(date 2>/dev/null)" "$SINCE"
[ "$(id -u 2>/dev/null)" = 0 ] || warn PRIV "Not running as root: some checks (processes of other users, sockets, /etc) will be incomplete. Re-run with sudo for full coverage."

# version-compare: is $1 < $2 ? (dotted numeric). returns 0 if strictly less.
ver_lt() {
  [ "$1" = "$2" ] && return 1
  local l; l=$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)
  [ "$l" = "$1" ]
}

# ---------------------------------------------------- resolve paths ----------
if [ -z "$NC_PATH" ]; then
  for c in $NC_CANDIDATES; do
    if [ -f "$c/occ" ] || [ -f "$c/version.php" ]; then NC_PATH="$c"; break; fi
  done
fi
if [ -z "$WEBROOT" ]; then
  if [ -n "$NC_PATH" ]; then WEBROOT="$NC_PATH"; else
    for c in /var/www/html /var/www /srv/www /usr/share/nginx/html; do
      [ -d "$c" ] && { WEBROOT="$c"; break; }
    done
  fi
fi
# Resolve the Nextcloud data directory once. It holds USER-uploaded files, so it
# is excluded from the app-code scans below (otherwise user .php uploads look
# like web shells) and reported only by its own dedicated check.
DATA_DIR=""
if [ -n "$NC_PATH" ] && [ -f "$NC_PATH/config/config.php" ] && have php; then
  DATA_DIR=$(php -r "include '$NC_PATH/config/config.php'; echo \$CONFIG['datadirectory']??'';" 2>/dev/null)
fi
[ -n "$DATA_DIR" ] || { [ -n "$NC_PATH" ] && [ -d "$NC_PATH/data" ] && DATA_DIR="$NC_PATH/data"; }
not_in_data() { if [ -n "$DATA_DIR" ]; then grep -vF "$DATA_DIR/"; else cat; fi; }

# ===================================================== 1. EXPOSURE ============
section "1. Exposure: PHP version and upload-progress setting"
if have php; then
  PHPV=$(php -r 'echo PHP_VERSION;' 2>/dev/null)
  branch=$(printf '%s' "$PHPV" | cut -d. -f1-2)
  case "$branch" in
    8.5) fixed="$FIXED_8_5" ;; 8.4) fixed="$FIXED_8_4" ;;
    8.3) fixed="$FIXED_8_3" ;; 8.2) fixed="$FIXED_8_2" ;;
    *) fixed="" ;;
  esac
  if [ -z "$fixed" ]; then
    crit PHPVER "PHP $PHPV is on an end-of-life branch with no official PHP2Shell fix. Treat as vulnerable; upgrade to a supported, patched branch."
  elif ver_lt "$PHPV" "$fixed"; then
    crit PHPVER "PHP $PHPV is OLDER than the patched $fixed on branch $branch -> vulnerable to PHP2Shell. Patch and restart the web workers."
  else
    okay "CLI PHP $PHPV >= $fixed (patched on branch $branch)."
  fi
  note "NOTE: this is the CLI PHP. The web SAPI (mod_php / php-fpm) can differ."
  note "Confirm the running web PHP: for fpm 'php-fpm -v'; for mod_php check the"
  note "loaded module, and ALWAYS confirm workers were restarted after patching."
  upr=$(php -r '@print(ini_get("session.upload_progress.enabled"));' 2>/dev/null)
  if [ "$upr" = "1" ] || [ "$upr" = "" ]; then
    info UPLOADPROG "session.upload_progress.enabled is on (CLI ini). It is the PHP2Shell vector; PHP's interim mitigation is to set it Off and restart workers (patching is the real fix). Confirm the web SAPI's php.ini, not just CLI."
  else
    okay "session.upload_progress.enabled is Off (CLI ini)."
  fi
else
  warn PHPVER "php CLI not found; check the web PHP version manually against 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35."
fi

# ===================================================== 2. LIVE PROCESSES ======
section "2. Live processes: web/PHP workers spawning shells or net tools"
# A snapshot only. A web worker (apache2/httpd/php-fpm/php-cgi/lsphp) whose child
# is a shell, interpreter or download tool is a classic post-exploitation sign.
if have ps; then
  procs=$(ps -eo pid,ppid,user,comm,args 2>/dev/null)
  parents=$(printf '%s\n' "$procs" | awk '$4 ~ /^(apache2|httpd|php-fpm|php-cgi|lsphp|php)$/ {print $1}')
  hit=0
  if [ -n "$parents" ]; then
    for ppid in $parents; do
      kids=$(printf '%s\n' "$procs" | awk -v p="$ppid" '$2==p')
      echo "$kids" | awk '{print $4}' | grep -Eq '^(sh|bash|dash|zsh|nc|ncat|netcat|curl|wget|python[0-9.]*|perl|ruby|socat|mkfifo)$' && {
        bad=$(printf '%s\n' "$kids" | grep -Ei '(^| )(sh|bash|dash|nc|ncat|netcat|curl|wget|python|perl|ruby|socat|mkfifo)( |$)')
        crit PROC-CHILD "Web/PHP worker (pid $ppid) has a suspicious child process: $(printf '%s' "$bad" | head -1 | cut -c1-160)"
        hit=1
      }
    done
  fi
  [ "$hit" = 0 ] && okay "No web/PHP worker seen spawning a shell or network tool right now (snapshot only)."
  note "This is a point-in-time snapshot; a short-lived reverse shell can be missed. Pair with auditd/EDR history if available."
else
  warn PROC-CHILD "ps not available; cannot inspect processes."
fi

# ===================================================== 3. OUTBOUND SOCKETS ====
section "3. Outbound connections from web/PHP workers"
if have ss; then
  out=$(ss -tnp 2>/dev/null | grep -Ei 'apache2|httpd|php-fpm|php-cgi|lsphp' | grep ESTAB)
  if [ -n "$out" ]; then
    # Loopback (Collabora/Redis/DB) is normal; external egress from a web worker is not.
    ext=$(printf '%s\n' "$out" | awk '{print $5}' | grep -Ev '^(127\.|\[::1\]|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)')
    if [ -n "$ext" ]; then
      crit NET-EGRESS "Web/PHP worker has ESTABLISHED outbound connection(s) to non-local addresses: $(printf '%s' "$ext" | tr '\n' ' ' | cut -c1-200)"
    else
      okay "Web/PHP worker sockets are all loopback/RFC1918 (normal: Collabora, DB, Redis)."
    fi
  else
    okay "No established outbound sockets owned by web/PHP workers."
  fi
else
  warn NET-EGRESS "ss not available; check outbound connections manually (lsof -i / netstat)."
fi

# ===================================================== 4. WEBSHELL FILES ======
section "4. Dropped web shells and recently-changed PHP"
# 4a. Campaign-specific shell names (CVE-2026-110447 + this engagement's drops).
shell_glob() { # dir
  find "$1" -xdev -type f \( \
    -iname 'sh[xr]f*.php' -o -iname 'shx*.php' -o -iname 'nx_*.php' \
    -o -iname 'noname*_.php' \) 2>/dev/null
}
# NC_PATH and WEBROOT frequently coincide; scan each distinct root once.
SCAN_ROOTS=$(for d in "$NC_PATH" "$WEBROOT"; do [ -n "$d" ] && [ -d "$d" ] && printf '%s\n' "$d"; done | awk '!seen[$0]++')
found_shell=0
for base in $SCAN_ROOTS; do
  [ -d "$base" ] || continue
  hits=$(shell_glob "$base")
  if [ -n "$hits" ]; then
    found_shell=1
    printf '%s\n' "$hits" | while IFS= read -r f; do
      crit WEBSHELL-FILE "Web-shell-named file present: $f ($(stat -c '%y' "$f" 2>/dev/null))"
    done
  fi
done
[ "$found_shell" = 0 ] && okay "No files matching known web-shell name patterns (shx*/shrf*/Nx_*/Noname*_.php)."

# 4b. ANY .php under the Nextcloud data dir - should never exist.
if [ -n "$NC_PATH" ]; then
  dd="$DATA_DIR"
  if [ -n "$dd" ] && [ -d "$dd" ]; then
    dphp=$(find "$dd" -xdev -type f -iname '*.php' 2>/dev/null | head -500)
    if [ -n "$dphp" ]; then
      cnt=$(printf '%s\n' "$dphp" | wc -l | tr -d ' ')
      warn DATA-PHP "$cnt PHP file(s) present under the Nextcloud data directory ($dd). This is often BENIGN: users can upload .php files as documents, and a default Nextcloud does not execute PHP under the data dir (it is outside the webroot and blocked by .htaccess). It is only dangerous if your web server is misconfigured to run PHP there. Review the list below - treat as serious only if the data dir is web-executable or a file looks like a planted shell:"
      printf '%s\n' "$dphp" | head -40 | while IFS= read -r f; do note "$(stat -c '%y  %s  %n' "$f" 2>/dev/null)"; done
      [ "$cnt" -gt 40 ] && note "... ($((cnt-40)) more; full list via: find \"$dd\" -type f -iname '*.php')"
      note "Confirm the data dir is NOT web-executable: a request to a .php under the data URL must NOT run it (expect 403/404/download)."
    else
      okay "No PHP files under the Nextcloud data directory ($dd)."
    fi
  fi
fi

# 4c. PHP files modified since the window, in webroot + temp dirs.
section "   PHP files modified since $SINCE"
rec=0
for base in "$WEBROOT" $TMP_DIRS; do
  [ -n "$base" ] && [ -d "$base" ] || continue
  newphp=$(find "$base" -xdev -type f -iname '*.php' -newermt "$SINCE" 2>/dev/null | not_in_data | head -200)
  if [ -n "$newphp" ]; then
    rec=1
    cnt=$(printf '%s\n' "$newphp" | wc -l | tr -d ' ')
    sev=warn; [ "$base" = /tmp ] || [ "$base" = /var/tmp ] || [ "$base" = /dev/shm ] && sev=crit
    $sev RECENT-PHP "$cnt PHP file(s) under $base modified since $SINCE (review against your deploy/update history):"
    printf '%s\n' "$newphp" | head -30 | while IFS= read -r f; do note "$(stat -c '%y %s %n' "$f" 2>/dev/null)"; done
    [ "$cnt" -gt 30 ] && note "... ($((cnt-30)) more)"
  fi
done
[ "$rec" = 0 ] && okay "No PHP files modified since $SINCE in webroot or temp dirs."
note "A Nextcloud/PHP upgrade in this window will also show here - correlate with your change log before alarming."

# ===================================================== 5. WEBSHELL CONTENT ====
section "5. Web-shell code signatures in the web tree"
if [ -n "$WEBROOT" ] && [ -d "$WEBROOT" ] && have grep; then
  # Tie a dangerous exec sink to request input on the same line -> low false positive.
  sig='(system|shell_exec|passthru|popen|proc_open|exec|eval|assert)[[:space:]]*\([^)]*\$_(GET|POST|REQUEST|COOKIE|SERVER)'
  scan=$(grep -rElI --include='*.php' -e "$sig" "$WEBROOT" 2>/dev/null | not_in_data | head -100)
  # Also the exact one-liners seen in this campaign.
  onel=$(grep -rElI --include='*.php' -e 'system(\$_GET\[c\]\?*)' -e "\\\$c=\\\$_GET\['c'\]" "$WEBROOT" 2>/dev/null | not_in_data | head -100)
  all=$(printf '%s\n%s\n' "$scan" "$onel" | sort -u | sed '/^$/d')
  if [ -n "$all" ]; then
    printf '%s\n' "$all" | while IFS= read -r f; do
      crit WEBSHELL-CODE "PHP file calls a command/eval sink on request input (possible web shell): $f"
    done
    note "Confirm by reading each file; some frameworks legitimately use these sinks, but a tiny standalone file in an app dir is almost always a shell."
  else
    okay "No PHP file in $WEBROOT pipes request input straight into a command/eval sink."
  fi
else
  warn WEBSHELL-CODE "Cannot scan web tree for shell signatures (no webroot or grep)."
fi

# ===================================================== 6. CALLBACKS ===========
section "6. Known callback indicators"
cbhit=0
for base in "$WEBROOT" /etc/cron.d /var/spool/cron "$NC_PATH"; do
  [ -n "$base" ] && [ -e "$base" ] || continue
  cb=$(grep -rIl --include='*' -e 'webhook\.site' "$base" 2>/dev/null | head -20)
  [ -n "$cb" ] && { cbhit=1; for f in $cb; do crit CALLBACK "Reference to webhook.site (known PHP2Shell/Collabora callback) in: $f"; done; }
done
[ "$cbhit" = 0 ] && okay "No reference to the known webhook.site callback on disk."

# ===================================================== 7. PERSISTENCE =========
section "7. Persistence: cron, accounts, SSH keys"
# 7a. cron entries referencing shells/network tools or recently changed.
cronbad=0
for cf in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
  [ -f "$cf" ] || continue
  if grep -Eq '(curl|wget|/dev/tcp/|nc |ncat|base64 -d|python -c|perl -e|bash -i)' "$cf" 2>/dev/null; then
    cronbad=1; warn CRON "Cron file $cf contains shell/network commands - review: $(grep -En '(curl|wget|/dev/tcp/|nc |ncat|base64 -d|python -c|perl -e|bash -i)' "$cf" 2>/dev/null | head -2 | tr '\n' ' ' | cut -c1-180)"
  fi
  if [ -n "$(find "$cf" -newermt "$SINCE" 2>/dev/null)" ]; then
    cronbad=1; info CRON "Cron file modified since $SINCE: $cf ($(stat -c '%y' "$cf" 2>/dev/null))"
  fi
done
# web-user crontab: judged by CONTENT, not mere existence. A www-data crontab
# running Nextcloud's own background job (php -f cron.php / occ / console.php)
# is normal and must not be flagged as compromise.
NC_CRON_OK='php[0-9.]*[[:space:]]+(-f[[:space:]]+)?[^[:space:]]*(cron\.php|occ|console\.php)([[:space:]]|$)'
CRON_EVIL='(curl|wget|/dev/tcp/|[[:space:]]nc[[:space:]]|ncat|base64[[:space:]]*-d|python[0-9.]*[[:space:]]*-c|perl[[:space:]]*-e|bash[[:space:]]*-i|\|[[:space:]]*sh([[:space:]]|$))'
for u in www-data apache nginx http; do
  wc="/var/spool/cron/crontabs/$u"; [ -f "$wc" ] || wc="/var/spool/cron/$u"
  [ -f "$wc" ] || continue
  active=$(grep -Ev '^[[:space:]]*(#|$)' "$wc" 2>/dev/null)
  [ -n "$active" ] || continue
  unexpected=$(printf '%s\n' "$active" | grep -Ev "$NC_CRON_OK")
  if printf '%s\n' "$active" | grep -Eq "$CRON_EVIL"; then
    cronbad=1; crit CRON "Web user ($u) crontab contains shell/network commands - inspect $wc: $(printf '%s' "$active" | grep -E "$CRON_EVIL" | head -2 | tr '\n' ' ' | cut -c1-180)"
  elif [ -n "$unexpected" ]; then
    cronbad=1; warn CRON "Web user ($u) crontab has entries beyond the normal Nextcloud background job - review $wc: $(printf '%s' "$unexpected" | head -2 | tr '\n' ' ' | cut -c1-180)"
  else
    info CRON "Web user ($u) crontab present and matches the normal Nextcloud background job ($wc) - benign."
  fi
done
[ "$cronbad" = 0 ] && okay "No suspicious or recently-changed cron entries found."

# 7b. accounts added since the window / shell users.
if [ -r /etc/passwd ]; then
  if [ -n "$(find /etc/passwd /etc/shadow -newermt "$SINCE" 2>/dev/null)" ]; then
    warn ACCOUNTS "/etc/passwd or /etc/shadow changed since $SINCE ($(stat -c '%y' /etc/passwd 2>/dev/null)) - review newly added users."
  else
    okay "/etc/passwd and /etc/shadow not modified since $SINCE."
  fi
  uid0=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd 2>/dev/null)
  [ -n "$uid0" ] && crit ACCOUNTS "Non-root account(s) with UID 0: $uid0"
fi

# 7c. SSH authorized_keys changed since the window.
akhit=0
for ak in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys \
          /var/www/.ssh/authorized_keys /home/*/.ssh/authorized_keys2; do
  [ -f "$ak" ] || continue
  if [ -n "$(find "$ak" -newermt "$SINCE" 2>/dev/null)" ]; then
    akhit=1; warn SSHKEYS "authorized_keys modified since $SINCE: $ak ($(stat -c '%y' "$ak" 2>/dev/null)) - verify every key is expected."
  fi
done
[ "$akhit" = 0 ] && okay "No authorized_keys modified since $SINCE."

# ===================================================== 8. NEXTCLOUD occ =======
section "8. Nextcloud application integrity (CVE-2026-110447)"
if [ -z "$NC_PATH" ]; then
  info NC "No Nextcloud install auto-detected; pass --nc-path if this host runs one."
else
  info NC "Nextcloud root: $NC_PATH"
  # pick the web user to run occ as
  ncuser=$(stat -c '%U' "$NC_PATH/occ" 2>/dev/null); [ -n "$ncuser" ] || ncuser=www-data
  occ() { if [ "$(id -un)" = "$ncuser" ]; then php "$NC_PATH/occ" "$@"; else sudo -u "$ncuser" php "$NC_PATH/occ" "$@"; fi; }
  # 8a. is the vulnerable app installed?
  if [ -d "$NC_PATH/apps/richdocumentscode" ]; then
    crit NC-APP "The vulnerable 'richdocumentscode' (Built-in CODE Server) app directory is PRESENT ($NC_PATH/apps/richdocumentscode). Update it to >= 26.4.303 or remove it; disabling is not enough."
    if [ "$DO_OCC" = 1 ] && have php; then
      ver=$(occ config:app:get richdocumentscode installed_version 2>/dev/null)
      [ -n "$ver" ] && note "Installed richdocumentscode version: $ver (fixed in 26.4.303)."
    fi
  else
    okay "The vulnerable 'richdocumentscode' app directory is not present."
  fi
  # 8b. integrity check -> EXTRA_FILE flags planted files.
  if [ "$DO_OCC" = 1 ] && [ "$DO_INTEGRITY" = 1 ] && have php; then
    note "Running occ integrity:check-core (may take a moment)..."
    ic=$(occ integrity:check-core 2>/dev/null)
    if printf '%s' "$ic" | grep -q 'EXTRA_FILE'; then
      crit NC-INTEGRITY "occ integrity:check-core reports EXTRA_FILE(s) - unexpected files in core, inspect: $(printf '%s' "$ic" | grep -A3 EXTRA_FILE | tr '\n' ' ' | cut -c1-200)"
    elif [ -n "$ic" ]; then
      warn NC-INTEGRITY "occ integrity:check-core returned output - review it: $(printf '%s' "$ic" | tr '\n' ' ' | cut -c1-160)"
    else
      okay "occ integrity:check-core reported no issues."
    fi
  else
    info NC-INTEGRITY "Skipped occ integrity check (--no-occ/--no-integrity or no php). Run manually: sudo -u $ncuser php $NC_PATH/occ integrity:check-core"
  fi
  note "Also review the Nextcloud log for this window: $NC_PATH/data/nextcloud.log (look for 'integrity', failed logins, app changes)."
fi

# ===================================================== 9. SECRETS ============
section "9. Secret exposure (rotate if compromise is confirmed)"
if [ -n "$NC_PATH" ] && [ -f "$NC_PATH/config/config.php" ]; then
  cfgt=$(stat -c '%y' "$NC_PATH/config/config.php" 2>/dev/null)
  if [ -n "$(find "$NC_PATH/config/config.php" -newermt "$SINCE" 2>/dev/null)" ]; then
    warn SECRETS "config/config.php changed since $SINCE ($cfgt). If unexpected, treat 'secret', 'passwordsalt' and the DB password as exposed and rotate them."
  else
    okay "config/config.php not modified since $SINCE ($cfgt)."
  fi
  note "If compromise is confirmed, config.php holds the DB password, 'secret' and 'passwordsalt' - rotate all three and plan a rebuild rather than a clean-up."
fi

# ===================================================== SUMMARY ===============
section "Summary"
printf 'CRIT: %s   WARN: %s   INFO: %s\n' "$n_crit" "$n_warn" "$n_info"
if [ -n "$JSON" ]; then
  printf '{"version":"%s","host":"%s","since":"%s","crit":%s,"warn":%s,"info":%s,"findings":[%s]}\n' \
    "$VERSION" "$(hostname 2>/dev/null)" "$SINCE" "$n_crit" "$n_warn" "$n_info" "${JOUT%,}" > "$JSON"
  note "JSON written to $JSON"
fi
if [ "$n_crit" -gt 0 ]; then
  printf '%sVERDICT: likely compromise - CRIT findings need immediate investigation.%s\n' "$C_CRIT" "$C_0"
  echo "Treat the host as compromised until proven otherwise: preserve evidence, isolate, rotate secrets, rebuild."
  exit 2
elif [ "$n_warn" -gt 0 ]; then
  printf '%sVERDICT: review needed - WARN findings should be checked against your change history.%s\n' "$C_WARN" "$C_0"
  exit 1
else
  printf '%sVERDICT: no host-side indicators found.%s\n' "$C_OK" "$C_0"
  echo "This sweep is not exhaustive: a careful attacker can hide from it. Combine with the log scan, auditd/EDR history, and offline disk review for high-assurance cases."
  exit 0
fi
