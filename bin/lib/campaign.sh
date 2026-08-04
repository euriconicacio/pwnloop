#!/usr/bin/env bash
# campaign.sh — state store for multi-host engagements (Pro Labs).
#
# Sourced by bin/pwnloop; not executable on its own. Every subcommand here is a
# deterministic mutation of campaigns/<lab>/campaign.json.
#
# Why a CLI instead of letting the agent edit the file: on a twenty-host lab the
# state outlives the agent's context many times over. Free-form edits drift —
# a host recorded twice under two spellings, a credential that exists in the
# ledger but not in the matrix. Every write goes through one of these commands,
# so the schema is enforced in one place and the agent never has to hold the
# whole file in context to append one fact.

CAMPAIGNS_DIR="$LAB_DIR/campaigns"

# ── helpers ──────────────────────────────────────────────────────────────────

_now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
_die() { echo "$*" >&2; exit 1; }

# Current campaign: $PWNLOOP_LAB wins, then campaigns/.current.
_lab() {
  local l="${PWNLOOP_LAB:-}"
  [ -z "$l" ] && [ -f "$CAMPAIGNS_DIR/.current" ] && l=$(cat "$CAMPAIGNS_DIR/.current")
  [ -n "$l" ] || _die "no current campaign — 'pwnloop campaign new <lab> <cidr>' or 'campaign use <lab>'"
  [ -d "$CAMPAIGNS_DIR/$l" ] || _die "campaign '$l' does not exist"
  printf '%s' "$l"
}
_cdir() { printf '%s/%s' "$CAMPAIGNS_DIR" "$(_lab)"; }
_cjson() { printf '%s/campaign.json' "$(_cdir)"; }

# Atomic edit: jq into a temp file, then move. A failed jq leaves state intact.
_edit() {
  local f; f=$(_cjson)
  jq "$@" "$f" > "$f.tmp" || { rm -f "$f.tmp"; _die "state edit failed — campaign.json unchanged"; }
  mv "$f.tmp" "$f"
  _sync_network_md
}

# k=v k=v … → {"k":"v",…}. Anything without an '=' is ignored.
_kv() {
  local out='{}' pair k v
  for pair in "$@"; do
    [ "${pair#*=}" = "$pair" ] && continue
    k="${pair%%=*}"; v="${pair#*=}"
    out=$(jq -c --arg k "$k" --arg v "$v" '. + {($k): $v}' <<<"$out")
  done
  printf '%s' "$out"
}

# Ports → the services worth spraying a credential against.
_services_for() {
  local ports="$1" out=""
  case " $ports " in *" 445 "*|*" 139 "*) out="$out smb";; esac
  case " $ports " in *" 22 "*)   out="$out ssh";;   esac
  case " $ports " in *" 5985 "*|*" 5986 "*) out="$out winrm";; esac
  case " $ports " in *" 3389 "*) out="$out rdp";;   esac
  case " $ports " in *" 1433 "*) out="$out mssql";; esac
  case " $ports " in *" 21 "*)   out="$out ftp";;   esac
  case " $ports " in *" 389 "*|*" 636 "*) out="$out ldap";; esac
  # Nothing pinned yet: assume the two that carry most lab credentials.
  [ -z "$out" ] && out=" smb ssh"
  printf '%s' "${out# }"
}

# ── campaign ─────────────────────────────────────────────────────────────────

campaign_new() {
  local lab="${1:?usage: pwnloop campaign new <lab> <cidr>[,<cidr>…]}"
  local scope="${2:?usage: pwnloop campaign new <lab> <cidr>[,<cidr>…]}"
  local dir="$CAMPAIGNS_DIR/$lab"
  [ -e "$dir" ] && _die "campaigns/$lab already exists — 'campaign use $lab' to resume it"

  mkdir -p "$dir"/{hosts,loot,routes,scans}
  jq -n --arg lab "$lab" --arg now "$(_now)" --arg scope "$scope" '{
    lab: $lab, created: $now, scope: ($scope | split(",")),
    hosts: [], creds: [], attempts: [], routes: [], leads: []
  }' > "$dir/campaign.json"
  printf '%s\n' "$lab" > "$CAMPAIGNS_DIR/.current"

  cat > "$dir/CAMPAIGN.md" <<EOF
# $lab — campaign ledger
Started: $(_now)
Scope: $scope

Network state (hosts, credentials, routes, flags) lives in \`campaign.json\` and
is rendered to \`network.md\`. This file is the narrative: what was decided and
why, in the order it happened. Per-host detail belongs in \`hosts/<ip>/FINDINGS.md\`.

| # | Time | Host | Event | Evidence |
|---|------|------|-------|----------|
EOF
  PWNLOOP_LAB="$lab" _sync_network_md
  echo "campaign $lab created at $dir"
  echo "scope: $scope"
}

campaign_use() {
  local lab="${1:?usage: pwnloop campaign use <lab>}"
  [ -d "$CAMPAIGNS_DIR/$lab" ] || _die "no campaign '$lab'"
  printf '%s\n' "$lab" > "$CAMPAIGNS_DIR/.current"
  echo "current campaign: $lab"
}

campaign_list() {
  local d cur
  cur=$(cat "$CAMPAIGNS_DIR/.current" 2>/dev/null || echo "")
  [ -d "$CAMPAIGNS_DIR" ] || { echo "no campaigns yet"; return; }
  printf '%-3s %-16s %-24s %-14s %s\n' "" LAB SCOPE HOSTS CREATED
  for d in "$CAMPAIGNS_DIR"/*/; do
    [ -f "$d/campaign.json" ] || continue
    local lab; lab=$(basename "$d")
    jq -r --arg lab "$lab" --arg cur "$cur" '
      "\(if $lab == $cur then "*" else " " end)   " +
      ($lab | .[0:16] | . + (" " * (16 - length))) + " " +
      ((.scope | join(",")) | .[0:24] | . + (" " * (24 - length))) + " " +
      (((.hosts | map(select(.status == "owned")) | length | tostring) + " owned/" +
        (.hosts | length | tostring)) | .[0:14] | . + (" " * (14 - length))) + " " +
      (.created | .[0:10])' "$d/campaign.json"
  done
}

# The dashboard. Also the thing an operator tails, via network.md.
campaign_status() {
  local f; f=$(_cjson)
  jq -r '
    def pad($n): .[0:$n] + (" " * ($n - (.[0:$n] | length)));
    def count($s): [.hosts[] | select(.status == $s)] | length;
    "campaign  \(.lab)   scope \(.scope | join(", "))   started \(.created[0:10])",
    "hosts     \(count("owned")) owned · \(count("foothold")) foothold · \(count("enum")) enumerating · \(count("seen")) seen · \(count("dead")) dead   (\(.hosts | length) total)",
    "flags     \([.hosts[].flags[]?] | length) captured",
    "creds     \(.creds | length)   attempts \(.attempts | length) (\([.attempts[] | select(.result == "ok")] | length) ok, \([.attempts[] | select(.result == "locked")] | length) locked)",
    "routes    \(.routes | length) registered, \([.routes[] | select(.status == "up")] | length) up",
    "leads     \([.leads[] | select(.status == "open")] | length) open",
    "",
    (if (.hosts | length) > 0 then
      ("HOST             OS        STATUS     ACCESS                    FL  VIA",
       (.hosts | sort_by(.status) | .[] |
         "\(.ip | pad(16)) \(.os // "" | pad(9)) \(.status | pad(10)) \(.access // "" | pad(25)) \((.flags | length | tostring) | pad(3)) \(.via // "")"))
     else "no hosts recorded yet" end),
    "",
    (if (.routes | length) > 0 then
      ("ROUTES",
       (.routes[] | "  \(.subnet) via \(.via) [\(.type)] — \(.status)\(if .canary != "" and .canary != null then " canary \(.canary)" else "" end)"))
     else empty end),
    (if ([.leads[] | select(.status == "open")] | length) > 0 then
      ("", "OPEN LEADS",
       (.leads | map(select(.status == "open")) | sort_by(.prio) | .[] |
         "  [\(.id)] p\(.prio) \(.kind) \(.target) — \(.note)"))
     else empty end)
  ' "$f"
}

# network.md is the operator-facing render of campaign.json. Rewritten on every
# mutation so `tail -f` shows the live network without the agent maintaining it.
_sync_network_md() {
  local lab dir
  lab=$(_lab 2>/dev/null) || return 0
  dir="$CAMPAIGNS_DIR/$lab"
  [ -f "$dir/campaign.json" ] || return 0
  { echo '```'; PWNLOOP_LAB="$lab" campaign_status; echo '```'; } > "$dir/network.md" 2>/dev/null || true
}

# Everything the next session needs to pick the campaign back up.
campaign_resume() {
  echo "── state ─────────────────────────────────────────────────────────────"
  campaign_status
  echo
  echo "── routes ────────────────────────────────────────────────────────────"
  route_check
  echo
  echo "── next ──────────────────────────────────────────────────────────────"
  local f; f=$(_cjson)
  jq -r '
    ([.hosts[] | select(.status == "seen")] | length) as $seen |
    ([.leads[] | select(.status == "open")] | length) as $leads |
    if $seen > 0 then "  \($seen) host(s) discovered but never enumerated — pwnloop host list seen" else empty end,
    if $leads > 0 then "  \($leads) open lead(s) — pwnloop lead list" else empty end,
    if (.creds | length) > 0 then "  credential replay — pwnloop try next" else empty end
  ' "$f"
  echo "  routes reported down above must be re-established before anything else."
}

# ── hosts ────────────────────────────────────────────────────────────────────

host_add() {
  local ip="${1:?usage: pwnloop host add <ip> [k=v …]}"; shift || true
  local kv; kv=$(_kv "$@")
  _edit --arg ip "$ip" --argjson kv "$kv" --arg now "$(_now)" '
    if any(.hosts[]; .ip == $ip)
    then .hosts |= map(if .ip == $ip then . + $kv + {updated: $now} else . end)
    else .hosts += [{
      ip: $ip, name: "", os: "", subnet: "", status: "seen", access: "",
      via: "", ports: "", notes: "", flags: [], updated: $now
    } + $kv]
    end'
  echo "host $ip recorded"
}

host_set() {
  local ip="${1:?usage: pwnloop host set <ip> k=v …}"; shift
  [ $# -gt 0 ] || _die "nothing to set"
  local kv; kv=$(_kv "$@")
  local f; f=$(_cjson)
  jq -e --arg ip "$ip" 'any(.hosts[]; .ip == $ip)' "$f" >/dev/null \
    || _die "no host $ip — 'pwnloop host add $ip' first"
  _edit --arg ip "$ip" --argjson kv "$kv" --arg now "$(_now)" \
    '.hosts |= map(if .ip == $ip then . + $kv + {updated: $now} else . end)'
  echo "host $ip updated"
}

host_list() {
  local want="${1:-}" f; f=$(_cjson)
  jq -r --arg want "$want" '
    def pad($n): .[0:$n] + (" " * ($n - (.[0:$n] | length)));
    .hosts[] | select($want == "" or .status == $want) |
    "\(.ip | pad(16)) \(.status | pad(10)) \(.os // "" | pad(9)) \(.ports // "" | pad(28)) \(.access // "")"
  ' "$f"
}

host_show() {
  local ip="${1:?usage: pwnloop host show <ip>}" f; f=$(_cjson)
  jq --arg ip "$ip" '.hosts[] | select(.ip == $ip)' "$f"
  echo "--- attempts ---"
  jq -r --arg ip "$ip" '.attempts[] | select(.host == $ip) |
    "  \(.cred) → \(.service): \(.result)"' "$f"
}

# ── credentials ──────────────────────────────────────────────────────────────

cred_add() {
  [ $# -gt 0 ] || _die "usage: pwnloop cred add user=<u> [secret=<s>] [type=password|nthash|key|ticket] [domain=<d>] [source=<where>]"
  local kv; kv=$(_kv "$@")
  local f; f=$(_cjson)
  # Dedupe on the triple that actually identifies a credential.
  local dup
  dup=$(jq -r --argjson kv "$kv" '
    [.creds[] | select(
      (.user // "") == ($kv.user // "") and
      (.secret // "") == ($kv.secret // "") and
      (.domain // "") == ($kv.domain // ""))] | .[0].id // ""' "$f")
  if [ -n "$dup" ]; then echo "credential already known: $dup"; return 0; fi

  local id; id="c$(jq '.creds | length + 1' "$f")"
  _edit --arg id "$id" --argjson kv "$kv" --arg now "$(_now)" '
    .creds += [{id: $id, domain: "", user: "", secret: "", type: "password",
                source: "", added: $now} + $kv]'
  echo "$id"
}

cred_list() {
  local f; f=$(_cjson)
  jq -r '
    def pad($n): .[0:$n] + (" " * ($n - (.[0:$n] | length)));
    .creds[] as $c |
    ([.attempts[] | select(.cred == $c.id and .result == "ok")] | length) as $ok |
    ([.attempts[] | select(.cred == $c.id)] | length) as $n |
    "\($c.id | pad(5)) \((($c.domain // "") + (if ($c.domain // "") != "" then "\\" else "" end) + $c.user) | pad(28)) \($c.type | pad(9)) \($c.secret | pad(26)) \($ok)/\($n) ok  \($c.source)"
  ' "$f"
}

# ── credential matrix ────────────────────────────────────────────────────────

try_record() {
  local cred="${1:?usage: pwnloop try <cred-id> <host> <service> <ok|fail|locked|error>}"
  local host="${2:?}" svc="${3:?}" res="${4:?}"
  case "$res" in ok|fail|locked|error) ;; *) _die "result must be ok|fail|locked|error";; esac
  _edit --arg c "$cred" --arg h "$host" --arg s "$svc" --arg r "$res" --arg now "$(_now)" '
    .attempts |= (map(select(.cred != $c or .host != $h or .service != $s))
                  + [{cred: $c, host: $h, service: $s, result: $r, time: $now}])'
  [ "$res" = "locked" ] && echo "WARNING: $cred locked out on $host — stop spraying it everywhere"
  echo "$cred → $host/$svc: $res"
}

# The point of the matrix: never spray the same pair twice, never touch a
# credential that has already tripped a lockout.
try_next() {
  local n="${1:-15}" f; f=$(_cjson)
  local hosts
  hosts=$(jq -r '.hosts[] | select(.status == "seen" or .status == "enum" or .status == "foothold") | "\(.ip)|\(.ports // "")"' "$f")
  [ -n "$hosts" ] || { echo "no unowned hosts to spray"; return; }

  local locked; locked=$(jq -r '[.attempts[] | select(.result == "locked") | .cred] | unique | join(" ")' "$f")
  local shown=0 line ip ports svc
  while IFS='|' read -r ip ports; do
    [ -n "$ip" ] || continue
    for svc in $(_services_for "$ports"); do
      while read -r cid; do
        [ -n "$cid" ] || continue
        case " $locked " in *" $cid "*) continue;; esac
        [ "$shown" -ge "$n" ] && return 0
        line=$(jq -r --arg c "$cid" '.creds[] | select(.id == $c) |
          "\(.id)  \((.domain // "") + (if (.domain // "") != "" then "\\" else "" end) + .user):\(.secret)"' "$f")
        printf '  %-46s → %s/%s\n' "$line" "$ip" "$svc"
        shown=$((shown + 1))
      done < <(jq -r --arg h "$ip" --arg s "$svc" '
        [.attempts[] | select(.host == $h and .service == $s) | .cred] as $done |
        .creds[] | select(.id as $i | ($done | index($i)) | not) | .id' "$f")
    done
  done <<< "$hosts"
  [ "$shown" -eq 0 ] && echo "matrix exhausted — every known credential has been tried on every unowned host"
  return 0
}

# ── routes ───────────────────────────────────────────────────────────────────

route_add() {
  [ $# -gt 0 ] || _die "usage: pwnloop route add subnet=<cidr> via=<ip> type=<ligolo|chisel|ssh|socat> [listener=<port>] [canary=<ip:port>] [note=<text>]"
  local kv; kv=$(_kv "$@")
  local sub; sub=$(jq -r '.subnet // ""' <<<"$kv")
  [ -n "$sub" ] || _die "subnet= is required"
  _edit --argjson kv "$kv" --arg sub "$sub" --arg now "$(_now)" '
    .routes |= (map(select(.subnet != $sub)) + [{
      subnet: "", via: "", type: "", listener: "", canary: "", note: "",
      status: "unknown", added: $now} + $kv])'
  echo "route $sub registered"
}

route_del() {
  local sub="${1:?usage: pwnloop route del <subnet>}"
  _edit --arg sub "$sub" '.routes |= map(select(.subnet != $sub))'
  echo "route $sub removed"
}

route_list() {
  local f; f=$(_cjson)
  jq -r '.routes[] | "  \(.subnet) via \(.via) [\(.type)] \(.status)\(if (.canary // "") != "" then "  canary \(.canary)" else "" end)"' "$f"
}

# A route is only real if traffic crosses it. After a lab reset every tunnel is
# dead while the state file still claims otherwise — this is the first thing a
# resumed session runs.
route_check() {
  local f sub via canary ip port ok any=0
  f=$(_cjson)
  while IFS='|' read -r sub via canary; do
    [ -n "$sub" ] || continue
    any=1
    if [ -z "$canary" ]; then
      printf '  %-20s via %-15s  no canary — cannot verify\n' "$sub" "$via"
      continue
    fi
    ip="${canary%%:*}"; port="${canary##*:}"
    if cmd_x "timeout 4 bash -c '</dev/tcp/$ip/$port' 2>/dev/null && echo up" 2>/dev/null | grep -q up; then
      ok=up
    else
      ok=down
    fi
    printf '  %-20s via %-15s  %s\n' "$sub" "$via" "$ok"
    _edit --arg s "$sub" --arg st "$ok" '.routes |= map(if .subnet == $s then . + {status: $st} else . end)'
  done < <(jq -r '.routes[] | "\(.subnet)|\(.via)|\(.canary // "")"' "$f")
  [ "$any" -eq 0 ] && echo "  no routes registered"
  return 0
}

# ── flags ────────────────────────────────────────────────────────────────────

flag_add() {
  local host="${1:?usage: pwnloop flag <host> <name> <value>}" name="${2:?}" val="${3:?}"
  local lab; lab=$(_lab)
  local f; f=$(_cjson)
  jq -e --arg ip "$host" 'any(.hosts[]; .ip == $ip)' "$f" >/dev/null || host_add "$host" >/dev/null
  _edit --arg ip "$host" --arg n "$name" --arg v "$val" --arg now "$(_now)" '
    .hosts |= map(if .ip == $ip
      then .flags |= (map(select(.name != $n)) + [{name: $n, value: $v, captured: $now}])
      else . end)'
  echo "| $lab/$host | $host | $name | $val | $(date -u '+%Y-%m-%d %H:%M') |" >> "$LAB_DIR/flags.local.md"
  echo "$name — $val"
}

# ── leads ────────────────────────────────────────────────────────────────────

lead_add() {
  [ $# -gt 0 ] || _die "usage: pwnloop lead add kind=<host|cred|subnet|edge|service> target=<x> note=<text> [prio=1-3]"
  local kv; kv=$(_kv "$@")
  local f; f=$(_cjson)
  local id; id="l$(jq '.leads | length + 1' "$f")"
  _edit --arg id "$id" --argjson kv "$kv" --arg now "$(_now)" '
    .leads += [{id: $id, kind: "", target: "", note: "", prio: "2",
                status: "open", added: $now} + $kv]'
  echo "$id"
}

lead_list() {
  local f; f=$(_cjson)
  jq -r '.leads[] | select(.status == "open") | "  [\(.id)] p\(.prio) \(.kind) \(.target) — \(.note)"' "$f"
}

lead_close() {
  local id="${1:?usage: pwnloop lead <done|dead> <id>}" st="${2:-done}"
  _edit --arg id "$id" --arg st "$st" '.leads |= map(if .id == $id then . + {status: $st} else . end)'
  echo "lead $id → $st"
}

# ── dispatch ─────────────────────────────────────────────────────────────────

cmd_campaign() {
  case "${1:-status}" in
    new)    shift; campaign_new "$@" ;;
    use)    shift; campaign_use "$@" ;;
    list)   shift; campaign_list "$@" ;;
    status) shift; campaign_status "$@" ;;
    resume) shift; campaign_resume "$@" ;;
    sync)   _sync_network_md; echo "network.md updated" ;;
    dir)    _cdir; echo ;;
    *) _die "usage: pwnloop campaign <new|use|list|status|resume|sync|dir>" ;;
  esac
}

cmd_host() {
  case "${1:-list}" in
    add)  shift; host_add "$@" ;;
    set)  shift; host_set "$@" ;;
    list) shift; host_list "$@" ;;
    show) shift; host_show "$@" ;;
    *) _die "usage: pwnloop host <add|set|list|show>" ;;
  esac
}

cmd_cred() {
  case "${1:-list}" in
    add)  shift; cred_add "$@" ;;
    list) shift; cred_list "$@" ;;
    *) _die "usage: pwnloop cred <add|list>" ;;
  esac
}

cmd_try() {
  case "${1:-next}" in
    next) shift; try_next "$@" ;;
    *) try_record "$@" ;;
  esac
}

cmd_route() {
  case "${1:-list}" in
    add)   shift; route_add "$@" ;;
    del)   shift; route_del "$@" ;;
    list)  shift; route_list "$@" ;;
    check) shift; route_check "$@" ;;
    *) _die "usage: pwnloop route <add|del|list|check>" ;;
  esac
}

cmd_lead() {
  case "${1:-list}" in
    add)  shift; lead_add "$@" ;;
    list) shift; lead_list "$@" ;;
    done) shift; lead_close "$1" done ;;
    dead) shift; lead_close "$1" dead ;;
    *) _die "usage: pwnloop lead <add|list|done|dead>" ;;
  esac
}
