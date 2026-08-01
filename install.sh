#!/usr/bin/env bash
# Link the skill and slash command into ~/.claude so Claude Code picks them up,
# then build the Kali container.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"

mkdir -p "$CLAUDE_DIR/skills" "$CLAUDE_DIR/commands"

ln -sfn "$REPO/skills/htb-machine" "$CLAUDE_DIR/skills/htb-machine"
ln -sfn "$REPO/commands/htb.md"    "$CLAUDE_DIR/commands/htb.md"
echo "linked skill  -> $CLAUDE_DIR/skills/htb-machine"
echo "linked command-> $CLAUDE_DIR/commands/htb.md"

mkdir -p "$REPO/engagements" "$REPO/vpn"

if [ "${1:-}" != "--no-build" ]; then
  echo "building the Kali image (first run takes a few minutes)…"
  "$REPO/bin/htb" build
  "$REPO/bin/htb" up
  "$REPO/bin/htb" status
fi

cat <<EOF

Next:
  1. download your HTB .ovpn and drop it in $REPO/vpn/
  2. $REPO/bin/htb vpn <file.ovpn>
  3. $REPO/bin/htb vpn-status
  4. cd $REPO && claude   →  /htb <target-ip> <machine-name>
EOF
