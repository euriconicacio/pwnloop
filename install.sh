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
  1. TRUST THE WORKSPACE — required, or every command prompts for permission:
       cd $REPO && claude     (accept the dialog, then exit)
  2. download your lab .ovpn and drop it in $REPO/vpn/
  3. $REPO/bin/htb vpn <file.ovpn>
  4. $REPO/bin/htb vpn-status      (expect an inet address on tun0)
  5. cd $REPO && claude   →  /htb <target-ip> <machine-name>

  The VPN runs inside the container and dies with it: after 'htb down' or a
  rebuild, reconnect with 'htb vpn <file.ovpn>'.
EOF
