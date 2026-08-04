#!/usr/bin/env bash
# Link the skill and slash command into ~/.claude so Claude Code picks them up,
# then build the Kali container.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"

mkdir -p "$CLAUDE_DIR/skills" "$CLAUDE_DIR/commands"

ln -sfn "$REPO/skills/pwnloop"          "$CLAUDE_DIR/skills/pwnloop"
ln -sfn "$REPO/skills/pwnloop-lab"      "$CLAUDE_DIR/skills/pwnloop-lab"
ln -sfn "$REPO/commands/pwnloop.md"     "$CLAUDE_DIR/commands/pwnloop.md"
ln -sfn "$REPO/commands/pwnloop-lab.md" "$CLAUDE_DIR/commands/pwnloop-lab.md"
echo "linked skill  -> $CLAUDE_DIR/skills/pwnloop"
echo "linked skill  -> $CLAUDE_DIR/skills/pwnloop-lab"
echo "linked command-> $CLAUDE_DIR/commands/pwnloop.md"
echo "linked command-> $CLAUDE_DIR/commands/pwnloop-lab.md"

mkdir -p "$REPO/engagements" "$REPO/campaigns" "$REPO/vpn"

# Your own learnings live in files upstream never touches, so `git pull` cannot
# conflict with what your engagements have written.
[ -f "$REPO/memory/local.md" ] || {
  cp "$REPO/memory/local.md.template" "$REPO/memory/local.md"
  echo "created       -> memory/local.md (yours; upstream never edits it)"
}
[ -f "$REPO/docker/packages.local.txt" ] || {
  cp "$REPO/docker/packages.local.txt.template" "$REPO/docker/packages.local.txt"
  echo "created       -> docker/packages.local.txt"
}

# Guard against committing engagement data — see hooks/pre-commit.
if [ -d "$REPO/.git" ]; then
  chmod +x "$REPO/hooks/pre-commit"
  ln -sfn "$REPO/hooks/pre-commit" "$REPO/.git/hooks/pre-commit"
  echo "linked hook   -> $REPO/.git/hooks/pre-commit"
fi

if [ "${1:-}" != "--no-build" ]; then
  echo "building the Kali image (first run takes a few minutes)…"
  "$REPO/bin/pwnloop" build
  "$REPO/bin/pwnloop" up
  "$REPO/bin/pwnloop" status
fi

cat <<EOF

Next:
  1. TRUST THE WORKSPACE — required, or every command prompts for permission:
       cd $REPO && claude     (accept the dialog, then exit)
  2. download your lab .ovpn and drop it in $REPO/vpn/
  3. $REPO/bin/pwnloop vpn <file.ovpn>
  4. $REPO/bin/pwnloop vpn-status      (expect an inet address on tun0)
  5. cd $REPO && claude   →  /pwnloop <target-ip> <machine-name>

  The VPN runs inside the container and dies with it: after 'pwnloop down' or a
  rebuild, reconnect with 'pwnloop vpn <file.ovpn>'.
EOF
