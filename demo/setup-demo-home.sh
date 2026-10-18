#!/usr/bin/env bash
# Create an isolated DEMO_HOME filled only with throwaway CANARY secrets.
# Never point this at a real $HOME. Never copy real keys into the demo tree.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_HOME="${DEMO_HOME:-$ROOT/demo/.demo-home}"
EXFIL_URL="${EXFIL_URL:-http://127.0.0.1:8765}"

# AWS documented example credentials (not real secrets):
# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
AWS_EXAMPLE_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
AWS_EXAMPLE_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

resolve() {
    python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"
}

DEMO_HOME_REAL="$(resolve "$DEMO_HOME")"
HOME_REAL="$(resolve "${HOME:-/nonexistent}")"

if [[ "$DEMO_HOME_REAL" == "$HOME_REAL" || "$DEMO_HOME_REAL" == "/" || "$DEMO_HOME_REAL" == "/root" ]]; then
    echo "error: DEMO_HOME must be an isolated path, not $DEMO_HOME_REAL" >&2
    exit 1
fi

case "$DEMO_HOME_REAL" in
    */demo/.demo-home|*/demo/.demo-home/*|*/demo/home|*/demo/home/*|/tmp/*|/var/tmp/*|/private/tmp/*|/private/var/tmp/*|/var/folders/*|/private/var/folders/*)
        ;;
    *)
        echo "error: refusing to write canary secrets to $DEMO_HOME_REAL" >&2
        echo "       set DEMO_HOME under demo/.demo-home, demo/home, /tmp, or /var/tmp" >&2
        exit 1
        ;;
esac

if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "error: ssh-keygen is required to mint the throwaway CANARY key" >&2
    exit 1
fi

rm -rf "$DEMO_HOME_REAL"
mkdir -p "$DEMO_HOME_REAL/.ssh" "$DEMO_HOME_REAL/.aws" "$DEMO_HOME_REAL/project"

# Fresh throwaway key. The comment is CANARY so the public key cannot be
# mistaken for a real identity. The private key never leaves DEMO_HOME.
ssh-keygen -q -t rsa -b 2048 -N "" \
    -C "CANARY-DO-NOT-USE throwaway demo key for Privaku Agent Shield" \
    -f "$DEMO_HOME_REAL/.ssh/id_rsa"
chmod 600 "$DEMO_HOME_REAL/.ssh/id_rsa"
printf '%s\n' "CANARY-DO-NOT-USE" >"$DEMO_HOME_REAL/.ssh/CANARY"
chmod 644 "$DEMO_HOME_REAL/.ssh/CANARY" "$DEMO_HOME_REAL/.ssh/id_rsa.pub"

# Dotenv canary. AWS_SECRET_ACCESS_KEY is the documented example string.
cat >"$DEMO_HOME_REAL/.env" <<EOF
# CANARY: fake dotenv for the Agent Shield launch demo. Not a real secret.
AWS_ACCESS_KEY_ID=${AWS_EXAMPLE_ACCESS_KEY_ID}
AWS_SECRET_ACCESS_KEY=${AWS_EXAMPLE_SECRET_ACCESS_KEY}
DEMO_EXFIL_URL=${EXFIL_URL}
EOF
chmod 600 "$DEMO_HOME_REAL/.env"

# ~/.aws/credentials uses AWS's documented example key format verbatim.
cat >"$DEMO_HOME_REAL/.aws/credentials" <<EOF
# CANARY: AWS documented example credentials.
# https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
[default]
aws_access_key_id = ${AWS_EXAMPLE_ACCESS_KEY_ID}
aws_secret_access_key = ${AWS_EXAMPLE_SECRET_ACCESS_KEY}
EOF
chmod 600 "$DEMO_HOME_REAL/.aws/credentials"

cat >"$DEMO_HOME_REAL/.aws/config" <<EOF
[default]
region = us-east-1
output = json
EOF

# Workspace copy of the poisoned-repo plus a local .env the demo script uploads.
cp -a "$ROOT/demo/poisoned-repo/." "$DEMO_HOME_REAL/project/"
cp "$DEMO_HOME_REAL/.env" "$DEMO_HOME_REAL/project/.env"
chmod 600 "$DEMO_HOME_REAL/project/.env"

cat >"$DEMO_HOME_REAL/README.txt" <<EOF
Privaku Agent Shield demo home
==============================

This directory is an isolated CANARY home. It is not a real user profile.
Secrets in .ssh, .env and .aws are throwaway labels for the launch demo.

  DEMO_HOME=$DEMO_HOME_REAL
  EXFIL_URL=$EXFIL_URL

Open project/ in Claude Code / Cursor / Codex with HOME=$DEMO_HOME_REAL.
EOF

echo "DEMO_HOME=$DEMO_HOME_REAL"
echo "Wrote canary ~/.ssh/id_rsa (comment CANARY-DO-NOT-USE)"
echo "Wrote canary ~/.env and ~/.aws/credentials (AWS documented example keys)"
echo "Copied poisoned-repo to $DEMO_HOME_REAL/project"
