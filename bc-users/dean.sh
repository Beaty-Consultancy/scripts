#!/bin/bash

# File Name:    dean.sh
# Description:  Add dean user, get public key from github.  Allow passwordless sudo.
# Version:      1
# Author:       ricky beaty
# Date:         09/06/25

#######################################

set -euo pipefail

USERNAME="dean"
GECOS="dean johnson,NA,NA,NA"
SSH_KEYS_URL="https://github.com/DeanJohnson0011.keys"
SSH_DIR="/home/${USERNAME}/.ssh"
AUTHORIZED_KEYS="${SSH_DIR}/authorized_keys"
SUDOERS_DROPIN="/etc/sudoers.d/${USERNAME}-nopasswd"

# Detect OS from /etc/os-release
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  OS_ID="${ID,,}"
  OS_LIKE="${ID_LIKE,,}"
else
  echo "❌ Cannot detect OS (no /etc/os-release)" >&2
  exit 1
fi

# Helper: does user already exist?
user_exists() { id "$1" &>/dev/null; }

# 1) Create user if needed, add to sudo-group
if user_exists "$USERNAME"; then
  echo "ℹ️  User '$USERNAME' already exists."
else
  if [[ "$OS_ID" =~ ^(debian|ubuntu|raspbian)$ ]] || [[ "$OS_LIKE" =~ debian ]]; then
    echo "🖥️  Detected Debian-family ($OS_ID)."
    adduser "$USERNAME" \
      --gecos "$GECOS" \
      --disabled-password
    usermod -aG sudo "$USERNAME"

  elif [[ "$OS_ID" =~ ^(rhel|centos|amzn|rocky|almalinux|fedora)$ ]] || [[ "$OS_LIKE" =~ (rhel|fedora) ]]; then
    echo "🖥️  Detected RHEL-family ($OS_ID)."
    useradd "$USERNAME" \
      --create-home \
      --shell /bin/bash \
      --comment "$GECOS"
    usermod -aG wheel "$USERNAME"

  else
    echo "⚠️  Unknown OS ($OS_ID). Using generic useradd."
    useradd "$USERNAME" \
      --create-home \
      --shell /bin/bash \
      --comment "$GECOS"
  fi
fi

# 2) Drop in a nopasswd sudoers file
cat > "$SUDOERS_DROPIN" <<EOF
# Allow $USERNAME to sudo without a password
$USERNAME ALL=(ALL) NOPASSWD:ALL
EOF
chmod 0440 "$SUDOERS_DROPIN"
echo "🔧  Installed sudoers drop-in at $SUDOERS_DROPIN."

# 3) Install SSH keys
echo "🔑  Fetching SSH keys from $SSH_KEYS_URL…"
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
curl -s "$SSH_KEYS_URL" >> "$AUTHORIZED_KEYS"
chmod 600 "$AUTHORIZED_KEYS"
chown -R "$USERNAME:$USERNAME" "$SSH_DIR"

echo "✅  Done! $USERNAME has passwordless sudo and your SSH key installed."