#!/bin/bash

# Function to install fail2ban on Amazon Linux 2
install_fail2ban_amzn2() {
    sudo amazon-linux-extras install epel -y
    sudo yum install fail2ban -y

    # Enable and start firewalld
    sudo systemctl enable firewalld
    sudo systemctl start firewalld
}

# Function to install fail2ban on Amazon Linux 2023 (Amazon Linux 3)
install_fail2ban_amzn2023() {
    REPO_FILE="/etc/yum.repos.d/amazonlinux.repo"
    COPR_REPO="[copr:copr.fedorainfracloud.org:faramirza:al2023_v2]
name=Copr repo for al2023_v2 owned by faramirza
baseurl=https://download.copr.fedorainfracloud.org/results/faramirza/al2023_v2/amazonlinux-2023-\$basearch/
type=rpm-md
skip_if_unavailable=True
gpgcheck=1
gpgkey=https://download.copr.fedorainfracloud.org/results/faramirza/al2023_v2/pubkey.gpg
repo_gpgcheck=0
enabled=1
enabled_metadata=1
module_hotfixes=1
priority=10"

    # Add the COPR repository to amazonlinux.repo
    echo "$COPR_REPO" | sudo tee -a $REPO_FILE

    # Install fail2ban from the COPR repository
    sudo yum install fail2ban -y

    # Install and enable rsyslog
    sudo dnf install rsyslog -y
    sudo systemctl enable rsyslog --now

    # Enable and start firewalld
    sudo systemctl enable firewalld
    sudo systemctl start firewalld
}

# Function to install fail2ban on Ubuntu
install_fail2ban_ubuntu() {
    sudo apt update
    sudo apt install fail2ban -y
}

# Determine the Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
    VERSION=$VERSION_ID
else
    echo "Cannot determine Linux distribution."
    exit 1
fi

# Install fail2ban based on distribution
case "$DISTRO" in
    "amzn")
        if [ "$VERSION" = "2" ]; then
            install_fail2ban_amzn2
        elif [ "$VERSION" = "2023" ]; then
            install_fail2ban_amzn2023
        else
            echo "Unsupported Amazon Linux version: $VERSION"
            exit 1
        fi
        ;;
    "ubuntu")
        install_fail2ban_ubuntu
        ;;
    *)
        echo "Unsupported Linux distribution: $DISTRO"
        exit 1
        ;;
esac

# Create and configure jail.local
JAIL_LOCAL="/etc/fail2ban/jail.local"

sudo bash -c "cat > $JAIL_LOCAL" <<EOL
[DEFAULT]
bantime  = 900
findtime  = 300
maxretry = 5

[sshd]
enabled = true
mode   = aggressive
EOL

# Replace the sshd.conf with the custom file from the script's directory
SCRIPT_DIR=$(dirname "$0")
CUSTOM_SSHD_FILTER="$SCRIPT_DIR/sshd.conf"
TARGET_SSHD_FILTER="/etc/fail2ban/filter.d/sshd.conf"

if [ -f "$CUSTOM_SSHD_FILTER" ]; then
    sudo cp "$CUSTOM_SSHD_FILTER" "$TARGET_SSHD_FILTER"
else
    echo "Custom sshd.conf not found in the script directory. Skipping file replacement."
fi

# Restart fail2ban service
sudo systemctl restart fail2ban

# Enable fail2ban service to start on boot
sudo systemctl enable fail2ban

echo "Fail2Ban installation and configuration completed."
