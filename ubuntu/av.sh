#!/bin/bash

# File Name:    av.sh
# Description:  Install, update and schedule AV scans using ClamScan for Ubuntu server
# Version:      1
# Author:       Ricky Beaty
# Date:         06/10/2021

# Comments:
# This script can be run against all servers managed by AWS System Manager as per https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-s3-shell.html

#######################################

# Check we are the root user
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Check to make sure there is 4GB free disk space to add a swap file to
reqSpace=4096000
availSpace=$(df "/" | awk 'NR==2 { print $4 }')
if (( availSpace < reqSpace )); then
  echo "not enough Space" >&2
  exit 1
fi

# Check if a swap file is present
if free | awk '/^Swap:/ {exit !$2}'; then
    echo "Have swap, skipping"
else
    # Add 2GB swapfile to root volume - ClamScan can be memory hungry
    /bin/dd if=/dev/zero of=/var/swap.1 bs=1M count=2048
    chmod 600 /var/swap.1
    /sbin/mkswap /var/swap.1
    /sbin/swapon /var/swap.1
    # Write out to fstab to retain the swapfile config on reboot
    echo "/var/swap.1   swap    swap    sw  0   0" >> /etc/fstab
fi

apt-get update
apt-get --fix-broken install -y
apt-get install -y clamav clamav-daemon


#Download and install latest AV signatures
systemctl stop clamav-freshclam
systemctl stop clamav-daemon.service
freshclam

systemctl start clamav-freshclam
systemctl start clamav-daemon.service

# Add a crontab entry to run an AV scan every night
(crontab -l 2>/dev/null; echo "10 4 * * * systemctl stop clamav-freshclam && systemctl stop clamav-daemon.service && freshclam && clamscan --infected --recursive --remove / && systemctl start clamav-freshclam && systemctl start clamav-daemon.service") | crontab -