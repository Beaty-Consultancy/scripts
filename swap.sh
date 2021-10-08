#!/bin/bash

# File Name:    swap.sh
# Description:  Add a 4GB swap file to server
# Version:      1
# Author:       Ricky Beaty
# Date:         04/10/2021

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
    # Add 4GB swapfile to root volume - ClamScan can be memory hungry
    /bin/dd if=/dev/zero of=/var/swap.1 bs=1M count=4096
    chmod 600 /var/swap.1
    /sbin/mkswap /var/swap.1
    /sbin/swapon /var/swap.1
    # Write out to fstab to retain the swapfile config on reboot
    echo "/var/swap.1   swap    swap    sw  0   0" >> /etc/fstab
fi