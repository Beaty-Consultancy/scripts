#!/bin/bash

# File Name:    swap.sh
# Description:  Add a 4GB swap file to server
# Version:      1
# Author:       Ricky Beaty
# Date:         04/10/2021

#######################################

# Add 4GB swapfile to root volume
/bin/dd if=/dev/zero of=/var/swap.1 bs=1M count=4096
chmod 600 /var/swap.1
/sbin/mkswap /var/swap.1
/sbin/swapon /var/swap.1
# Write out to fstab to retain the swapfile config on reboot
echo "/var/swap.1   swap    swap    sw  0   0" >> /etc/fstab