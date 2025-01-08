#!/bin/bash

# File Name:    ahmed.sh
# Description:  Add an ahmed user with his public keyu for RHEL
# Version:      1
# Author:       ricky Beaty
# Date:         08/01/25

#######################################

# Add ahmed's public key
adduser ahmed
usermod -aG wheel ahmed
su -c 'mkdir /home/ahmed/.ssh' ahmed 
su -c 'chmod 700 /home/ahmed/.ssh' ahmed
su -c 'touch /home/ahmed/.ssh/authorized_keys' ahmed
curl https://github.com/syedahmedmansoor.keys >> /home/ahmed/.ssh/authorized_keys
chmod 600 /home/ahmed/.ssh/authorized_keys
echo "ahmed ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users