#!/bin/bash

# File Name:    ahmed.sh
# Description:  Add an ahmed user with his public keyu for Amazon Linux 2 boxes
# Version:      1
# Author:       Ricky Beaty
# Date:         08/01/25

#######################################

# Add ahmed's public key
adduser ahmed --gecos "Syed Ahmed,NA,NA,NA" --disabled-password
su -c 'mkdir /home/ahmed/.ssh' ahmed 
su -c 'chmod 700 /home/ahmed/.ssh' ahmed
su -c 'touch /home/ahmed/.ssh/authorized_keys' ahmed
curl https://github.com/syedahmedmansoor.keys >> /home/ahmed/.ssh/authorized_keys
chmod 600 /home/ahmed/.ssh/authorized_keys
echo "ahmed ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users