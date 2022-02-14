#!/bin/bash

# File Name:    plesk-build.sh
# Description:  Add a dean user with his public keyu for Amazon Linux 2 boxes
# Version:      1
# Author:       dean johnson
# Date:         14/02/2022

#######################################

# Add dean's public key
adduser dean
usermod -aG wheel dean
su -c 'mkdir /home/dean/.ssh' dean 
su -c 'chmod 700 /home/dean/.ssh' dean
su -c 'touch /home/dean/.ssh/authorized_keys' dean
curl https://bc-public.s3.eu-west-2.amazonaws.com/dean.pub >> /home/dean/.ssh/authorized_keys
chmod 600 /home/dean/.ssh/authorized_keys
echo "dean ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users