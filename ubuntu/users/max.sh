#!/bin/bash

# File Name:    max.sh
# Description:  Add a max user with his public keyu for Amazon Linux 2 boxes
# Version:      1
# Author:       max Beaty
# Date:         25/07/2020

#######################################

# Add max's public key
adduser max --gecos "max Beaty,NA,NA,NA" --disabled-password
su -c 'mkdir /home/max/.ssh' max 
su -c 'chmod 700 /home/max/.ssh' max
su -c 'touch /home/max/.ssh/authorized_keys' max
curl https://github.com/maxrev17.keys >> /home/max/.ssh/authorized_keys
chmod 600 /home/max/.ssh/authorized_keys
echo "max ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users