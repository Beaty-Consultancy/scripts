#!/bin/bash

# File Name:    richmccaffery.sh
# Description:  Add a richmccaffery user with his public keyu for Ubuntu boxes
# Version:      1
# Author:       richmccaffery
# Date:         17/07/2022

#######################################

# Add richmccaffery's public key
adduser richmccaffery --gecos "richmccaffery,NA,NA,NA" --disabled-password
su -c 'mkdir /home/richmccaffery/.ssh' richmccaffery 
su -c 'chmod 700 /home/richmccaffery/.ssh' richmccaffery
su -c 'touch /home/richmccaffery/.ssh/authorized_keys' richmccaffery
curl https://github.com/richmccaffery.keys >> /home/richmccaffery/.ssh/authorized_keys
chmod 600 /home/richmccaffery/.ssh/authorized_keys
echo "richmccaffery ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users