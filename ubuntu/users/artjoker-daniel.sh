#!/bin/bash

# File Name:    artjoker-daniel.sh
# Description:  Add a artjoker-daniel user with his public keyu for Amazon Linux 2 boxes
# Version:      1
# Author:       ricky Beaty
# Date:         05/05/2022

#######################################

# Add artjoker-daniel's public key
adduser artjoker-daniel --gecos "artjoker-daniel,NA,NA,NA" --disabled-password
su -c 'mkdir /home/artjoker-daniel/.ssh' artjoker-daniel 
su -c 'chmod 700 /home/artjoker-daniel/.ssh' artjoker-daniel
su -c 'touch /home/artjoker-daniel/.ssh/authorized_keys' artjoker-daniel
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB1j5ASsjZ+eVP5zInZdjIEKS33/3+OsNDfPhCrW+ViP o.melnychenko@artjoker.net" >> /home/artjoker-daniel/.ssh/authorized_keys
chmod 600 /home/artjoker-daniel/.ssh/authorized_keys
echo "artjoker-daniel ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users