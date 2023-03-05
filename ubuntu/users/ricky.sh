#!/bin/bash

# File Name:    ricky.sh
# Description:  Add a ricky user with his public keyu for Amazon Linux 2 boxes
# Version:      1
# Author:       Ricky Beaty
# Date:         25/07/2020

#######################################

# Add ricky's public key
adduser ricky --gecos "Ricky Beaty,NA,NA,NA" --disabled-password
su -c 'mkdir /home/ricky/.ssh' ricky 
su -c 'chmod 700 /home/ricky/.ssh' ricky
su -c 'touch /home/ricky/.ssh/authorized_keys' ricky
curl https://github.com/beatyconsultancy.keys >> /home/ricky/.ssh/authorized_keys
chmod 600 /home/ricky/.ssh/authorized_keys
echo "ricky ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users