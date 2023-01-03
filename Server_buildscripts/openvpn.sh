#!/bin/bash

# File Name:    openvpn.sh
# Description:  Build a new OpenVPN server with prerequisites.  Last step is done manually so we can easily get the password.
# Version:      1
# Author:       Ricky Beaty
# Date:         12/08/2022

#######################################

# Add SWAP file
/bin/dd if=/dev/zero of=/var/swap.1 bs=1M count=2048
chmod 600 /var/swap.1
/sbin/mkswap /var/swap.1
/sbin/swapon /var/swap.1
# Write out to fstab to retain the swapfile config on reboot
echo "/var/swap.1   swap    swap    sw  0   0" >> /etc/fstab

#Update server
apt update
apt upgrade -y

# Add ricky's public key
adduser ricky --gecos "Ricky Beaty,NA,NA,NA" --disabled-password
su -c 'mkdir /home/ricky/.ssh' ricky 
su -c 'chmod 700 /home/ricky/.ssh' ricky
su -c 'touch /home/ricky/.ssh/authorized_keys' ricky
curl https://bc-public.s3.eu-west-2.amazonaws.com/ricky.pub >> /home/ricky/.ssh/authorized_keys
chmod 600 /home/ricky/.ssh/authorized_keys
echo "ricky ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users

# Add dean's public key
adduser dean --gecos "dean johnson,NA,NA,NA" --disabled-password
su -c 'mkdir /home/dean/.ssh' dean 
su -c 'chmod 700 /home/dean/.ssh' dean
su -c 'touch /home/dean/.ssh/authorized_keys' dean
curl https://bc-public.s3.eu-west-2.amazonaws.com/dean.pub >> /home/dean/.ssh/authorized_keys
chmod 600 /home/dean/.ssh/authorized_keys
echo "dean ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users

# Install OpenVPN prerequisites
apt update
apt install -y tzdata
dpkg-reconfigure tzdata
apt update && apt -y install ca-certificates wget net-tools gnupg
wget -qO - https://as-repository.openvpn.net/as-repo-public.gpg | apt-key add -
echo "deb http://as-repository.openvpn.net/as/debian jammy main">/etc/apt/sources.list.d/openvpn-as-repo.list
apt update

# Run this after the server comes up:
# apt -y install openvpn-as