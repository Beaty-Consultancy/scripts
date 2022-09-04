#!/bin/bash

# File Name:    openvas.sh
# Description:  Install OpenVAS to a new Ubuntu 20:04 server
# Version:      1
# Author:       Ricky Beaty
# Date:         23/08/2022

#######################################

# Check we are the root user
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Check to make sure there is 4GB free disk space to add a swap file to
reqSpace=2048000
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
    /bin/dd if=/dev/zero of=/var/swap.1 bs=1M count=2048
    chmod 600 /var/swap.1
    /sbin/mkswap /var/swap.1
    /sbin/swapon /var/swap.1
    # Write out to fstab to retain the swapfile config on reboot
    echo "/var/swap.1   swap    swap    sw  0   0" >> /etc/fstab
fi

# Add bc users
adduser ricky --gecos "Ricky Beaty,NA,NA,NA" --disabled-password
su -c 'mkdir /home/ricky/.ssh' ricky 
su -c 'chmod 700 /home/ricky/.ssh' ricky
su -c 'touch /home/ricky/.ssh/authorized_keys' ricky
curl https://bc-public.s3.eu-west-2.amazonaws.com/ricky.pub >> /home/ricky/.ssh/authorized_keys
chmod 600 /home/ricky/.ssh/authorized_keys
echo "ricky ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users

adduser dean --gecos "dean johnson,NA,NA,NA" --disabled-password
su -c 'mkdir /home/dean/.ssh' dean 
su -c 'chmod 700 /home/dean/.ssh' dean
su -c 'touch /home/dean/.ssh/authorized_keys' dean
curl https://bc-public.s3.eu-west-2.amazonaws.com/dean.pub >> /home/dean/.ssh/authorized_keys
chmod 600 /home/dean/.ssh/authorized_keys
echo "dean ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users

adduser richmccaffery --gecos "richmccaffery,NA,NA,NA" --disabled-password
su -c 'mkdir /home/richmccaffery/.ssh' richmccaffery 
su -c 'chmod 700 /home/richmccaffery/.ssh' richmccaffery
su -c 'touch /home/richmccaffery/.ssh/authorized_keys' richmccaffery
curl https://github.com/richmccaffery.keys >> /home/richmccaffery/.ssh/authorized_keys
chmod 600 /home/richmccaffery/.ssh/authorized_keys
echo "richmccaffery ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users

# Install some OpenVAS stuffs
wget https://raw.githubusercontent.com/yu210148/gvm_install/master/install_gvm.sh
chmod +x install_gvm.sh
sudo ./install_gvm.sh -v 21 -u