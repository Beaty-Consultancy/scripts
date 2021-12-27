#!/bin/bash

# File Name:    plesk-build.sh
# Description:  Add a yama user with his public keyu for Amazon Linux 2 boxes
# Version:      1
# Author:       Ricky Beaty
# Date:         25/07/2020

#######################################

# Add yama's public key
adduser yama --gecos "yama Beaty,NA,NA,NA" --disabled-password
su -c 'mkdir /home/yama/.ssh' yama 
su -c 'chmod 700 /home/yama/.ssh' yama
su -c 'touch /home/yama/.ssh/authorized_keys' yama
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI3LZmH2jgzx7P5D4CVYTgXKUZbgQJRrELbvjgmACEC7pxVtuV3KJyUwqBph3Ol0Lsgbi11VLfFNdWOWkNXV24cLfKq+lYANHNMzbtcHItp/WZxEBI6kmkS+MnYk2ku2cK6e9y44kvGnP8aPZTqRjaRPIY3mrXrT7+IYXRR7TlTXeVcainEUh+K5fhkZak/7sbSAY4SUoFGtaGDl2ZFP1UWzgvewPmXWn2hYYPt7Nj7h+h+YdGz59Ux9Zbf6mRj+dF3SYtVt1kpCRwTXmRn5Mu07tRf1/Veovigh22B2KlHk8jCD0IL7DQqgzUh7H4i4GwVMStXg7LvUkADPcm530x yamahakimi@Yamas-MacBook-Pro.local" >> /home/yama/.ssh/authorized_keys
chmod 600 /home/yama/.ssh/authorized_keys
echo "yama ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users