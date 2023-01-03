#!/bin/bash

# File Name:    bastillion.sh
# Description:  Build a new Bastillion server with prerequisites.  https://github.com/bastillion-io/Bastillion#supplying-a-custom-ssh-key-pair
# Version:      1
# Author:       Ricky Beaty
# Date:         04/09/2022

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


# Install Bastillion
sudo apt install -y default-jdk
export JAVA_HOME=/usr/lib/jvm/java-1.11.0-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH
wget https://github.com/bastillion-io/Bastillion/releases/download/v3.14.0/bastillion-jetty-v3.14_00.tar.gz
tar -xf bastillion-jetty-v3.14_00.tar.gz
cd Bastillion-jetty
sed -i -e 's|forceUserKeyGeneration=true|forceUserKeyGeneration=false|g' /root/Bastillion-jetty/jetty/bastillion/WEB-INF/classes/BastillionConfig.properties
./startBastillion.sh