#!/bin/bash

# File Name:    sftp.sh
# Description:  Configures an SFTP service, root jailed to the apache web root.
#               Log in as sftpuser01 and open the /web directory to be redirected to /var/www/html.
# Version:      1
# Author:       Ricky Beaty
# Date:         23/02/2022

#######################################
# Set SFTP user's password here - NEVER SAVE AND COMMIT THIS TO THE REPO
pwd='YM6yPJN9VP0uJdipNWchnii3'


# Check we are the root user
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi


# If you don't set it, we ask for input (obviously this won't work if running unattended
if [ $pwd='' ]; then
    read -p "Enter SFTP user password: " pwd
fi

if [ -z $pwd ]; then
    echo "No password detected.  Exiting."
    exit 1
fi


# Configure SSH service to root jail members of the sftp group
cat <<EOT >> /etc/ssh/sshd_config

    Match Group sftp
    ChrootDirectory %h
    ForceCommand internal-sftp
    X11Forwarding no
    AllowTcpForwarding no
EOT

sed -i 's|PasswordAuthentication no|PasswordAuthentication yes|g' /etc/ssh/sshd_config
systemctl restart sshd

# Create the SFTP user and group
addgroup sftp
useradd -m -s /bin/false -G sftp neil
echo -e ""$pwd"\n"$pwd"" | passwd neil
passwd neil "$pwd"

# Configure the user's home directory
chown root:root /home/neil
chmod 0755 /home/neil
mkdir /home/neil/web
chown neil:www-data /home/neil/web

# Mount the apache web root to the sftp user's home directory
mount --bind /var/www/ /home/neil/web
chown -R neil:www-data /home/neil/web

# Make sure the apache group still owns objects saved here by neil
chmod g+s /home/neil/web


# Persist the mount after reboots
echo "/var/www/html /home/neil/web none bind 0 0" >> /etc/fstab
