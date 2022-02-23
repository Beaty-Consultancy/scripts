#!/bin/bash

# File Name:    sftp.sh
# Description:  Configures an SFTP service, root jailed to the apache web root.
#               Log in as sftpuser01 and open the /web directory to be redirected to /var/www/html.
# Version:      1
# Author:       Ricky Beaty
# Date:         23/02/2022

#######################################
# Set SFTP user's password here - NEVER SAVE AND COMMIT THIS TO THE REPO
pwd=''


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
useradd -m -s /bin/false -G sftp sftpuser01
echo -e ""$pwd"\n"$pwd"" | passwd sftpuser01
passwd sftpuser01 "$pwd"

# Configure the user's home directory
chown root:root /home/sftpuser01
chmod 0755 /home/sftpuser01
mkdir /home/sftpuser01/web
chown sftpuser01:www-data /home/sftpuser01/web

# Mount the apache web root to the sftp user's home directory
mount --bind /var/www/html /home/sftpuser01/web
chown -R sftpuser01:www-data /home/sftpuser01/web

# Make sure the apache group still owns objects saved here by sftpuser01
chmod g+s /home/sftpuser01/web


# Persist the mount after reboots
echo "/var/www/html /home/sftpuser01/web none bind 0 0" >> /etc/fstab
