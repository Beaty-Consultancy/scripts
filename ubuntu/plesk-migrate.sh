#!/bin/bash

# File Name:    plesk-migrate.sh
# Description:  Deploy Plesk to a new server and make ready for migration from the old one
#               This isnn't a script you can just execute - rather a set of commands to be run on the old and new servers to complete a migration
# Version:      1
# Author:       Ricky Beaty
# Date:         30/12/2021

# Run scripts to add users, OS harden, install antivirus first.

# New server
## Install Plesk
sh <(curl https://autoinstall.plesk.com/one-click-installer || wget -O - https://autoinstall.plesk.com/one-click-installer)

# Old Server
## Temporarily allow root login for the new Plesk server
sed -i -e "s/PermitRootLogin prohibit-password/PermitRootLogin yes/g" /etc/ssh/sshd_config
sed -i -e "s/PasswordAuthentication no/PasswordAuthentication yes/g" /etc/ssh/sshd_config
systemctl restart sshd
# Interractively reset the root password to something you know
passwd root

# Follow instructions here; https://docs.plesk.com/en-US/obsidian/migration-guide/migrating-from-supported-hosting-platfoms/migrating-via-the-plesk-interface.75721/
# Decommission old server, move elastic ip to new server, activate license on new server.