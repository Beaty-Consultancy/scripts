#!/bin/bash

# File Name:    dhaval.sh
# Description:  Add a dhaval user with his public keyu for Amazon Linux 2 boxes
# Version:      1
# Author:       ricky Beaty
# Date:         05/05/2022

#######################################

# Add dhaval's public key
adduser dhaval
usermod -aG wheel dhaval
su -c 'mkdir /home/dhaval/.ssh' dhaval 
su -c 'chmod 700 /home/dhaval/.ssh' dhaval
su -c 'touch /home/dhaval/.ssh/authorized_keys' dhaval
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUzKa6Tb2hBp0oBxC4I1HmCJaGBGkWybfKSmL34THhOMYYPGqsdwYszRPJEkeVTOaKYwE6S9AoKewUFOGtJZt/Djzi3KKzBO7ZRsJho+v7Ifxl34le4Gf77c3cI2NvNMrAMWL2+ObPXUxpplzuOox7SyPWudCEUy4a5F1vChNQm/4EkJ+57LSeFUGR/N1+rNcdYpuAiQFtQsIlXUedj6+T0ujvEDutXcSM5uh6JZA2lz4qy9MfU0eOuDWtlbjZzHlCFmxobQNEqW4AU9I2kBXrXBFhBLHEa1y0mBxZxdN8ohEesEgJvzrEYNG29hLpd3D6QKoAJzLTBiQRdQ7JhM41 BEATYCONSULTANC\dhaval@a-l9y4imjucnkl" >> /home/dhaval/.ssh/authorized_keys
chmod 600 /home/dhaval/.ssh/authorized_keys
echo "dhaval ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users