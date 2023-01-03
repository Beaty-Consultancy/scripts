#!/bin/bash

# File Name:    bastillion-user.sh
# Description:  Add Bastillion public key to server
# Version:      1
# Author:       ricky Beaty
# Date:         13/09/2022

#######################################

# Add bc-keysync's public key
adduser bc-keysync --gecos "bc-keysync,NA,NA,NA" --disabled-password
su -c 'mkdir /home/bc-keysync/.ssh' bc-keysync 
su -c 'chmod 700 /home/bc-keysync/.ssh' bc-keysync
su -c 'touch /home/bc-keysync/.ssh/authorized_keys' bc-keysync
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCAIxo8J4wouLXFuU2a3CbLjbAnXh/A1DooZSPGFMRgx/ovEcUMzPC6eafksHHggyvfvu4DoeF/T6DTx/uya8tI+trAO7RrShy/7lijCBw6A70NTkYWqltNhSJ31a+JX7KVyQFbdIsbfirrjgH5sSe5Hhhn7xnk3lm80FDnxp9hBEcD6QH2CsgXQefkjjKne31H1KqowY6DzP/c0g/uxViH7+liern9aTx8ZCek0GK/WnSXLxWw9ID7rPvz2bHT5yL6EVdqdNMqYLJ3i10TDTB7cqq3TH9tSFL8Lm9pqZQBXE1iG7JYQJ8N7RwvjZM8p6HktYKEV/Z/IERCc2dENCn5l7bY17O4/VAgu7paa6p2LOx03yF0R/63FOPzvQUlUXI+KGAP69FkAKwKtrVoExDcAuKj/CAZW6Sc1UCkVpotUxo0N+uNyZ7PHSLb4muIstteV50kjJhSE6OwSYD5YWUUARKB4am8c6no/Cx629y8MzAV+yjWNiEAPHQnS9jkTKvkqHd/tZUkA/ilnffN6YaxA1HYjWqMn1blBeGgFzVEuU7fB4IZGmoXH+AJOdUsoqN0TQlPgeX1Do51Bt4OhH4/5kcCT00y1bgSohTDv5RN5PYN2jwyZFB0fbjj37vCYYGVNxIQ3aISbN5N0ppeyEhIp5G1fSxyWuOKixnQO6WIlw== bastillion@global_key" >> /home/bc-keysync/.ssh/authorized_keys
chmod 600 /home/bc-keysync/.ssh/authorized_keys
echo "bc-keysync ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users