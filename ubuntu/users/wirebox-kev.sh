#!/bin/bash

# File Name:    kev.sh
# Description:  Add a kev user with his public keyu for Amazon Linux 2 boxes
# Version:      1
# Author:       ricky Beaty
# Date:         05/05/2022

#######################################

# Add kev's public key
adduser kev --gecos "kev,NA,NA,NA" --disabled-password
su -c 'mkdir /home/kev/.ssh' kev 
su -c 'chmod 700 /home/kev/.ssh' kev
su -c 'touch /home/kev/.ssh/authorized_keys' kev
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5LtLwDOPAxRK0bwOiFFotgmRjucXLdkfBRm2PhlVh66BjoDdYQ7g/4iy6wdakrCwD8CasHcFO1XSK+sQpQ0s3IffLkFVMJk15Zsio7SY6g28Rv1D5q6AoOhNrF3icLSfh7Z2iJ1sI6Co7VQX5B3Tzrkujv9l+7VGTtYcCdStnWYr2MRKAeax7o2mIN6mGBh1qu2WwW5nMA2QHm3lsSaf960Na9ymmcmXa6Q06aZoDn4U7vF12sjHU8+o3FOalGU/foaw1X+wVMBRqkHlQiVHXKXeRQ6Fu0eF0QmQnYy6f3WROc6MYF3yAXZCsjmJ2yTUejos8D0R3sXA+j32WxFsmbZKfh/mE9nJsJA9LRgc9hB0e2Tx2Eb9Em+M0e03tst5odWZ8OBtW1yo3E1WLC//w449iCaB05LH2TW2mXvjoQeTsXtu965jef9aRzE9N3FTtoPppN1EdEp5phosqFAzCmP8kaelbC4MkvqCRjQit9oi2tEzCEU6B59V8j6p8xGU= kev@Kevins-MacBook-Pro.local" >> /home/kev/.ssh/authorized_keys
chmod 600 /home/kev/.ssh/authorized_keys
echo "kev ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/90-cloud-init-users