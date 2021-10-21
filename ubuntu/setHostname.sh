#!/bin/bash

# File Name:    setHostname.sh
# Description:  Sets the operating system's hostname to match the EC2 Name tag value
# Version:      1
# Author:       Ricky Beaty
# Date:         20/10/2021

apt -f install -y
apt update
apt install -y jq awscli
instance_id=$(curl http://169.254.169.254/latest/meta-data/instance-id)
hostname=$(aws ec2 describe-tags --filters "Name=resource-id,Values=$instance_id" "Name=key,Values=Name" --region eu-west-1 |jq -r ".Tags[0].Value")
hostnamectl set-hostname $hostname