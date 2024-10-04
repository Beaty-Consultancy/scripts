#!/bin/bash

# File Name:    av.sh
# Description:  Install, update and schedule AV scans using ClamScan and CloudWatch Agent
# Version:      1.2
# Author:       Ricky Beaty
# Date:         30/09/24

#######################################

# Check we are the root user
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Check we are running on Ubuntu 18.04
if ! grep -q 'DISTRIB_ID=Ubuntu' /etc/lsb-release; then
   echo "This script is only suitable for Ubuntu 18.04" 
   exit 1
fi

# Check if we have Internet access
wget -q --spider http://google.com
if [ $? -ne 0 ]; then
    echo "No internet access. Please check your connection."
    exit 1
fi

# Install ClamAV and its daemon
apt update
apt install -y clamav clamav-daemon clamav-freshclam

# Update virus definitions
systemctl stop clamav-freshclam
freshclam
systemctl start clamav-freshclam

# Set up necessary directories and permissions
mkdir -p /var/lib/clamav
chown clamav:clamav /var/lib/clamav

# Start and enable clamav-daemon
systemctl start clamav-daemon
systemctl enable clamav-daemon

# Check if the daemon is running
if systemctl status clamav-daemon | grep -q "active (running)"; then
    echo "clamav-daemon is running."
else
    echo "clamav-daemon failed to start. Check the logs for details."
    exit 1
fi

# ** FIX OUTDATED SYSLOG SETTINGS **
# Update ClamAV systemd service files to use 'journal' instead of 'syslog'
sed -i 's/StandardOutput=syslog/StandardOutput=journal/' /lib/systemd/system/clamav-daemon.service
sed -i 's/StandardOutput=syslog/StandardOutput=journal/' /lib/systemd/system/clamav-freshclam.service

# Reload systemd to apply the service file changes
systemctl daemon-reload

# Restart services to apply the new configuration
systemctl restart clamav-daemon
systemctl restart clamav-freshclam

# ** CONTINUE WITH EXISTING SCRIPT **

# Set up AV log in common place
touch /var/log/av.log

# Install Cronie for scheduling
apt install -y cron

# Create the AV scanning script
cat <<EOT >> /root/av.sh
#!/bin/bash
# Check the age of AV definitions, and sync from S3 if outdated
if [[ \$(find "/var/lib/clamav/main.cvd" -mtime +35 -print) ]]; then
    echo "Virus definitions are outdated. Updating..."
    freshclam
fi
clamscan --infected --recursive --remove /
EOT

chmod +x /root/av.sh

# Set up nightly scan
(crontab -l 2>/dev/null; echo "10 4 * * * /root/av.sh >> /var/log/av.log") | crontab -

# Install CloudWatch logs if necessary
if [ -f "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl" ]; then
    echo "CloudWatch Agent is already installed."
else
    # Install the CloudWatch agent
    apt install -y amazon-cloudwatch-agent
fi

# ** Non-interactive CloudWatch Agent Configuration **

# Create CloudWatch Agent config file to monitor /var/log/av.log
cat <<EOT > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "root"
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/av.log",
            "log_group_name": "av-log-group",
            "log_stream_name": "{instance_id}",
            "timestamp_format": "%b %d %H:%M:%S"
          }
        ]
      }
    }
  }
}
EOT

# Start CloudWatch Agent using the configuration
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
-a fetch-config -m ec2 \
-c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json \
-s

# ** Check CloudWatch Agent Status **
if systemctl status amazon-cloudwatch-agent | grep -q "active (running)"; then
    echo "CloudWatch Agent is running."
else
    echo "CloudWatch Agent failed to start. Check the logs for details."
    exit 1
fi

# ** NEW STATUS CHECKS ADDED HERE **

# Check the status of clamav-freshclam
if systemctl status clamav-freshclam | grep -q "active (running)"; then
    echo "clamav-freshclam is running."
else
    echo "clamav-freshclam failed to start. Check the logs for details."
    exit 1
fi

# Check the status of clamav-daemon
if systemctl status clamav-daemon | grep -q "active (running)"; then
    echo "clamav-daemon is running."
else
    echo "clamav-daemon failed to start. Check the logs for details."
    exit 1
fi

# Add option to limit memory consumption during virus definition updates
echo "ConcurrentDatabaseReload no" >> /etc/clamav/clamd.conf

echo "AV setup completed successfully