#!/bin/bash

# File Name:    oshardening.sh
# Description:  Deploy changes advised by AWS Inspector
# Version:      1
# Author:       Ricky Beaty
# Date:         07/10/2021

#######################################
# Variables here
#######################################

# Check we are the root user
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Disable execution in the /tmp and /dev/shm directories.
echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev ,noexec,relatime 0 0" >> /etc/fstab
echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev ,noexec,relatime 0 0" >> /etc/fstab

# Disable unused filesystem services
echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf
echo "install hfs /bin/true" > /etc/modprobe.d/hfs.conf
echo "install hfsplus /bin/true" > /etc/modprobe.d/hfsplus.conf
echo "install freevxfs /bin/true" > /etc/ modprobe.d/freevxfs.conf
echo "install jjfs /bin/true" > /etc/modprobe.d/jjfs.conf
echo "install udf /bin/true" > /etc/modprobe.d/udf.conf

# Tie down core dumps
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

# Enable ASLR
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

# Explicitly set permission for MOTD.  Modern ubuntu creates the file on the fly, so we create it as root here.
touch /etc/motd
chown root:root /etc/motd
chmod 644 /etc/motd

# Disable routing stuff
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv4 .conf.all.send_redirects = 0"  >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.con f.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4 .conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4 .conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4 .icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_ig nore_bogus_error_responses = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6 .conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
echo "install sctp /bin/true" >> /etc/modprobe.d/sctp.conf
echo "install rds /bin/true" >> /etc/modprobe.d/rds.conf

# Restrict access to root's crontab
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

# Restrict access to ssh daemon config
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config

# Reconfigure some SSH parameters
echo "Protocol 2" >> /etc/ssh/sshd_config
echo "X11Forwarding no" >> /etc/ssh/sshd_config
sed -i -e "s/#MaxAuthTries 6/MaxAuthTries 4/g" /etc/ssh/sshd_config
sed -i -e "s/#IgnoreRhosts yes/IgnoreRhosts yes/g" /etc/ssh/sshd_config
sed -i -e "s/#PermitUserEnvironment no/PermitUserEnvironment no/g" /etc/ssh/sshd_config
sed -i -e "s/#LoginGraceTime 2m/LoginGraceTime 30/g" /etc/ssh/sshd_config

# Lock users out for 15 minutes after 5 failed login attempts
echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth