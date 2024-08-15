# Fail2Ban Installation and Configuration Script

This repository contains a script to automatically install and configure Fail2Ban on various Linux distributions, including Amazon Linux 2, Amazon Linux 2023, and Ubuntu. The script also enables and starts `rsyslog` on Amazon Linux 2023.

## Features

- **Automatic Installation**: The script detects the Linux distribution and version, and installs Fail2Ban accordingly.
- **Custom Configuration**: The script sets up a custom `jail.local` configuration for Fail2Ban and replaces the default `sshd.conf` filter with a custom version provided in the repository.
- **Rsyslog Setup**: On Amazon Linux 2023, the script installs and enables `rsyslog`.
- **Service Management**: The script ensures that both Fail2Ban and Rsyslog services are enabled and running.

## Requirements

- Amazon Linux 2, Amazon Linux 2023, or Ubuntu.
- Superuser (root) privileges to run the script.

## Usage

### 1. Clone the Repository

First, clone this repository to your local machine:

```bash
git clone https://github.com/Beaty-Consultancy/scripts.git
cd scripts/fail2ban
```

### 2. Custom Configuration (Optional)

If you have a custom `sshd.conf` file for Fail2Ban, place it in the root directory of this repository. This file will replace the default `sshd.conf` after installation.

### 3. Run the Script

Make the script executable:

```bash
chmod +x setup_fail2ban.sh
```

Then, execute the script with superuser privileges:

```bash
sudo ./setup_fail2ban.sh
```

### 4. Verify Installation

After running the script, you can verify that Fail2Ban and Rsyslog are installed and running:

```bash
sudo systemctl status fail2ban
sudo systemctl status rsyslog
```

## Script Overview

The script performs the following actions:

1. **Detects the Linux Distribution and Version**: Determines whether the system is Amazon Linux 2, Amazon Linux 2023, or Ubuntu.

2. **Installs Fail2Ban**:
   - **Amazon Linux 2**: Installs Fail2Ban using EPEL.
   - **Amazon Linux 2023**: Configures a custom COPR repository to install Fail2Ban.
   - **Ubuntu**: Installs Fail2Ban using `apt`.

3. **Configures Fail2Ban**:
   - Creates a `jail.local` file with predefined parameters.
   - Replaces the default `sshd.conf` in `/etc/fail2ban/filter.d/` with a custom version if provided.

4. **Rsyslog Setup (Amazon Linux 2023)**:
   - Installs and enables `rsyslog` for log handling.

5. **Service Management**:
   - Ensures Fail2Ban and Rsyslog are enabled and running.

## Customization

- **jail.local**: The configuration in `jail.local` can be modified to suit your security requirements.
- **sshd.conf**: Replace or edit the custom `sshd.conf` file in this repository to adjust the Fail2Ban filters.

## Troubleshooting

- Ensure you have superuser privileges when running the script.
- Check the script's output for any errors during installation.
- Verify that the custom `sshd.conf` file replaces the original conf file in the script's directory.