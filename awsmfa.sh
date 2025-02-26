#!/bin/bash

# File Name:    setup-awsmfa.sh
# Description:  Sets up the awsmfa script to easily refresh AWS session credentials.
#               Assumptions: The default aws profile is the one used to issue the aws sts get-session-token command.
# Version:      1
# Author:       Ricky Beaty
# Date:         25/02/25

#######################################

AWSLOGIN_FILE="$HOME/.awslogin.sh"
ZSHRC_FILE="$HOME/.zshrc"

# Ensure the user provides their MFA serial number
echo "Enter your AWS MFA Serial Number (e.g., arn:aws:iam::123456789012:mfa/my-mfa-device):"
read MFA_SERIAL

# Check if the script already exists
if [ -f "$AWSLOGIN_FILE" ]; then
    echo "⚠️  $AWSLOGIN_FILE already exists. Overwrite it? (y/n)"
    read -r OVERWRITE
    if [[ "$OVERWRITE" != "y" ]]; then
        echo "Aborting setup."
        exit 1
    fi
fi

# Write the awsmfa script to ~/.awslogin.sh
cat > "$AWSLOGIN_FILE" <<EOF
#!/bin/zsh

# File Name:    awslogin.sh
# Description:  Fetches temporary AWS credentials using MFA and updates the [bc] profile
# Version:      1
# Author:       Ricky Beaty
# Date:         25/02/25

#######################################

# Prompt for TOTP code
echo -n "Enter MFA token code: " && read TOKEN

# Fetch temporary AWS credentials
CREDENTIALS=\$(aws sts get-session-token \\
--serial-number $MFA_SERIAL \\
--token-code \$TOKEN \\
--output json | jq -r '.Credentials | "aws_access_key_id = " + .AccessKeyId + "\\naws_secret_access_key = " + .SecretAccessKey + "\\naws_session_token = " + .SessionToken')

# Define AWS credentials file
AWS_CREDENTIALS_FILE="\$HOME/.aws/credentials"
BACKUP_FILE="\$AWS_CREDENTIALS_FILE.backup"

# Backup the credentials file (overwrite previous backup)
cp "\$AWS_CREDENTIALS_FILE" "\$BACKUP_FILE"

# Remove old [bc] section if it exists and create a new credentials file
awk '
    BEGIN {found=0}
    /^\[bc\]/ {found=1; next}
    found && /^\[/ {found=0}
    !found {print}
' "\$AWS_CREDENTIALS_FILE" > "\$AWS_CREDENTIALS_FILE.tmp"

# Append the new [bc] profile with credentials
echo -e "\\n[bc]\\n\$CREDENTIALS" >> "\$AWS_CREDENTIALS_FILE.tmp"

# Replace the credentials file with the updated one
mv "\$AWS_CREDENTIALS_FILE.tmp" "\$AWS_CREDENTIALS_FILE"

echo "✅ AWS credentials updated for profile [bc]. Backup saved at \$BACKUP_FILE"
EOF

# Make the script executable
chmod +x "$AWSLOGIN_FILE"

# Add alias to Zsh profile if not already present
if ! grep -q "alias awsmfa=" "$ZSHRC_FILE"; then
    echo 'alias awsmfa="~/.awslogin.sh"' >> "$ZSHRC_FILE"
    echo "✅ Added 'awsmfa' alias to $ZSHRC_FILE"
    source "$ZSHRC_FILE"
else
    echo "⚠️  Alias 'awsmfa' already exists in $ZSHRC_FILE"
fi

echo "✅ Setup complete! Run 'awsmfa' to refresh your AWS credentials."