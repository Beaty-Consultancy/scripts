#!/bin/bash

# File Name:    OSversions.sh
# Description:  Strats up stopped instances, checks OS versions, stops previously stopped instances
# Version:      1
# Author:       Ricky Beaty
# Date:         09/04/25

#######################################
set -e

REGION="us-east-1"
WAIT_TIME=120

echo "🔍 Finding stopped instances in $REGION..."
# Capture instance IDs into an array
read -a STOPPED_INSTANCES <<< "$(aws ec2 describe-instances \
  --region "$REGION" \
  --filters Name=instance-state-name,Values=stopped \
  --query 'Reservations[].Instances[].InstanceId' \
  --output text)"

if [ ${#STOPPED_INSTANCES[@]} -eq 0 ]; then
  echo "✅ No stopped instances found."
  exit 0
fi

echo "🟢 Starting stopped instances: ${STOPPED_INSTANCES[@]}"
aws ec2 start-instances --region "$REGION" --instance-ids "${STOPPED_INSTANCES[@]}" > /dev/null

echo "⏳ Waiting $WAIT_TIME seconds for instances to start and register with SSM..."
sleep $WAIT_TIME

echo "📦 Getting OS info from SSM for the newly started instances..."

# Retrieve SSM information in JSON format
SSM_OUTPUT=$(aws ssm describe-instance-information \
  --region "$REGION" \
  --query 'InstanceInformationList[].{InstanceId:InstanceId, PlatformName:PlatformName, PlatformVersion:PlatformVersion}' \
  --output json)

# Display the output as a table using jq and column
echo "$SSM_OUTPUT" | jq -r '(["InstanceId", "PlatformName", "PlatformVersion"], (.[] | [.InstanceId, .PlatformName, .PlatformVersion])) | @tsv' | column -t

# Extract Instance IDs reported by SSM
SSM_INSTANCE_IDS=( $(echo "$SSM_OUTPUT" | jq -r '.[].InstanceId') )

# Check which of the originally stopped instances are missing in the SSM results
MISSING_IDS=()
for id in "${STOPPED_INSTANCES[@]}"; do
    found=false
    for ssm_id in "${SSM_INSTANCE_IDS[@]}"; do
        if [[ "$ssm_id" == "$id" ]]; then
            found=true
            break
        fi
    done
    if ! $found; then
        MISSING_IDS+=("$id")
    fi
done

# If any are missing, show a warning
if [[ ${#MISSING_IDS[@]} -gt 0 ]]; then
    echo "⚠️  Warning: The following instances were not found in the SSM inventory:"
    for missing in "${MISSING_IDS[@]}"; do
       echo "   - $missing"
    done
else
    echo "✅ All started instances are present in the SSM inventory."
fi

echo "🔴 Stopping the instances again: ${STOPPED_INSTANCES[@]}"
aws ec2 stop-instances --region "$REGION" --instance-ids "${STOPPED_INSTANCES[@]}" > /dev/null

echo "✅ Done."