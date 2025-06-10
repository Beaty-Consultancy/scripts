#!/bin/bash
# File Name:    OSversions.sh
# Description:  Starts up stopped instances, checks OS versions and instance tags, stops previously stopped instances
# Version:      3
# Author:       Ricky Beaty
# Date:         09/04/25

#######################################
set -e

REGION="eu-west-2"
WAIT_TIME=120

# Function to retrieve and print a table merging SSM OS info and EC2 instance tags.
print_instance_table() {
  local SSM_OUTPUT="$1"

  # Get a unique list of instance IDs from the SSM output.
  INSTANCE_IDS=$(echo "$SSM_OUTPUT" | jq -r '.[].InstanceId' | sort -u | xargs)

  # Retrieve EC2 instance details (to pull instance tags)
  EC2_OUTPUT=$(aws ec2 describe-instances \
    --region "$REGION" \
    --instance-ids $INSTANCE_IDS \
    --output json)

  # Print table header
  printf "%-20s %-30s %-20s %-20s %-20s\n" "InstanceId" "Name" "Environment" "PlatformName" "PlatformVersion"
  printf "%-20s %-30s %-20s %-20s %-20s\n" "----------" "----" "-----------" "------------" "---------------"
  
  # Loop over each instance info from SSM
  echo "$SSM_OUTPUT" | jq -c '.[]' | while read -r instance; do
    instance_id=$(echo "$instance" | jq -r '.InstanceId')
    platform_name=$(echo "$instance" | jq -r '.PlatformName')
    platform_version=$(echo "$instance" | jq -r '.PlatformVersion')
    
    # Query the EC2 output for the corresponding instance and extract tag values
    name=$(echo "$EC2_OUTPUT" | jq -r --arg iid "$instance_id" '
      .Reservations[]?.Instances[]? 
      | select(.InstanceId == $iid)
      | (.Tags[]? | select(.Key=="Name") | .Value) // "N/A"
    ')
    environment=$(echo "$EC2_OUTPUT" | jq -r --arg iid "$instance_id" '
      .Reservations[]?.Instances[]? 
      | select(.InstanceId == $iid)
      | (.Tags[]? | select(.Key=="Environment") | .Value) // "N/A"
    ')
    
    printf "%-20s %-30s %-20s %-20s %-20s\n" "$instance_id" "$name" "$environment" "$platform_name" "$platform_version"
  done
}

echo "🔍 Finding stopped instances in $REGION..."
# Capture instance IDs into an array
read -a STOPPED_INSTANCES <<< "$(aws ec2 describe-instances \
  --region "$REGION" \
  --filters Name=instance-state-name,Values=stopped \
  --query 'Reservations[].Instances[].InstanceId' \
  --output text)"

if [ ${#STOPPED_INSTANCES[@]} -eq 0 ]; then
  echo "✅ No stopped instances found. All instances are running."
  echo "📦 Getting OS info (and instance tags) from SSM for running instances..."

  # Retrieve SSM information in JSON format for all running instances.
  SSM_OUTPUT=$(aws ssm describe-instance-information \
    --region "$REGION" \
    --query 'InstanceInformationList[].{InstanceId:InstanceId, PlatformName:PlatformName, PlatformVersion:PlatformVersion}' \
    --output json)

  print_instance_table "$SSM_OUTPUT"
  exit 0
fi

echo "🟢 Starting stopped instances: ${STOPPED_INSTANCES[@]}"
aws ec2 start-instances --region "$REGION" --instance-ids "${STOPPED_INSTANCES[@]}" > /dev/null

echo "⏳ Waiting $WAIT_TIME seconds for instances to start and register with SSM..."
sleep $WAIT_TIME

echo "📦 Getting OS info (and instance tags) from SSM for the newly started instances..."
# Retrieve SSM information in JSON format
SSM_OUTPUT=$(aws ssm describe-instance-information \
  --region "$REGION" \
  --query 'InstanceInformationList[].{InstanceId:InstanceId, PlatformName:PlatformName, PlatformVersion:PlatformVersion}' \
  --output json)

print_instance_table "$SSM_OUTPUT"

# (Optional) Check if all originally stopped instances are present in the SSM output
SSM_INSTANCE_IDS=( $(echo "$SSM_OUTPUT" | jq -r '.[].InstanceId') )
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