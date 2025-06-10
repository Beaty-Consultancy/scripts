#!/bin/bash

# Get all bucket names
buckets=$(aws s3api list-buckets --query "Buckets[].Name" --output text)

# Loop through each bucket and check encryption status
for bucket in $buckets; do
    encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null)

    if [ $? -eq 0 ]; then
        algo=$(echo "$encryption" | jq -r '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm')
        echo "$bucket: Encryption ENABLED with $algo"
    else
        echo "$bucket: Encryption NOT ENABLED"
    fi
done