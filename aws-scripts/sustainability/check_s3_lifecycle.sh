#!/bin/bash

# List all S3 buckets in the account
buckets=$(aws s3api list-buckets --query "Buckets[].Name" --output text)

# Iterate over each bucket
for bucket in $buckets; do
    echo "Checking bucket: $bucket"

    # Attempt to retrieve the lifecycle configuration for the bucket
    lifecycle=$(aws s3api get-bucket-lifecycle-configuration --bucket "$bucket" 2>&1)

    # Check if the bucket has a lifecycle policy
    if [[ $? -eq 0 ]]; then
        echo "Lifecycle policy found for bucket: $bucket"
        echo "$lifecycle" | jq
    else
        # Check if the error is due to no lifecycle configuration
        if echo "$lifecycle" | grep -q 'NoSuchLifecycleConfiguration'; then
            echo "No lifecycle policy found for bucket: $bucket"
        else
            echo "Error retrieving lifecycle policy for bucket: $bucket"
            echo "$lifecycle"
        fi
    fi

    echo "----------------------------------------"
done
