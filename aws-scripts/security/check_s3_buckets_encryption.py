#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Security Pillar
Check S3 Bucket Encryption Configuration

This script checks if S3 buckets have server-side encryption enabled.

Encryption Types Checked:
- AES256 (SSE-S3)
- aws:kms (SSE-KMS)
- aws:kms:dsse (SSE-KMS with Dual-layer Server-Side Encryption)
"""

import boto3
import json
import sys
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError


def get_s3_buckets(s3_client):
    """
    Get all S3 buckets
    
    Args:
        s3_client: Boto3 S3 client
        
    Returns:
        list: List of S3 buckets
    """
    try:
        response = s3_client.list_buckets()
        return response.get('Buckets', [])
    except ClientError as e:
        raise ClientError(e.response, e.operation_name) from e
    except Exception as e:
        raise RuntimeError(f"Failed to get S3 buckets: {str(e)}") from e


def get_bucket_location(s3_client, bucket_name):
    """
    Get the region of an S3 bucket
    
    Args:
        s3_client: Boto3 S3 client
        bucket_name: Name of the S3 bucket
        
    Returns:
        str: Bucket region
    """
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        location = response.get('LocationConstraint')
        # us-east-1 returns None as LocationConstraint
        return location if location else 'us-east-1'
    except ClientError:
        # If we can't get location, assume us-east-1
        return 'us-east-1'


def get_bucket_encryption(s3_client, bucket_name):
    """
    Get encryption configuration for an S3 bucket
    
    Args:
        s3_client: Boto3 S3 client
        bucket_name: Name of the S3 bucket
        
    Returns:
        dict: Encryption configuration details
    """
    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        
        if not rules:
            return {
                'encrypted': False,
                'encryption_type': None,
                'kms_key_id': None,
                'bucket_key_enabled': False
            }
        
        # Get the first rule (typically only one rule exists)
        rule = rules[0]
        sse_config = rule.get('ApplyServerSideEncryptionByDefault', {})
        
        encryption_type = sse_config.get('SSEAlgorithm')
        kms_key_id = sse_config.get('KMSMasterKeyID', 'N/A')
        bucket_key_enabled = rule.get('BucketKeyEnabled', False)
        
        return {
            'encrypted': True,
            'encryption_type': encryption_type,
            'kms_key_id': kms_key_id if encryption_type in ['aws:kms', 'aws:kms:dsse'] else 'N/A',
            'bucket_key_enabled': bucket_key_enabled
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
            # No encryption configuration found
            return {
                'encrypted': False,
                'encryption_type': None,
                'kms_key_id': None,
                'bucket_key_enabled': False
            }
        else:
            # Other error - assume we can't determine encryption status
            return {
                'encrypted': None,
                'encryption_type': 'Error',
                'kms_key_id': None,
                'bucket_key_enabled': False,
                'error': str(e)
            }


def analyze_bucket_encryption(s3_client, bucket):
    """
    Analyze encryption configuration for an S3 bucket
    
    Args:
        s3_client: Boto3 S3 client
        bucket: S3 bucket dict
        
    Returns:
        dict: Complete bucket encryption analysis
    """
    bucket_name = bucket['Name']
    creation_date = bucket['CreationDate']
    
    # Get bucket location
    bucket_region = get_bucket_location(s3_client, bucket_name)
    
    # Get encryption configuration
    encryption_config = get_bucket_encryption(s3_client, bucket_name)
    
    return {
        'bucket_name': bucket_name,
        'bucket_region': bucket_region,
        'creation_date': creation_date.isoformat() if creation_date else 'Unknown',
        'encrypted': encryption_config['encrypted'],
        'encryption_type': encryption_config['encryption_type'],
        'kms_key_id': encryption_config['kms_key_id'],
        'bucket_key_enabled': encryption_config['bucket_key_enabled'],
        'error': encryption_config.get('error')
    }


def check_s3_encryption():
    """
    Check S3 bucket encryption configuration
    
    Returns:
        dict: Complete check results
    """
    try:
        # S3 is a global service, but we use us-east-1 for consistency
        s3_client = boto3.client('s3', region_name='us-east-1')
        
        # Get all buckets
        buckets = get_s3_buckets(s3_client)
        
        # Analyze each bucket
        bucket_analyses = []
        unencrypted_buckets = []
        error_buckets = []
        
        for bucket in buckets:
            analysis = analyze_bucket_encryption(s3_client, bucket)
            bucket_analyses.append(analysis)
            
            if analysis['error']:
                error_buckets.append(analysis)
            elif analysis['encrypted'] is False:
                unencrypted_buckets.append(analysis)
        
        return {
            'total_buckets': len(buckets),
            'encrypted_buckets': len([b for b in bucket_analyses if b['encrypted'] is True]),
            'unencrypted_buckets': len(unencrypted_buckets),
            'error_buckets': len(error_buckets),
            'buckets': bucket_analyses,
            'unencrypted_items': unencrypted_buckets,
            'error_items': error_buckets,
            'error': None
        }
        
    except ClientError as e:
        error_msg = f"AWS API error: {str(e)}"
        return {
            'total_buckets': 0,
            'encrypted_buckets': 0,
            'unencrypted_buckets': 0,
            'error_buckets': 0,
            'buckets': [],
            'unencrypted_items': [],
            'error_items': [],
            'error': error_msg
        }
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        return {
            'total_buckets': 0,
            'encrypted_buckets': 0,
            'unencrypted_buckets': 0,
            'error_buckets': 0,
            'buckets': [],
            'unencrypted_items': [],
            'error_items': [],
            'error': error_msg
        }


def determine_encryption_status(stats):
    """Determine overall encryption status and message"""
    total_buckets = stats['total_buckets']
    unencrypted_buckets = stats['unencrypted_buckets']
    error_buckets = stats['error_buckets']
    
    if total_buckets == 0:
        status = 'Success'
        message = 'No S3 buckets found in the account.'
    elif unencrypted_buckets == 0 and error_buckets == 0:
        status = 'Success'
        message = f'All {total_buckets} S3 buckets have encryption enabled.'
    elif unencrypted_buckets > 0 and error_buckets == 0:
        status = 'Warning'
        message = f'Found {unencrypted_buckets} unencrypted S3 buckets out of {total_buckets} total buckets.'
    elif unencrypted_buckets == 0 and error_buckets > 0:
        status = 'Warning'
        message = f'Could not determine encryption status for {error_buckets} S3 buckets out of {total_buckets} total buckets.'
    else:
        status = 'Warning'
        message = f'Found {unencrypted_buckets} unencrypted and {error_buckets} error S3 buckets out of {total_buckets} total buckets.'
    
    return status, message


def check_s3_buckets_encryption(profile_name=None):
    """
    Main function to check S3 bucket encryption configuration
    
    Args:
        profile_name: AWS profile name (optional)
        
    Returns:
        dict: Complete check results in JSON format
    """
    timestamp = datetime.now(timezone.utc).isoformat() + 'Z'
    
    try:
        # Create session and S3 client
        session = boto3.Session(profile_name=profile_name)
        
        # Override the default client creation for this specific check
        original_client = boto3.client
        boto3.client = lambda service, **kwargs: session.client(service, **kwargs)
        
        try:
            # Perform the encryption check
            result = check_s3_encryption()
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        stats = {
            'total_buckets': result['total_buckets'],
            'encrypted_buckets': result['encrypted_buckets'],
            'unencrypted_buckets': result['unencrypted_buckets'],
            'error_buckets': result['error_buckets']
        }
        
        status, message = determine_encryption_status(stats)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 's3_bucket_encryption',
            'total_buckets': result['total_buckets'],
            'encrypted_buckets': result['encrypted_buckets'],
            'unencrypted_buckets': result['unencrypted_buckets'],
            'error_buckets': result['error_buckets'],
            'buckets': result['buckets'],
            'unencrypted_items': result['unencrypted_items']
        }
        
        # Add error details if any
        if result['error']:
            final_result['error'] = result['error']
        
        if result['error_items']:
            final_result['error_items'] = result['error_items']
        
        return final_result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'check_type': 's3_bucket_encryption',
            'total_buckets': 0,
            'encrypted_buckets': 0,
            'unencrypted_buckets': 0,
            'error_buckets': 0,
            'buckets': [],
            'unencrypted_items': []
        }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'check_type': 's3_bucket_encryption',
            'total_buckets': 0,
            'encrypted_buckets': 0,
            'unencrypted_buckets': 0,
            'error_buckets': 0,
            'buckets': [],
            'unencrypted_items': []
        }


def print_bucket_details(bucket, index):
    """Print detailed information about an S3 bucket"""
    print(f"\n{index}. S3 Bucket Details:")
    print(f"   Bucket Name: {bucket['bucket_name']}")
    print(f"   Region: {bucket['bucket_region']}")
    print(f"   Created: {bucket['creation_date']}")
    
    # Determine encryption status display
    if bucket['encrypted'] is True:
        encryption_status = 'Yes'
    elif bucket['encrypted'] is False:
        encryption_status = 'No'
    else:
        encryption_status = 'Unknown'
    print(f"   Encrypted: {encryption_status}")
    
    if bucket['encrypted']:
        print(f"   Encryption Type: {bucket['encryption_type']}")
        if bucket['kms_key_id'] and bucket['kms_key_id'] != 'N/A':
            print(f"   KMS Key: {bucket['kms_key_id']}")
        if bucket['bucket_key_enabled']:
            print("   Bucket Key Enabled: Yes")
    
    if bucket.get('error'):
        print(f"   Error: {bucket['error']}")


def print_basic_summary(result):
    """Print basic summary information"""
    print("\nS3 Bucket Encryption Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Buckets: {result['total_buckets']}")
    print(f"Encrypted Buckets: {result['encrypted_buckets']}")
    print(f"Unencrypted Buckets: {result['unencrypted_buckets']}")
    print(f"Error Buckets: {result['error_buckets']}")


def print_unencrypted_buckets(buckets):
    """Print details of unencrypted S3 buckets"""
    if buckets:
        print(f"\nUnencrypted S3 Buckets ({len(buckets)}):")
        for i, bucket in enumerate(buckets, 1):
            print_bucket_details(bucket, i)


def print_error_buckets(buckets):
    """Print details of S3 buckets with errors"""
    if buckets:
        print(f"\nS3 Buckets with Errors ({len(buckets)}):")
        for i, bucket in enumerate(buckets, 1):
            print_bucket_details(bucket, i)


def print_summary_output(result):
    """Print human-readable summary output"""
    print_basic_summary(result)
    
    unencrypted_buckets = result.get('unencrypted_items', [])
    print_unencrypted_buckets(unencrypted_buckets)
    
    error_buckets = result.get('error_items', [])
    print_error_buckets(error_buckets)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check S3 bucket encryption configuration")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_s3_buckets_encryption(profile_name=args.profile)
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        print_summary_output(result)
    
    # Exit with appropriate code
    if result['status'] == 'Error':
        sys.exit(1)
    elif result['status'] == 'Warning':
        sys.exit(0)  # Warning is not a failure for script execution
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
