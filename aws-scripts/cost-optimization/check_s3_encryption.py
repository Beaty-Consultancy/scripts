#!/usr/bin/env python3
"""
AWS S3 Bucket Encryption Check Script

This script checks if S3 buckets have encryption enabled.
It identifies unencrypted buckets to help improve security posture.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime

# Constants
NOT_CONFIGURED = 'Not Configured'


def check_bucket_encryption(s3_client, bucket_name, bucket_info):
    """Check encryption status for a single bucket"""
    try:
        # Check bucket encryption
        encryption_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        
        # If we get here, encryption is enabled
        encryption_rules = encryption_response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        if encryption_rules:
            return {
                'bucket': bucket_name,
                'encryption': 'Enabled',
                'created': bucket_info['CreationDate'].isoformat()
            }, True, None
        else:
            return {
                'bucket': bucket_name,
                'encryption': NOT_CONFIGURED,
                'created': bucket_info['CreationDate'].isoformat()
            }, False, None
            
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
            # No encryption configured
            return {
                'bucket': bucket_name,
                'encryption': NOT_CONFIGURED,
                'created': bucket_info['CreationDate'].isoformat()
            }, False, None
        elif error_code == 'AccessDenied':
            return None, False, f"Access denied when checking encryption for bucket: {bucket_name}"
        else:
            return None, False, f"Error checking encryption for bucket {bucket_name}: {e.response['Error']['Message']}"


def check_s3_encryption(profile_name=None, region_filter=None):
    """
    Check S3 bucket encryption status across all buckets
    
    Args:
        profile_name (str): AWS profile name (optional)
        region_filter (str): Filter by region (not used for S3 as it's global)
        
    Returns:
        dict: Structured result for dashboard compatibility
    """
    
    try:
        # Initialize session with profile
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
        else:
            session = boto3.Session()
        
        # Initialize S3 client
        s3_client = session.client('s3')
        
        # Get all buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        encrypted_buckets = []
        unencrypted_buckets = []
        warnings = []
        
        # Check encryption for each bucket
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            bucket_info, is_encrypted, warning = check_bucket_encryption(s3_client, bucket_name, bucket)
            
            if warning:
                warnings.append(warning)
            elif bucket_info:
                if is_encrypted:
                    encrypted_buckets.append(bucket_info)
                else:
                    unencrypted_buckets.append(bucket_info)
        
        # Generate summary
        total_encrypted = len(encrypted_buckets)
        total_unencrypted = len(unencrypted_buckets)
        total_buckets = total_encrypted + total_unencrypted
        
        # Add warnings for unencrypted buckets
        if total_unencrypted > 0:
            warnings.append(f"{total_unencrypted} bucket(s) found without encryption")
        
        return {
            'status': 'Success',
            'message': f'{total_buckets} bucket(s) analyzed. {total_unencrypted} unencrypted bucket(s) found.',
            'timestamp': datetime.now().isoformat(),
            'total_buckets': str(total_buckets),
            'details': {
                'total_encrypted': total_encrypted,
                'total_unencrypted': total_unencrypted,
                'encrypted_buckets': encrypted_buckets,
                'unencrypted_buckets': unencrypted_buckets,
                'warnings': warnings
            }
        }
        
    except NoCredentialsError:
        return {
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'timestamp': datetime.now().isoformat(),
            'total_buckets': '0',
            'details': {
                'error_type': 'NoCredentialsError',
                'error_message': 'AWS credentials not found',
                'total_encrypted': 0,
                'total_unencrypted': 0,
                'encrypted_buckets': [],
                'unencrypted_buckets': [],
                'warnings': []
            }
        }
    
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        return {
            'status': 'Error',
            'message': f'AWS API error: {error_message}',
            'timestamp': datetime.now().isoformat(),
            'total_buckets': '0',
            'details': {
                'error_type': error_code,
                'error_message': error_message,
                'total_encrypted': 0,
                'total_unencrypted': 0,
                'encrypted_buckets': [],
                'unencrypted_buckets': [],
                'warnings': []
            }
        }
    
    except Exception as e:
        return {
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'total_buckets': '0',
            'details': {
                'error_type': 'UnexpectedError',
                'error_message': str(e),
                'total_encrypted': 0,
                'total_unencrypted': 0,
                'encrypted_buckets': [],
                'unencrypted_buckets': [],
                'warnings': []
            }
        }


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check AWS S3 bucket encryption status')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_s3_encryption(profile_name=args.profile)
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        # Summary output
        print(f"Status: {result['status']}")
        print(f"Message: {result['message']}")
        print(f"Total Buckets: {result['total_buckets']}")
        print(f"Encrypted Buckets: {result['details']['total_encrypted']}")
        print(f"Unencrypted Buckets: {result['details']['total_unencrypted']}")
        
        if result['details']['unencrypted_buckets']:
            print("\nUnencrypted Buckets:")
            for i, bucket in enumerate(result['details']['unencrypted_buckets'], 1):
                print(f"  {i}. {bucket['bucket']} (Created: {bucket['created']})")
        
        if result['details']['warnings']:
            print("\nWarnings:")
            for warning in result['details']['warnings']:
                print(f"  - {warning}")


if __name__ == "__main__":
    main()
