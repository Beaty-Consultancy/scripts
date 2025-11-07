#!/usr/bin/env python3
"""
AWS S3 Bucket Versioning Check Script

This script checks if S3 buckets have versioning enabled.
It identifies buckets with versioning disabled to help improve data protection.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime

# Constants
VERSIONING_DISABLED = 'Disabled'
VERSIONING_SUSPENDED = 'Suspended'


def check_bucket_versioning(s3_client, bucket_name, bucket_info):
    """Check versioning status for a single bucket"""
    try:
        # Get bucket versioning configuration
        versioning_response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        
        # Check versioning status
        versioning_status = versioning_response.get('Status', 'Disabled')
        
        bucket_details = {
            'bucket': bucket_name,
            'versioning_status': versioning_status,
            'created': bucket_info['CreationDate'].isoformat()
        }
        
        # Versioning is considered enabled if status is 'Enabled'
        is_enabled = versioning_status == 'Enabled'
        
        return bucket_details, is_enabled, None
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            return None, False, f"Access denied when checking versioning for bucket: {bucket_name}"
        else:
            return None, False, f"Error checking versioning for bucket {bucket_name}: {e.response['Error']['Message']}"


def check_s3_versioning(profile_name=None, region_filter=None):
    """
    Check S3 bucket versioning status across all buckets
    
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
        
        versioning_enabled_buckets = []
        versioning_disabled_buckets = []
        warnings = []
        
        # Check versioning for each bucket
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            bucket_info, is_enabled, warning = check_bucket_versioning(s3_client, bucket_name, bucket)
            
            if warning:
                warnings.append(warning)
            elif bucket_info:
                if is_enabled:
                    versioning_enabled_buckets.append(bucket_info)
                else:
                    versioning_disabled_buckets.append(bucket_info)
        
        # Generate summary
        total_enabled = len(versioning_enabled_buckets)
        total_disabled = len(versioning_disabled_buckets)
        total_buckets = total_enabled + total_disabled
        
        # Add warnings for buckets with versioning disabled
        if total_disabled > 0:
            warnings.append(f"{total_disabled} bucket(s) found with versioning disabled")
        
        return {
            'status': 'Success',
            'message': f'{total_buckets} bucket(s) analyzed. {total_disabled} bucket(s) with versioning disabled.',
            'timestamp': datetime.now().isoformat(),
            'total_buckets': str(total_buckets),
            'details': {
                'total_versioning_enabled': total_enabled,
                'total_versioning_disabled': total_disabled,
                'versioning_enabled_buckets': versioning_enabled_buckets,
                'versioning_disabled_buckets': versioning_disabled_buckets,
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
                'total_versioning_enabled': 0,
                'total_versioning_disabled': 0,
                'versioning_enabled_buckets': [],
                'versioning_disabled_buckets': [],
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
                'total_versioning_enabled': 0,
                'total_versioning_disabled': 0,
                'versioning_enabled_buckets': [],
                'versioning_disabled_buckets': [],
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
                'total_versioning_enabled': 0,
                'total_versioning_disabled': 0,
                'versioning_enabled_buckets': [],
                'versioning_disabled_buckets': [],
                'warnings': []
            }
        }


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check AWS S3 bucket versioning status')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_s3_versioning(profile_name=args.profile)
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        # Summary output
        print(f"Status: {result['status']}")
        print(f"Message: {result['message']}")
        print(f"Total Buckets: {result['total_buckets']}")
        print(f"Versioning Enabled: {result['details']['total_versioning_enabled']}")
        print(f"Versioning Disabled: {result['details']['total_versioning_disabled']}")
        
        if result['details']['versioning_disabled_buckets']:
            print("\nBuckets with Versioning Disabled:")
            for i, bucket in enumerate(result['details']['versioning_disabled_buckets'], 1):
                print(f"  {i}. {bucket['bucket']} (Status: {bucket['versioning_status']}, Created: {bucket['created']})")
        
        if result['details']['warnings']:
            print("\nWarnings:")
            for warning in result['details']['warnings']:
                print(f"  - {warning}")


if __name__ == "__main__":
    main()
