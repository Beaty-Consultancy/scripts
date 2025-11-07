#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Sustainability Pillar
Check Large S3 Buckets

This script identifies S3 buckets with significant storage usage (default: >1GB).
"""

import boto3
import json
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError
import sys


def get_bucket_size_cloudwatch(bucket_name, region='us-east-1'):
    """
    Get bucket size using CloudWatch metrics (more accurate for large buckets)
    
    Args:
        bucket_name: Name of the S3 bucket
        region: AWS region
        
    Returns:
        int: Bucket size in bytes
    """
    try:
        cloudwatch = boto3.client('cloudwatch', region_name=region)
        
        # Get the most recent BucketSizeBytes metric
        end_time = datetime.now()
        start_time = end_time - timedelta(days=2)  # Look back 2 days for recent data
        
        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/S3',
            MetricName='BucketSizeBytes',
            Dimensions=[
                {'Name': 'BucketName', 'Value': bucket_name},
                {'Name': 'StorageType', 'Value': 'StandardStorage'}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,  # Daily
            Statistics=['Average']
        )
        
        if response['Datapoints']:
            # Get the most recent datapoint
            latest = max(response['Datapoints'], key=lambda x: x['Timestamp'])
            return int(latest['Average'])
        
        return 0
    except Exception:
        return 0


def get_bucket_region(bucket_name):
    """
    Get the region where the bucket is located
    
    Args:
        bucket_name: Name of the S3 bucket
        
    Returns:
        str: AWS region name
    """
    try:
        s3 = boto3.client('s3')
        response = s3.get_bucket_location(Bucket=bucket_name)
        region = response['LocationConstraint']
        # us-east-1 returns None
        return region if region else 'us-east-1'
    except Exception:
        return 'us-east-1'


def calculate_bucket_size_objects(bucket_name, region):
    """
    Calculate bucket size by summing object sizes (fallback method)
    
    Args:
        bucket_name: Name of the S3 bucket
        region: AWS region
        
    Returns:
        tuple: (total_size_bytes, object_count)
    """
    try:
        s3 = boto3.client('s3', region_name=region)
        total_size = 0
        object_count = 0
        
        paginator = s3.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=bucket_name)
        
        for page in page_iterator:
            if 'Contents' in page:
                for obj in page['Contents']:
                    total_size += obj['Size']
                    object_count += 1
        
        return total_size, object_count
    except Exception:
        return 0, 0


def format_bytes_readable(bytes_value):
    """
    Convert bytes to human readable format
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        str: Formatted byte string
    """
    if bytes_value == 0:
        return "0 B"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    
    return f"{bytes_value:.2f} EB"


def analyze_bucket_size(bucket_name, size_threshold_gb=1.0):
    """
    Analyze a bucket's size and determine if it exceeds the threshold
    
    Args:
        bucket_name: Name of the S3 bucket
        size_threshold_gb: Size threshold in GB
        
    Returns:
        dict: Bucket analysis result
    """
    try:
        # Get bucket region first
        region = get_bucket_region(bucket_name)
        
        # Try CloudWatch metrics first (more efficient for large buckets)
        size_bytes = get_bucket_size_cloudwatch(bucket_name, region)
        object_count = None
        method = "CloudWatch Metrics"
        
        # If CloudWatch doesn't have recent data, fall back to object enumeration
        if size_bytes == 0:
            size_bytes, object_count = calculate_bucket_size_objects(bucket_name, region)
            method = "Object Enumeration"
        
        size_gb = size_bytes / (1024**3)  # Convert bytes to GB
        
        return {
            'bucket_name': bucket_name,
            'region': region,
            'size_bytes': size_bytes,
            'size_gb': round(size_gb, 2),
            'size_readable': format_bytes_readable(size_bytes),
            'object_count': object_count,
            'method': method,
            'exceeds_threshold': size_gb > size_threshold_gb,
            'error': None
        }
        
    except Exception as e:
        return {
            'bucket_name': bucket_name,
            'region': 'unknown',
            'size_bytes': 0,
            'size_gb': 0,
            'size_readable': '0 B',
            'object_count': 0,
            'method': 'error',
            'exceeds_threshold': False,
            'error': str(e)
        }


def check_large_s3_buckets_all(size_threshold_gb=1.0, max_workers=10):
    """
    Check all S3 buckets for large storage usage
    
    Args:
        size_threshold_gb: Size threshold in GB to consider a bucket large
        max_workers: Maximum number of concurrent workers
        
    Returns:
        dict: Complete check results
    """
    try:
        # Get all S3 buckets
        s3_client = boto3.client('s3')
        response = s3_client.list_buckets()
        bucket_names = [bucket['Name'] for bucket in response.get('Buckets', [])]
        
        # Analyze buckets concurrently
        bucket_analyses = []
        large_buckets = []
        error_buckets = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all bucket checks
            future_to_bucket = {
                executor.submit(analyze_bucket_size, bucket_name, size_threshold_gb): bucket_name 
                for bucket_name in bucket_names
            }
            
            # Process results as they complete
            for future in as_completed(future_to_bucket):
                try:
                    result = future.result()
                    bucket_analyses.append(result)
                    
                    # Categorize buckets
                    if result.get('error'):
                        error_buckets.append(result)
                    elif result['exceeds_threshold']:
                        large_buckets.append(result)
                        
                except Exception as e:
                    bucket_name = future_to_bucket[future]
                    error_result = {
                        'bucket_name': bucket_name,
                        'region': 'unknown',
                        'size_bytes': 0,
                        'size_gb': 0,
                        'size_readable': '0 B',
                        'object_count': 0,
                        'method': 'error',
                        'exceeds_threshold': False,
                        'error': f"Processing error: {str(e)}"
                    }
                    bucket_analyses.append(error_result)
                    error_buckets.append(error_result)
        
        # Calculate total storage
        total_storage_bytes = sum(
            bucket['size_bytes'] for bucket in bucket_analyses if not bucket.get('error')
        )
        
        return {
            'total_buckets': len(bucket_names),
            'large_buckets': len(large_buckets),
            'compliant_buckets': len(bucket_analyses) - len(large_buckets) - len(error_buckets),
            'error_buckets': len(error_buckets),
            'size_threshold_gb': size_threshold_gb,
            'total_storage_bytes': total_storage_bytes,
            'total_storage_readable': format_bytes_readable(total_storage_bytes),
            'buckets': bucket_analyses,
            'non_compliant_items': large_buckets,
            'compliant_items': [b for b in bucket_analyses if not b['exceeds_threshold'] and not b.get('error')],
            'error_items': error_buckets,
            'error': None
        }
        
    except ClientError as e:
        error_msg = f"AWS API error: {str(e)}"
        return {
            'total_buckets': 0,
            'large_buckets': 0,
            'compliant_buckets': 0,
            'error_buckets': 0,
            'size_threshold_gb': size_threshold_gb,
            'total_storage_bytes': 0,
            'total_storage_readable': '0 B',
            'buckets': [],
            'non_compliant_items': [],
            'compliant_items': [],
            'error_items': [],
            'error': error_msg
        }
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        return {
            'total_buckets': 0,
            'large_buckets': 0,
            'compliant_buckets': 0,
            'error_buckets': 0,
            'size_threshold_gb': size_threshold_gb,
            'total_storage_bytes': 0,
            'total_storage_readable': '0 B',
            'buckets': [],
            'non_compliant_items': [],
            'compliant_items': [],
            'error_items': [],
            'error': error_msg
        }


def determine_large_buckets_status(stats):
    """Determine overall large buckets status and message"""
    total_buckets = stats['total_buckets']
    large_buckets = stats['large_buckets']
    error_buckets = stats['error_buckets']
    threshold_gb = stats['size_threshold_gb']
    
    if total_buckets == 0:
        status = 'Success'
        message = 'No S3 buckets found in the account.'
    elif large_buckets == 0 and error_buckets == 0:
        status = 'Success'
        message = f'No buckets exceed {threshold_gb}GB threshold out of {total_buckets} total buckets.'
    elif large_buckets > 0 and error_buckets == 0:
        status = 'Warning'
        message = f'Found {large_buckets} buckets exceeding {threshold_gb}GB threshold out of {total_buckets} total buckets.'
    elif large_buckets == 0 and error_buckets > 0:
        status = 'Warning'
        message = f'Could not determine size for {error_buckets} buckets out of {total_buckets} total buckets.'
    else:
        status = 'Warning'
        message = f'Found {large_buckets} large and {error_buckets} error buckets out of {total_buckets} total buckets.'
    
    return status, message


def check_large_s3_buckets(profile_name=None, size_threshold_gb=1.0, max_workers=10):
    """
    Main function to check for large S3 buckets
    
    Args:
        profile_name: AWS profile name (optional)
        size_threshold_gb: Size threshold in GB to consider a bucket large
        max_workers: Maximum number of concurrent workers
        
    Returns:
        dict: Complete check results in JSON format
    """
    timestamp = datetime.now(timezone.utc).isoformat() + 'Z'
    
    try:
        # Create session
        session = boto3.Session(profile_name=profile_name)
        
        # Override the default client creation for this specific check
        original_client = boto3.client
        boto3.client = lambda service, **kwargs: session.client(service, **kwargs)
        
        try:
            # Perform the large buckets check
            result = check_large_s3_buckets_all(size_threshold_gb, max_workers)
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        stats = {
            'total_buckets': result['total_buckets'],
            'large_buckets': result['large_buckets'],
            'error_buckets': result['error_buckets'],
            'size_threshold_gb': result['size_threshold_gb']
        }
        
        status, message = determine_large_buckets_status(stats)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'large_s3_buckets',
            'total_buckets': result['total_buckets'],
            'large_buckets': result['large_buckets'],
            'compliant_buckets': result['compliant_buckets'],
            'error_buckets': result['error_buckets'],
            'size_threshold_gb': result['size_threshold_gb'],
            'total_storage_bytes': result['total_storage_bytes'],
            'total_storage_readable': result['total_storage_readable'],
            'buckets': result['buckets'],
            'non_compliant_items': result['non_compliant_items']
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
            'check_type': 'large_s3_buckets',
            'total_buckets': 0,
            'large_buckets': 0,
            'compliant_buckets': 0,
            'error_buckets': 0,
            'size_threshold_gb': size_threshold_gb,
            'total_storage_bytes': 0,
            'total_storage_readable': '0 B',
            'buckets': [],
            'non_compliant_items': []
        }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'check_type': 'large_s3_buckets',
            'total_buckets': 0,
            'large_buckets': 0,
            'compliant_buckets': 0,
            'error_buckets': 0,
            'size_threshold_gb': size_threshold_gb,
            'total_storage_bytes': 0,
            'total_storage_readable': '0 B',
            'buckets': [],
            'non_compliant_items': []
        }


def print_bucket_details(bucket, index):
    """Print detailed information about a bucket"""
    print(f"\n{index}. Bucket Details:")
    print(f"   Bucket Name: {bucket['bucket_name']}")
    print(f"   Region: {bucket['region']}")
    print(f"   Size: {bucket['size_readable']} ({bucket['size_gb']} GB)")
    print(f"   Object Count: {bucket['object_count'] if bucket['object_count'] is not None else 'N/A'}")
    print(f"   Method: {bucket['method']}")
    print(f"   Exceeds Threshold: {'Yes' if bucket['exceeds_threshold'] else 'No'}")
    
    if bucket.get('error'):
        print(f"   Error: {bucket['error']}")


def print_basic_summary(result):
    """Print basic summary information"""
    print("\nLarge S3 Buckets Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Buckets: {result['total_buckets']}")
    print(f"Large Buckets: {result['large_buckets']}")
    print(f"Compliant Buckets: {result['compliant_buckets']}")
    print(f"Error Buckets: {result['error_buckets']}")
    print(f"Size Threshold: {result['size_threshold_gb']} GB")
    print(f"Total Storage: {result['total_storage_readable']}")


def print_large_buckets(buckets):
    """Print details of large buckets"""
    if buckets:
        print(f"\nLarge Buckets ({len(buckets)}):")
        # Sort by size (largest first)
        sorted_buckets = sorted(buckets, key=lambda x: x['size_bytes'], reverse=True)
        for i, bucket in enumerate(sorted_buckets, 1):
            print_bucket_details(bucket, i)


def print_error_buckets(buckets):
    """Print details of buckets with errors"""
    if buckets:
        print(f"\nBuckets with Errors ({len(buckets)}):")
        for i, bucket in enumerate(buckets, 1):
            print_bucket_details(bucket, i)


def print_summary_output(result):
    """Print human-readable summary output"""
    print_basic_summary(result)
    
    large_buckets = result.get('non_compliant_items', [])
    print_large_buckets(large_buckets)
    
    error_buckets = result.get('error_items', [])
    print_error_buckets(error_buckets)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check for large S3 buckets")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    parser.add_argument('--threshold', type=float, default=1.0,
                       help='Size threshold in GB (default: 1.0)')
    parser.add_argument('--max-workers', type=int, default=10,
                       help='Maximum number of concurrent workers (default: 10)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_large_s3_buckets(
        profile_name=args.profile,
        size_threshold_gb=args.threshold,
        max_workers=args.max_workers
    )
    
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