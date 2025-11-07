#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Sustainability Pillar
Check S3 Bucket Lifecycle Policies

This script checks S3 buckets for lifecycle policies.
"""

import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError
import sys


def get_bucket_lifecycle_configuration(s3_client, bucket_name):
    """
    Get lifecycle configuration for a specific bucket
    
    Args:
        s3_client: Boto3 S3 client
        bucket_name: Name of the S3 bucket
        
    Returns:
        dict: Lifecycle configuration info or error details
    """
    try:
        response = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        lifecycle_config = response.get('Rules', [])
        
        return {
            'bucket_name': bucket_name,
            'has_lifecycle_policy': True,
            'lifecycle_rules_count': len(lifecycle_config),
            'lifecycle_rules': lifecycle_config,
            'error': None
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        
        if error_code == 'NoSuchLifecycleConfiguration':
            return {
                'bucket_name': bucket_name,
                'has_lifecycle_policy': False,
                'lifecycle_rules_count': 0,
                'lifecycle_rules': [],
                'error': None
            }
        else:
            return {
                'bucket_name': bucket_name,
                'has_lifecycle_policy': None,
                'lifecycle_rules_count': 0,
                'lifecycle_rules': [],
                'error': f"Error retrieving lifecycle policy: {str(e)}"
            }
    except Exception as e:
        return {
            'bucket_name': bucket_name,
            'has_lifecycle_policy': None,
            'lifecycle_rules_count': 0,
            'lifecycle_rules': [],
            'error': f"Unexpected error: {str(e)}"
        }


def analyze_lifecycle_rules(lifecycle_rules):
    """
    Analyze lifecycle rules for effectiveness
    
    Args:
        lifecycle_rules: List of lifecycle rules
        
    Returns:
        dict: Analysis of lifecycle rules
    """
    if not lifecycle_rules:
        return {
            'has_transition_rules': False,
            'has_expiration_rules': False,
            'has_incomplete_multipart_cleanup': False,
            'transition_rule_count': 0,
            'expiration_rule_count': 0,
            'active_rules': 0
        }
    
    transition_rules = 0
    expiration_rules = 0
    incomplete_multipart_cleanup = False
    active_rules = 0
    
    for rule in lifecycle_rules:
        if rule.get('Status') == 'Enabled':
            active_rules += 1
            
            # Check for transition rules
            if 'Transitions' in rule and rule['Transitions']:
                transition_rules += 1
            
            # Check for expiration rules
            if 'Expiration' in rule and rule['Expiration']:
                expiration_rules += 1
            
            # Check for incomplete multipart upload cleanup
            if 'AbortIncompleteMultipartUpload' in rule:
                incomplete_multipart_cleanup = True
    
    return {
        'has_transition_rules': transition_rules > 0,
        'has_expiration_rules': expiration_rules > 0,
        'has_incomplete_multipart_cleanup': incomplete_multipart_cleanup,
        'transition_rule_count': transition_rules,
        'expiration_rule_count': expiration_rules,
        'active_rules': active_rules
    }


def check_s3_lifecycle_policies():
    """
    Check S3 lifecycle policies for all buckets
    
    Returns:
        dict: Complete check results
    """
    try:
        # S3 is a global service, but we use us-east-1 as the default region
        s3_client = boto3.client('s3', region_name='us-east-1')
        
        # List all S3 buckets
        response = s3_client.list_buckets()
        bucket_names = [bucket['Name'] for bucket in response.get('Buckets', [])]
        
        # Analyze each bucket
        bucket_analyses = []
        buckets_without_policies = []
        buckets_with_policies = []
        error_buckets = []
        
        for bucket_name in bucket_names:
            bucket_analysis = get_bucket_lifecycle_configuration(s3_client, bucket_name)
            
            # Add lifecycle analysis
            lifecycle_analysis = analyze_lifecycle_rules(bucket_analysis['lifecycle_rules'])
            bucket_analysis.update(lifecycle_analysis)
            
            bucket_analyses.append(bucket_analysis)
            
            # Categorize buckets
            if bucket_analysis.get('error'):
                error_buckets.append(bucket_analysis)
            elif bucket_analysis['has_lifecycle_policy']:
                buckets_with_policies.append(bucket_analysis)
            else:
                buckets_without_policies.append(bucket_analysis)
        
        return {
            'total_buckets': len(bucket_names),
            'buckets_with_policies': len(buckets_with_policies),
            'buckets_without_policies': len(buckets_without_policies),
            'error_buckets': len(error_buckets),
            'buckets': bucket_analyses,
            'non_compliant_items': buckets_without_policies,
            'compliant_items': buckets_with_policies,
            'error_items': error_buckets,
            'error': None
        }
        
    except ClientError as e:
        error_msg = f"AWS API error: {str(e)}"
        return {
            'total_buckets': 0,
            'buckets_with_policies': 0,
            'buckets_without_policies': 0,
            'error_buckets': 0,
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
            'buckets_with_policies': 0,
            'buckets_without_policies': 0,
            'error_buckets': 0,
            'buckets': [],
            'non_compliant_items': [],
            'compliant_items': [],
            'error_items': [],
            'error': error_msg
        }


def determine_lifecycle_status(stats):
    """Determine overall lifecycle policy status and message"""
    total_buckets = stats['total_buckets']
    buckets_without_policies = stats['buckets_without_policies']
    error_buckets = stats['error_buckets']
    
    if total_buckets == 0:
        status = 'Success'
        message = 'No S3 buckets found in the account.'
    elif buckets_without_policies == 0 and error_buckets == 0:
        status = 'Success'
        message = f'All {total_buckets} S3 buckets have lifecycle policies configured.'
    elif buckets_without_policies > 0 and error_buckets == 0:
        status = 'Warning'
        message = f'Found {buckets_without_policies} buckets without lifecycle policies out of {total_buckets} total buckets.'
    elif buckets_without_policies == 0 and error_buckets > 0:
        status = 'Warning'
        message = f'Could not determine lifecycle policy status for {error_buckets} buckets out of {total_buckets} total buckets.'
    else:
        status = 'Warning'
        message = f'Found {buckets_without_policies} non-compliant and {error_buckets} error buckets out of {total_buckets} total buckets.'
    
    return status, message


def check_s3_lifecycle(profile_name=None):
    """
    Main function to check S3 lifecycle policies
    
    Args:
        profile_name: AWS profile name (optional)
        
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
            # Perform the lifecycle check
            result = check_s3_lifecycle_policies()
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        stats = {
            'total_buckets': result['total_buckets'],
            'buckets_without_policies': result['buckets_without_policies'],
            'error_buckets': result['error_buckets']
        }
        
        status, message = determine_lifecycle_status(stats)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 's3_lifecycle_policies',
            'total_buckets': result['total_buckets'],
            'buckets_with_policies': result['buckets_with_policies'],
            'buckets_without_policies': result['buckets_without_policies'],
            'error_buckets': result['error_buckets'],
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
            'check_type': 's3_lifecycle_policies',
            'total_buckets': 0,
            'buckets_with_policies': 0,
            'buckets_without_policies': 0,
            'error_buckets': 0,
            'buckets': [],
            'non_compliant_items': []
        }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'check_type': 's3_lifecycle_policies',
            'total_buckets': 0,
            'buckets_with_policies': 0,
            'buckets_without_policies': 0,
            'error_buckets': 0,
            'buckets': [],
            'non_compliant_items': []
        }


def print_bucket_details(bucket, index):
    """Print detailed information about a bucket"""
    print(f"\n{index}. Bucket Details:")
    print(f"   Bucket Name: {bucket['bucket_name']}")
    print(f"   Has Lifecycle Policy: {'Yes' if bucket['has_lifecycle_policy'] else 'No'}")
    
    if bucket['has_lifecycle_policy']:
        print(f"   Lifecycle Rules Count: {bucket['lifecycle_rules_count']}")
        print(f"   Active Rules: {bucket['active_rules']}")
        print(f"   Has Transition Rules: {'Yes' if bucket['has_transition_rules'] else 'No'}")
        print(f"   Has Expiration Rules: {'Yes' if bucket['has_expiration_rules'] else 'No'}")
        print(f"   Has Multipart Cleanup: {'Yes' if bucket['has_incomplete_multipart_cleanup'] else 'No'}")
    
    if bucket.get('error'):
        print(f"   Error: {bucket['error']}")


def print_basic_summary(result):
    """Print basic summary information"""
    print("\nS3 Lifecycle Policies Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Buckets: {result['total_buckets']}")
    print(f"Buckets With Policies: {result['buckets_with_policies']}")
    print(f"Buckets Without Policies: {result['buckets_without_policies']}")
    print(f"Error Buckets: {result['error_buckets']}")


def print_non_compliant_buckets(buckets):
    """Print details of buckets without lifecycle policies"""
    if buckets:
        print(f"\nBuckets Without Lifecycle Policies ({len(buckets)}):")
        for i, bucket in enumerate(buckets, 1):
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
    
    non_compliant_buckets = result.get('non_compliant_items', [])
    print_non_compliant_buckets(non_compliant_buckets)
    
    error_buckets = result.get('error_items', [])
    print_error_buckets(error_buckets)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check S3 bucket lifecycle policies")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_s3_lifecycle(profile_name=args.profile)
    
    if args.output == 'json':
        print(json.dumps(result, indent=2, default=str))
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