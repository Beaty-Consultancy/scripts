#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Sustainability Pillar
Check CloudWatch Log Groups Retention Policy

This script checks CloudWatch log groups across all AWS regions to identify
groups without retention policies.
"""

import boto3
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError
import sys


def get_available_regions():
    """
    Get all AWS regions where CloudWatch Logs is available
    
    Returns:
        list: List of AWS region names
    """
    try:
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        response = ec2_client.describe_regions()
        return [region['RegionName'] for region in response['Regions']]
    except ClientError as e:
        raise ClientError(e.response, e.operation_name) from e
    except Exception as e:
        raise RuntimeError(f"Failed to get AWS regions: {str(e)}") from e


def get_log_groups_for_region(region_name):
    """
    Get all CloudWatch log groups for a specific region
    
    Args:
        region_name: AWS region name
        
    Returns:
        list: List of log group information dictionaries
    """
    try:
        logs_client = boto3.client('logs', region_name=region_name)
        log_groups = []
        
        paginator = logs_client.get_paginator('describe_log_groups')
        
        for page in paginator.paginate():
            for log_group in page.get('logGroups', []):
                log_group_info = {
                    'region': region_name,
                    'log_group_name': log_group.get('logGroupName', ''),
                    'retention_days': log_group.get('retentionInDays'),
                    'stored_bytes': log_group.get('storedBytes', 0),
                    'creation_time': log_group.get('creationTime', 0),
                    'has_retention_policy': log_group.get('retentionInDays') is not None,
                    'error': None
                }
                log_groups.append(log_group_info)
        
        return log_groups
        
    except ClientError as e:
        error_msg = f"AWS API error in region {region_name}: {str(e)}"
        return [{
            'region': region_name,
            'log_group_name': 'Error',
            'retention_days': None,
            'stored_bytes': 0,
            'creation_time': 0,
            'has_retention_policy': False,
            'error': error_msg
        }]
    except Exception as e:
        error_msg = f"Unexpected error in region {region_name}: {str(e)}"
        return [{
            'region': region_name,
            'log_group_name': 'Error',
            'retention_days': None,
            'stored_bytes': 0,
            'creation_time': 0,
            'has_retention_policy': False,
            'error': error_msg
        }]


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


def check_cloudwatch_retention_all_regions():
    """
    Check CloudWatch log group retention across all AWS regions
    
    Returns:
        dict: Complete check results
    """
    try:
        # Get all available regions
        regions = get_available_regions()
        
        # Collect log groups from all regions using parallel processing
        all_log_groups = []
        region_errors = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_region = {
                executor.submit(get_log_groups_for_region, region): region 
                for region in regions
            }
            
            for future in as_completed(future_to_region):
                region = future_to_region[future]
                try:
                    log_groups = future.result()
                    all_log_groups.extend(log_groups)
                except Exception as e:
                    region_errors.append({
                        'region': region,
                        'error': str(e)
                    })
        
        # Separate log groups by retention status
        groups_without_retention = []
        groups_with_retention = []
        error_groups = []
        
        for log_group in all_log_groups:
            if log_group.get('error'):
                error_groups.append(log_group)
            elif log_group['has_retention_policy']:
                groups_with_retention.append(log_group)
            else:
                groups_without_retention.append(log_group)
        
        # Calculate total storage for groups without retention
        total_storage_no_retention = sum(
            group['stored_bytes'] for group in groups_without_retention
        )
        
        return {
            'total_regions_checked': len(regions),
            'total_log_groups': len(all_log_groups),
            'groups_without_retention': len(groups_without_retention),
            'groups_with_retention': len(groups_with_retention),
            'error_groups': len(error_groups),
            'total_storage_no_retention_bytes': total_storage_no_retention,
            'total_storage_no_retention_readable': format_bytes_readable(total_storage_no_retention),
            'log_groups': all_log_groups,
            'non_compliant_items': groups_without_retention,
            'compliant_items': groups_with_retention,
            'error_items': error_groups,
            'region_errors': region_errors,
            'error': None
        }
        
    except ClientError as e:
        error_msg = f"AWS API error: {str(e)}"
        return {
            'total_regions_checked': 0,
            'total_log_groups': 0,
            'groups_without_retention': 0,
            'groups_with_retention': 0,
            'error_groups': 0,
            'total_storage_no_retention_bytes': 0,
            'total_storage_no_retention_readable': '0 B',
            'log_groups': [],
            'non_compliant_items': [],
            'compliant_items': [],
            'error_items': [],
            'region_errors': [],
            'error': error_msg
        }
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        return {
            'total_regions_checked': 0,
            'total_log_groups': 0,
            'groups_without_retention': 0,
            'groups_with_retention': 0,
            'error_groups': 0,
            'total_storage_no_retention_bytes': 0,
            'total_storage_no_retention_readable': '0 B',
            'log_groups': [],
            'non_compliant_items': [],
            'compliant_items': [],
            'error_items': [],
            'region_errors': [],
            'error': error_msg
        }


def determine_retention_status(stats):
    """Determine overall retention compliance status and message"""
    total_groups = stats['total_log_groups']
    groups_without_retention = stats['groups_without_retention']
    error_groups = stats['error_groups']
    
    if total_groups == 0:
        status = 'Success'
        message = 'No CloudWatch log groups found in any region.'
    elif groups_without_retention == 0 and error_groups == 0:
        status = 'Success'
        message = f'All {total_groups} CloudWatch log groups have retention policies configured.'
    elif groups_without_retention > 0 and error_groups == 0:
        status = 'Warning'
        message = f'Found {groups_without_retention} log groups without retention policies out of {total_groups} total groups.'
    elif groups_without_retention == 0 and error_groups > 0:
        status = 'Warning'
        message = f'Could not determine retention status for {error_groups} log groups out of {total_groups} total groups.'
    else:
        status = 'Warning'
        message = f'Found {groups_without_retention} non-compliant and {error_groups} error log groups out of {total_groups} total groups.'
    
    return status, message


def check_cloudwatch_retention(profile_name=None, regions=None):
    """
    Main function to check CloudWatch log groups retention
    
    Args:
        profile_name: AWS profile name (optional)
        regions: Specific regions to check (optional, defaults to all regions)
        
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
            # Perform the retention check
            result = check_cloudwatch_retention_all_regions()
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        stats = {
            'total_log_groups': result['total_log_groups'],
            'groups_without_retention': result['groups_without_retention'],
            'error_groups': result['error_groups']
        }
        
        status, message = determine_retention_status(stats)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'cloudwatch_log_retention',
            'total_regions_checked': result['total_regions_checked'],
            'total_log_groups': result['total_log_groups'],
            'groups_without_retention': result['groups_without_retention'],
            'groups_with_retention': result['groups_with_retention'],
            'error_groups': result['error_groups'],
            'total_storage_no_retention_bytes': result['total_storage_no_retention_bytes'],
            'total_storage_no_retention_readable': result['total_storage_no_retention_readable'],
            'log_groups': result['log_groups'],
            'non_compliant_items': result['non_compliant_items']
        }
        
        # Add error details if any
        if result['error']:
            final_result['error'] = result['error']
        
        if result['error_items']:
            final_result['error_items'] = result['error_items']
        
        if result['region_errors']:
            final_result['region_errors'] = result['region_errors']
        
        return final_result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'check_type': 'cloudwatch_log_retention',
            'total_regions_checked': 0,
            'total_log_groups': 0,
            'groups_without_retention': 0,
            'groups_with_retention': 0,
            'error_groups': 0,
            'total_storage_no_retention_bytes': 0,
            'total_storage_no_retention_readable': '0 B',
            'log_groups': [],
            'non_compliant_items': []
        }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'check_type': 'cloudwatch_log_retention',
            'total_regions_checked': 0,
            'total_log_groups': 0,
            'groups_without_retention': 0,
            'groups_with_retention': 0,
            'error_groups': 0,
            'total_storage_no_retention_bytes': 0,
            'total_storage_no_retention_readable': '0 B',
            'log_groups': [],
            'non_compliant_items': []
        }


def print_log_group_details(log_group, index):
    """Print detailed information about a log group"""
    print(f"\n{index}. Log Group Details:")
    print(f"   Region: {log_group['region']}")
    print(f"   Name: {log_group['log_group_name']}")
    print(f"   Retention Days: {log_group['retention_days'] or 'No retention policy'}")
    print(f"   Storage Size: {format_bytes_readable(log_group['stored_bytes'])}")
    print(f"   Has Retention Policy: {'Yes' if log_group['has_retention_policy'] else 'No'}")
    
    if log_group.get('error'):
        print(f"   Error: {log_group['error']}")


def print_basic_summary(result):
    """Print basic summary information"""
    print("\nCloudWatch Log Groups Retention Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Regions Checked: {result['total_regions_checked']}")
    print(f"Total Log Groups: {result['total_log_groups']}")
    print(f"Groups Without Retention: {result['groups_without_retention']}")
    print(f"Groups With Retention: {result['groups_with_retention']}")
    print(f"Error Groups: {result['error_groups']}")
    print(f"Storage Without Retention: {result['total_storage_no_retention_readable']}")


def print_non_compliant_groups(groups):
    """Print details of log groups without retention policies"""
    if groups:
        print(f"\nLog Groups Without Retention Policies ({len(groups)}):")
        for i, group in enumerate(groups, 1):
            print_log_group_details(group, i)


def print_error_groups(groups):
    """Print details of log groups with errors"""
    if groups:
        print(f"\nLog Groups with Errors ({len(groups)}):")
        for i, group in enumerate(groups, 1):
            print_log_group_details(group, i)


def print_summary_output(result):
    """Print human-readable summary output"""
    print_basic_summary(result)
    
    non_compliant_groups = result.get('non_compliant_items', [])
    print_non_compliant_groups(non_compliant_groups)
    
    error_groups = result.get('error_items', [])
    print_error_groups(error_groups)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check CloudWatch log groups retention policies")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    parser.add_argument('--regions', nargs='+', help='Specific regions to check (default: all regions)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_cloudwatch_retention(
        profile_name=args.profile,
        regions=args.regions
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