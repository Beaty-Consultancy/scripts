#!/usr/bin/env python3
"""
SSM Management Checker

Simple script to check if SSM is configured for EC2 instances across all regions.
"""

import boto3
import json
import sys
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError


def get_enabled_regions() -> List[str]:
    """Get list of enabled AWS regions."""
    try:
        ec2_client = boto3.client('ec2', region_name='eu-west-2')
        regions_response = ec2_client.describe_regions()
        return [region['RegionName'] for region in regions_response['Regions']]
    except Exception:
        # Fallback to common regions if describe_regions fails
        return [
            'eu-west-2', 'us-west-2', 'eu-west-1', 'eu-central-1', 
            'ap-southeast-1', 'ap-northeast-1'
        ]


def get_managed_instance_ids(ssm_client) -> List[str]:
    """Get list of SSM managed instance IDs."""
    try:
        managed_instance_ids = []
        paginator = ssm_client.get_paginator('describe_instance_information')
        for page in paginator.paginate():
            managed_instance_ids.extend(
                instance['InstanceId']
                for instance in page['InstanceInformationList']
            )
        return managed_instance_ids
    except ClientError:
        # SSM might not be available in this region or no permissions
        return []


def check_ssm_management_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Check SSM management in a specific region.
    
    Args:
        region: AWS region to check
        
    Returns:
        List of instances not managed by SSM
    """
    unmanaged_instances = []
    
    try:
        ec2_client = boto3.client('ec2', region_name=region)
        ssm_client = boto3.client('ssm', region_name=region)
        
        # Get all running instances in this region
        instances_response = ec2_client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        
        instance_ids = []
        for reservation in instances_response['Reservations']:
            for instance in reservation['Instances']:
                instance_ids.append({
                    'id': instance['InstanceId'],
                    'type': instance.get('InstanceType', 'unknown')
                })
        
        if not instance_ids:
            return unmanaged_instances
        
        # Check which instances are managed by SSM
        managed_instance_ids = get_managed_instance_ids(ssm_client)
        
        # Find unmanaged instances
        for instance in instance_ids:
            if instance['id'] not in managed_instance_ids:
                unmanaged_instances.append({
                    'instance_id': instance['id'],
                    'instance_type': instance['type'],
                    'region': region,
                    'reason': 'Not managed by SSM',
                    'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
                })
    
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code not in ['UnauthorizedOperation', 'AccessDenied']:
            unmanaged_instances.append({
                'region': region,
                'error': f'Failed to check region {region}: {error_code}',
                'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
            })
    
    return unmanaged_instances


def check_ssm_management_all_regions(max_workers: int = 5) -> Dict[str, Any]:
    """
    Check SSM management across all regions.
    
    Args:
        max_workers: Maximum number of concurrent workers
        
    Returns:
        Dictionary containing aggregated results
    """
    regions = get_enabled_regions()
    all_unmanaged_instances = []
    total_regions_checked = 0
    error_count = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit tasks for all regions
        future_to_region = {
            executor.submit(check_ssm_management_in_region, region): region 
            for region in regions
        }
        
        # Collect results
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            total_regions_checked += 1
            
            try:
                region_results = future.result()
                if region_results:
                    # Check if any results contain errors
                    error_results = [item for item in region_results if 'error' in item]
                    
                    error_count += len(error_results)
                    all_unmanaged_instances.extend(region_results)
                
            except Exception as e:
                error_count += 1
                all_unmanaged_instances.append({
                    'region': region,
                    'error': f'Failed to process region {region}: {str(e)}',
                    'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
                })
    
    # Filter out error entries for statistics
    valid_instances = [item for item in all_unmanaged_instances if 'error' not in item]
    
    return {
        'total_regions_checked': total_regions_checked,
        'unmanaged_instances': len(valid_instances),
        'error_count': error_count,
        'instance_items': all_unmanaged_instances
    }


def determine_ssm_management_status(stats: Dict[str, Any]) -> Tuple[str, str]:
    """
    Determine the overall status based on SSM management check results.
    
    Args:
        stats: Dictionary containing check statistics
        
    Returns:
        Tuple of (status, message)
    """
    unmanaged_instances = stats['unmanaged_instances']
    error_count = stats['error_count']
    total_regions = stats['total_regions_checked']
    
    if error_count > 0:
        if error_count == total_regions:
            return 'Error', f'Failed to check SSM management in all {total_regions} regions'
        else:
            return 'Warning', f'Failed to check SSM management in {error_count} out of {total_regions} regions'
    
    if unmanaged_instances == 0:
        return 'Pass', 'All instances are managed by SSM'
    else:
        return 'Fail', f'Found {unmanaged_instances} instances not managed by SSM'


def check_ssm_management(profile_name: Optional[str] = None, max_workers: int = 5) -> Dict[str, Any]:
    """
    Main function to check SSM management across all regions
    
    Args:
        profile_name: AWS profile name (optional)
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
            # Perform the SSM management check
            result = check_ssm_management_all_regions(max_workers)
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        status, message = determine_ssm_management_status(result)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'ssm_management',
            'total_regions_checked': result['total_regions_checked'],
            'unmanaged_instances': result['unmanaged_instances'],
            'error_count': result['error_count'],
            'non_compliant_items': result['instance_items']
        }
        
        return final_result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found or invalid',
            'check_type': 'ssm_management',
            'non_compliant_items': []
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': 'Insufficient permissions to check SSM management',
                'check_type': 'ssm_management',
                'non_compliant_items': []
            }
        else:
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': f'AWS API error: {error_code}',
                'check_type': 'ssm_management',
                'non_compliant_items': []
            }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error during SSM management check: {str(e)}',
            'check_type': 'ssm_management',
            'non_compliant_items': []
        }


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check SSM management for EC2 instances")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--max-workers', type=int, default=5,
                       help='Maximum number of concurrent workers (default: 5)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_ssm_management(
        profile_name=args.profile,
        max_workers=args.max_workers
    )
    
    # Output JSON
    print(json.dumps(result, indent=2))
    
    # Exit with appropriate code
    if result['status'] == 'Error':
        sys.exit(1)
    elif result['status'] == 'Fail':
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()