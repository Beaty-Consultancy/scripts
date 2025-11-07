#!/usr/bin/env python3
"""
Patch Manager Configuration Checker

Script to check if AWS Systems Manager Patch Manager is configured for instances.
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
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        regions_response = ec2_client.describe_regions()
        return [region['RegionName'] for region in regions_response['Regions']]
    except Exception:
        # Fallback to common regions if describe_regions fails
        return [
            'us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 
            'ap-southeast-1', 'ap-northeast-1'
        ]


def get_patch_group_from_tags(tags: Dict[str, str]) -> Optional[str]:
    """Extract patch group from instance tags."""
    return (
        tags.get('Patch Group') or
        tags.get('PatchGroup') or
        tags.get('Patch Group 2')
    )


def get_patch_groups_for_region(ssm_client) -> Dict[str, str]:
    """Get patch groups for a region."""
    try:
        pg_response = ssm_client.describe_patch_groups()
        return {
            mapping.get('PatchGroup'): mapping.get('BaselineId')
            for mapping in pg_response.get('Mappings', [])
        }
    except ClientError:
        return {}


def check_patch_manager_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Check Patch Manager configuration in a specific region.
    
    Args:
        region: AWS region to check
        
    Returns:
        List of instances without proper patch configuration
    """
    unconfigured_instances = []
    
    try:
        ec2_client = boto3.client('ec2', region_name=region)
        ssm_client = boto3.client('ssm', region_name=region)
        
        # Get running instances in this region
        instances_response = ec2_client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        
        # Get patch groups in this region
        patch_groups = get_patch_groups_for_region(ssm_client)
        
        # Check each instance for patch group configuration
        for reservation in instances_response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_type = instance.get('InstanceType', 'unknown')
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                
                patch_group = get_patch_group_from_tags(tags)
                
                # Check if instance is properly configured
                is_configured = patch_group and patch_group in patch_groups
                
                if not is_configured:
                    reason = 'No Patch Group tag' if not patch_group else f'Patch group "{patch_group}" not found'
                    unconfigured_instances.append({
                        'instance_id': instance_id,
                        'instance_type': instance_type,
                        'region': region,
                        'patch_group': patch_group,
                        'reason': reason,
                        'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
                    })
    
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code not in ['UnauthorizedOperation', 'AccessDenied']:
            unconfigured_instances.append({
                'region': region,
                'error': f'Failed to check region {region}: {error_code}',
                'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
            })
    
    return unconfigured_instances


def check_patch_manager_all_regions(max_workers: int = 5) -> Dict[str, Any]:
    """
    Check Patch Manager configuration across all regions.
    
    Args:
        max_workers: Maximum number of concurrent workers
        
    Returns:
        Dictionary containing aggregated results
    """
    regions = get_enabled_regions()
    all_unconfigured_instances = []
    total_regions_checked = 0
    error_count = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit tasks for all regions
        future_to_region = {
            executor.submit(check_patch_manager_in_region, region): region 
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
                    all_unconfigured_instances.extend(region_results)
                
            except Exception as e:
                error_count += 1
                all_unconfigured_instances.append({
                    'region': region,
                    'error': f'Failed to process region {region}: {str(e)}',
                    'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
                })
    
    # Filter out error entries for statistics
    valid_instances = [item for item in all_unconfigured_instances if 'error' not in item]
    
    return {
        'total_regions_checked': total_regions_checked,
        'unconfigured_instances': len(valid_instances),
        'error_count': error_count,
        'instance_items': all_unconfigured_instances
    }


def determine_patch_manager_status(stats: Dict[str, Any]) -> Tuple[str, str]:
    """
    Determine the overall status based on patch manager check results.
    
    Args:
        stats: Dictionary containing check statistics
        
    Returns:
        Tuple of (status, message)
    """
    unconfigured_instances = stats['unconfigured_instances']
    error_count = stats['error_count']
    total_regions = stats['total_regions_checked']
    
    if error_count > 0:
        if error_count == total_regions:
            return 'Error', f'Failed to check patch manager configuration in all {total_regions} regions'
        else:
            return 'Warning', f'Failed to check patch manager configuration in {error_count} out of {total_regions} regions'
    
    if unconfigured_instances == 0:
        return 'Pass', 'All instances are properly configured for patch management'
    else:
        return 'Fail', f'Found {unconfigured_instances} instances without proper patch management configuration'


def check_patch_manager(profile_name: Optional[str] = None, max_workers: int = 5) -> Dict[str, Any]:
    """
    Main function to check Patch Manager configuration across all regions
    
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
            # Perform the patch manager check
            result = check_patch_manager_all_regions(max_workers)
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        status, message = determine_patch_manager_status(result)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'patch_manager',
            'total_regions_checked': result['total_regions_checked'],
            'unconfigured_instances': result['unconfigured_instances'],
            'error_count': result['error_count'],
            'non_compliant_items': result['instance_items']
        }
        
        return final_result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found or invalid',
            'check_type': 'patch_manager',
            'non_compliant_items': []
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': 'Insufficient permissions to check patch manager configuration',
                'check_type': 'patch_manager',
                'non_compliant_items': []
            }
        else:
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': f'AWS API error: {error_code}',
                'check_type': 'patch_manager',
                'non_compliant_items': []
            }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error during patch manager check: {str(e)}',
            'check_type': 'patch_manager',
            'non_compliant_items': []
        }


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check Patch Manager configuration for instances")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--max-workers', type=int, default=5,
                       help='Maximum number of concurrent workers (default: 5)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_patch_manager(
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