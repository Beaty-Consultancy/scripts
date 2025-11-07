#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Security Pillar
Check RDS Backup Configuration

This script checks if RDS instances have backups enabled through:
1. Standard RDS automated backups (backup retention period)
2. AWS Backup service protection
"""

import boto3
import json
import sys
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError


def get_rds_instances(rds_client, region):
    """
    Get all RDS instances in a region
    
    Args:
        rds_client: Boto3 RDS client
        region: AWS region name
        
    Returns:
        list: List of RDS instances
    """
    try:
        instances = []
        paginator = rds_client.get_paginator('describe_db_instances')
        
        for page in paginator.paginate():
            for instance in page['DBInstances']:
                instances.append(instance)
        
        return instances
    except ClientError as e:
        raise ClientError(e.response, e.operation_name) from e
    except Exception as e:
        raise RuntimeError(f"Failed to get RDS instances in {region}: {str(e)}") from e


def check_rds_automated_backup(instance):
    """
    Check if RDS instance has automated backup enabled
    
    Args:
        instance: RDS instance dict
        
    Returns:
        dict: Backup status information
    """
    backup_retention_period = instance.get('BackupRetentionPeriod', 0)
    
    return {
        'has_automated_backup': backup_retention_period > 0,
        'backup_retention_period': backup_retention_period,
        'backup_window': instance.get('PreferredBackupWindow', 'N/A')
    }


def get_aws_backup_protected_resources(backup_client, region):
    """
    Get list of resources protected by AWS Backup in a region
    
    Args:
        backup_client: Boto3 Backup client
        region: AWS region name
        
    Returns:
        set: Set of protected resource ARNs
    """
    try:
        protected_resources = set()
        paginator = backup_client.get_paginator('list_protected_resources')
        
        for page in paginator.paginate():
            for resource in page['Results']:
                if resource['ResourceType'] == 'RDS':
                    protected_resources.add(resource['ResourceArn'])
        
        return protected_resources
    except ClientError as e:
        # AWS Backup might not be available in all regions or user might not have permissions
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            return set()
        raise e
    except Exception:
        # If AWS Backup service is not available, return empty set
        return set()


def analyze_rds_instance_backup(instance, protected_resources):
    """
    Analyze backup configuration for an RDS instance
    
    Args:
        instance: RDS instance dict
        protected_resources: Set of AWS Backup protected resource ARNs
        
    Returns:
        dict: Complete backup analysis
    """
    instance_arn = instance['DBInstanceArn']
    instance_id = instance['DBInstanceIdentifier']
    
    # Check automated backup
    automated_backup = check_rds_automated_backup(instance)
    
    # Check AWS Backup protection
    has_aws_backup = instance_arn in protected_resources
    
    # Determine overall backup status
    has_any_backup = automated_backup['has_automated_backup'] or has_aws_backup
    
    return {
        'instance_id': instance_id,
        'instance_arn': instance_arn,
        'engine': instance.get('Engine', 'Unknown'),
        'instance_class': instance.get('DBInstanceClass', 'Unknown'),
        'instance_status': instance.get('DBInstanceStatus', 'Unknown'),
        'automated_backup': automated_backup,
        'aws_backup_protected': has_aws_backup,
        'has_any_backup': has_any_backup
    }


def check_rds_backups_region(rds_client, backup_client, region):
    """
    Check RDS backup configuration in a specific region
    
    Args:
        rds_client: Boto3 RDS client
        backup_client: Boto3 Backup client
        region: AWS region name
        
    Returns:
        dict: Region check results
    """
    try:
        # Get all RDS instances
        instances = get_rds_instances(rds_client, region)
        
        # Get AWS Backup protected resources
        protected_resources = get_aws_backup_protected_resources(backup_client, region)
        
        # Analyze each instance
        instance_analyses = []
        instances_without_backup = []
        
        for instance in instances:
            analysis = analyze_rds_instance_backup(instance, protected_resources)
            instance_analyses.append(analysis)
            
            if not analysis['has_any_backup']:
                instances_without_backup.append(analysis)
        
        return {
            'region': region,
            'total_instances': len(instances),
            'instances_with_backup': len(instances) - len(instances_without_backup),
            'instances_without_backup': len(instances_without_backup),
            'instances': instance_analyses,
            'unprotected_instances': instances_without_backup,
            'error': None
        }
        
    except ClientError as e:
        error_msg = f"AWS API error in {region}: {str(e)}"
        return {
            'region': region,
            'total_instances': 0,
            'instances_with_backup': 0,
            'instances_without_backup': 0,
            'instances': [],
            'unprotected_instances': [],
            'error': error_msg
        }
    except Exception as e:
        error_msg = f"Unexpected error in {region}: {str(e)}"
        return {
            'region': region,
            'total_instances': 0,
            'instances_with_backup': 0,
            'instances_without_backup': 0,
            'instances': [],
            'unprotected_instances': [],
            'error': error_msg
        }


def get_aws_regions(session):
    """Get list of all available AWS regions"""
    try:
        ec2_client = session.client('ec2', region_name='us-east-1')
        response = ec2_client.describe_regions()
        return [region['RegionName'] for region in response['Regions']]
    except Exception:
        # Fallback to common regions if describe_regions fails
        return [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-central-1', 'ap-south-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
        ]


def determine_backup_status(stats, regions_with_errors):
    """Determine overall backup status and message"""
    total_instances = stats['total_instances']
    unprotected_instances = stats['instances_without_backup']
    
    if total_instances == 0:
        status = 'Success'
        message = 'No RDS instances found in the checked regions.'
    elif unprotected_instances == 0:
        status = 'Success'
        message = f'All {total_instances} RDS instances have backup protection enabled.'
    else:
        status = 'Warning'
        message = f'Found {unprotected_instances} RDS instances without backup protection out of {total_instances} total instances.'
    
    # Add error information to message if there were region errors
    if regions_with_errors:
        message += f" Note: {len(regions_with_errors)} regions had errors during check."
    
    return status, message


def setup_aws_clients_and_regions(profile_name, region_name):
    """Setup AWS session and determine regions to check"""
    session = boto3.Session(profile_name=profile_name)
    
    if region_name:
        regions_to_check = [region_name]
    else:
        regions_to_check = get_aws_regions(session)
    
    return session, regions_to_check


def process_regions(session, regions_to_check):
    """Process all regions and collect results"""
    region_results = []
    regions_with_errors = []
    
    for region in regions_to_check:
        try:
            rds_client = session.client('rds', region_name=region)
            backup_client = session.client('backup', region_name=region)
            
            result = check_rds_backups_region(rds_client, backup_client, region)
            region_results.append(result)
            
            if result['error']:
                regions_with_errors.append({
                    'region': region,
                    'error': result['error']
                })
                
        except Exception as e:
            error_msg = f"Failed to check region {region}: {str(e)}"
            regions_with_errors.append({
                'region': region,
                'error': error_msg
            })
            region_results.append({
                'region': region,
                'total_instances': 0,
                'instances_with_backup': 0,
                'instances_without_backup': 0,
                'instances': [],
                'unprotected_instances': [],
                'error': error_msg
            })
    
    return region_results, regions_with_errors


def build_final_result(timestamp, region_results, regions_with_errors, regions_to_check):
    """Build the final result structure"""
    # Calculate overall statistics
    stats = {
        'total_instances': sum(r['total_instances'] for r in region_results),
        'instances_with_backup': sum(r['instances_with_backup'] for r in region_results),
        'instances_without_backup': sum(r['instances_without_backup'] for r in region_results),
        'regions_checked': len([r for r in region_results if not r['error']]),
        'regions_with_errors': len(regions_with_errors)
    }
    
    # Collect all unprotected instances
    all_unprotected_instances = []
    for result in region_results:
        if not result['error']:
            for instance in result['unprotected_instances']:
                instance['region'] = result['region']
                all_unprotected_instances.append(instance)
    
    # Determine overall status
    status, message = determine_backup_status(stats, regions_with_errors)
    
    # Build final result
    result = {
        'timestamp': timestamp,
        'status': status,
        'message': message,
        'check_type': 'rds_backups',
        'regions_checked': len(regions_to_check),
        'total_instances': stats['total_instances'],
        'instances_with_backup': stats['instances_with_backup'],
        'instances_without_backup': stats['instances_without_backup'],
        'unprotected_instances': all_unprotected_instances,
        'region_results': region_results
    }
    
    # Add error details if any
    if regions_with_errors:
        result['region_errors'] = regions_with_errors
    
    return result


def check_rds_backups(profile_name=None, region_name=None):
    """
    Main function to check RDS backup configuration
    
    Args:
        profile_name: AWS profile name (optional)
        region_name: Specific region to check (optional, default: all regions)
        
    Returns:
        dict: Complete check results in JSON format
    """
    timestamp = datetime.now(timezone.utc).isoformat() + 'Z'
    
    try:
        # Setup AWS session and regions
        session, regions_to_check = setup_aws_clients_and_regions(profile_name, region_name)
        
        # Process all regions
        region_results, regions_with_errors = process_regions(session, regions_to_check)
        
        # Build and return final result
        return build_final_result(timestamp, region_results, regions_with_errors, regions_to_check)
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'check_type': 'rds_backups',
            'regions_checked': 0,
            'total_instances': 0,
            'instances_with_backup': 0,
            'instances_without_backup': 0,
            'unprotected_instances': [],
            'region_results': []
        }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'check_type': 'rds_backups',
            'regions_checked': 0,
            'total_instances': 0,
            'instances_with_backup': 0,
            'instances_without_backup': 0,
            'unprotected_instances': [],
            'region_results': []
        }


def print_instance_details(instance, index):
    """Print detailed information about an RDS instance"""
    print(f"\n{index}. RDS Instance Details:")
    print(f"   Instance ID: {instance['instance_id']}")
    print(f"   Engine: {instance['engine']}")
    print(f"   Instance Class: {instance['instance_class']}")
    print(f"   Status: {instance['instance_status']}")
    print(f"   Region: {instance['region']}")
    
    auto_backup = instance['automated_backup']
    print(f"   Automated Backup: {'Enabled' if auto_backup['has_automated_backup'] else 'Disabled'}")
    if auto_backup['has_automated_backup']:
        print(f"   Retention Period: {auto_backup['backup_retention_period']} days")
        print(f"   Backup Window: {auto_backup['backup_window']}")
    
    print(f"   AWS Backup Protected: {'Yes' if instance['aws_backup_protected'] else 'No'}")


def print_basic_summary(result):
    """Print basic summary information"""
    print("\nRDS Backup Configuration Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Regions Checked: {result['regions_checked']}")
    print(f"Total RDS Instances: {result['total_instances']}")
    print(f"Instances with Backup: {result['instances_with_backup']}")
    print(f"Instances without Backup: {result['instances_without_backup']}")


def print_region_errors(result):
    """Print region errors if any"""
    if result.get('region_errors'):
        print("\nRegion Errors:")
        for error in result['region_errors']:
            print(f"  - {error['region']}: {error['error']}")


def print_unprotected_instances(instances):
    """Print details of unprotected RDS instances"""
    if instances:
        print(f"\nUnprotected RDS Instances ({len(instances)}):")
        for i, instance in enumerate(instances, 1):
            print_instance_details(instance, i)


def print_summary_output(result):
    """Print human-readable summary output"""
    print_basic_summary(result)
    print_region_errors(result)
    
    unprotected_instances = result.get('unprotected_instances', [])
    print_unprotected_instances(unprotected_instances)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check RDS backup configuration")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--region', help='AWS region to check (default: all regions)')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_rds_backups(
        profile_name=args.profile,
        region_name=args.region
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
