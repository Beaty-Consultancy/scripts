#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Operational Excellence Pillar
CloudWatch Alarms Check

This script checks if essential CloudWatch alarms are configured for AWS resources.
"""

import boto3
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError
import sys


def get_available_regions():
    """
    Get all AWS regions where CloudWatch is available
    
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


def has_instance_alarm(alarms: List[Dict], instance_id: str, metric: str) -> bool:
    """
    Check if an instance has a specific alarm
    
    Args:
        alarms: List of CloudWatch alarms
        instance_id: EC2 instance ID
        metric: Metric name to check
        
    Returns:
        bool: True if alarm exists
    """
    for alarm in alarms:
        if (alarm.get('Namespace') == 'AWS/EC2' and 
            alarm.get('MetricName') == metric):
            
            dimensions = alarm.get('Dimensions', [])
            for dimension in dimensions:
                if (dimension.get('Name') == 'InstanceId' and 
                    dimension.get('Value') == instance_id):
                    return True
    return False


def has_rds_alarm(alarms: List[Dict], db_id: str, metric: str) -> bool:
    """
    Check if an RDS instance has a specific alarm
    
    Args:
        alarms: List of CloudWatch alarms
        db_id: RDS instance identifier
        metric: Metric name to check
        
    Returns:
        bool: True if alarm exists
    """
    for alarm in alarms:
        if (alarm.get('Namespace') == 'AWS/RDS' and 
            alarm.get('MetricName') == metric):
            
            dimensions = alarm.get('Dimensions', [])
            for dimension in dimensions:
                if (dimension.get('Name') == 'DBInstanceIdentifier' and 
                    dimension.get('Value') == db_id):
                    return True
    return False


def check_ec2_alarms_in_region(region_name: str) -> List[Dict[str, Any]]:
    """
    Check CloudWatch alarms for EC2 instances in a specific region
    
    Args:
        region_name: AWS region name
        
    Returns:
        list: List of EC2 instances without required alarms
    """
    non_compliant_instances = []
    
    try:
        ec2_client = boto3.client('ec2', region_name=region_name)
        cloudwatch_client = boto3.client('cloudwatch', region_name=region_name)
        
        # Get running EC2 instances
        response = ec2_client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        
        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instances.append({
                    'instance_id': instance['InstanceId'],
                    'instance_type': instance['InstanceType'],
                    'name': next((tag['Value'] for tag in instance.get('Tags', []) 
                                if tag['Key'] == 'Name'), 'No Name')
                })
        
        if not instances:
            return non_compliant_instances
        
        # Get all CloudWatch alarms
        alarms_response = cloudwatch_client.describe_alarms()
        alarms = alarms_response['MetricAlarms']
        
        # Check each instance for CPU utilization alarms
        for instance in instances:
            instance_id = instance['instance_id']
            
            if not has_instance_alarm(alarms, instance_id, 'CPUUtilization'):
                non_compliant_instances.append({
                    'resource_type': 'EC2',
                    'resource_id': instance_id,
                    'resource_name': instance['name'],
                    'instance_type': instance['instance_type'],
                    'region': region_name,
                    'missing_alarm': 'CPUUtilization',
                    'reason': 'No CPU utilization alarm configured'
                })
    
    except Exception as e:
        # Return error info for this region
        non_compliant_instances.append({
            'resource_type': 'EC2',
            'resource_id': 'unknown',
            'resource_name': 'unknown',
            'region': region_name,
            'error': str(e),
            'reason': 'Failed to check EC2 alarms'
        })
    
    return non_compliant_instances


def check_rds_alarms_in_region(region_name: str) -> List[Dict[str, Any]]:
    """
    Check CloudWatch alarms for RDS instances in a specific region
    
    Args:
        region_name: AWS region name
        
    Returns:
        list: List of RDS instances without required alarms
    """
    non_compliant_instances = []
    
    try:
        rds_client = boto3.client('rds', region_name=region_name)
        cloudwatch_client = boto3.client('cloudwatch', region_name=region_name)
        
        # Get RDS instances
        response = rds_client.describe_db_instances()
        db_instances = response['DBInstances']
        
        if not db_instances:
            return non_compliant_instances
        
        # Get all CloudWatch alarms
        alarms_response = cloudwatch_client.describe_alarms()
        alarms = alarms_response['MetricAlarms']
        
        # Required metrics for RDS
        required_metrics = ['CPUUtilization', 'DatabaseConnections', 'FreeStorageSpace']
        
        # Check each RDS instance for required alarms
        for db_instance in db_instances:
            if db_instance['DBInstanceStatus'] != 'available':
                continue
                
            db_id = db_instance['DBInstanceIdentifier']
            missing_alarms = []
            
            for metric in required_metrics:
                if not has_rds_alarm(alarms, db_id, metric):
                    missing_alarms.append(metric)
            
            if missing_alarms:
                non_compliant_instances.append({
                    'resource_type': 'RDS',
                    'resource_id': db_id,
                    'resource_name': db_id,
                    'engine': db_instance.get('Engine', 'unknown'),
                    'region': region_name,
                    'missing_alarms': missing_alarms,
                    'reason': f'Missing alarms: {", ".join(missing_alarms)}'
                })
    
    except Exception as e:
        # Return error info for this region
        non_compliant_instances.append({
            'resource_type': 'RDS',
            'resource_id': 'unknown',
            'resource_name': 'unknown',
            'region': region_name,
            'error': str(e),
            'reason': 'Failed to check RDS alarms'
        })
    
    return non_compliant_instances


def check_cloudwatch_alarms_for_region(region_name: str) -> Dict[str, Any]:
    """
    Check CloudWatch alarms for all resources in a specific region
    
    Args:
        region_name: AWS region name
        
    Returns:
        dict: Region analysis data
    """
    try:
        region_results = []
        
        # Check EC2 alarms
        ec2_issues = check_ec2_alarms_in_region(region_name)
        region_results.extend(ec2_issues)
        
        # Check RDS alarms
        rds_issues = check_rds_alarms_in_region(region_name)
        region_results.extend(rds_issues)
        
        return {
            "region": region_name,
            "results": region_results,
            "error": None
        }
        
    except Exception as e:
        return {
            "region": region_name,
            "results": [],
            "error": str(e)
        }


def check_cloudwatch_alarms_all_regions(max_workers: int = 5) -> Dict[str, Any]:
    """
    Check CloudWatch alarms across all AWS regions
    
    Args:
        max_workers: Maximum number of concurrent workers
        
    Returns:
        dict: Complete analysis results
    """
    try:
        regions = get_available_regions()
        all_results = []
        error_regions = []
        
        # Use ThreadPoolExecutor for parallel region checking
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_region = {
                executor.submit(check_cloudwatch_alarms_for_region, region): region 
                for region in regions
            }
            
            for future in as_completed(future_to_region):
                region = future_to_region[future]
                try:
                    result = future.result()
                    if result['error']:
                        error_regions.append(result)
                    else:
                        all_results.extend(result['results'])
                except Exception as e:
                    error_regions.append({
                        "region": region,
                        "error": str(e),
                        "results": []
                    })
        
        # Filter out error entries for statistics
        valid_results = [item for item in all_results if 'error' not in item]
        error_results = [item for item in all_results if 'error' in item]
        
        # Calculate statistics
        total_resources = len(valid_results)
        ec2_missing_alarms = len([item for item in valid_results if item.get('resource_type') == 'EC2'])
        rds_missing_alarms = len([item for item in valid_results if item.get('resource_type') == 'RDS'])
        
        return {
            'total_regions_checked': len(regions),
            'total_resources_missing_alarms': total_resources,
            'ec2_missing_alarms': ec2_missing_alarms,
            'rds_missing_alarms': rds_missing_alarms,
            'error_count': len(error_results),
            'non_compliant_items': valid_results,
            'error_items': error_results,
            'error_regions': error_regions
        }
        
    except Exception as e:
        raise RuntimeError(f"Failed to check CloudWatch alarms across regions: {str(e)}") from e


def determine_cloudwatch_alarms_status(stats: Dict[str, Any]) -> tuple:
    """
    Determine overall status based on CloudWatch alarms analysis statistics
    
    Args:
        stats: Dictionary containing analysis statistics
        
    Returns:
        tuple: (status, message)
    """
    total_missing = stats['total_resources_missing_alarms']
    error_count = stats['error_count']
    
    if error_count > 0 and total_missing == 0:
        return ('Error', f'Failed to check CloudWatch alarms: {error_count} regions had errors')
    elif total_missing == 0:
        return ('Pass', 'All resources have appropriate CloudWatch alarms configured')
    else:
        return ('Fail', f'{total_missing} resources are missing essential CloudWatch alarms')


def check_cloudwatch_alarms(profile_name: Optional[str] = None, max_workers: int = 5) -> Dict[str, Any]:
    """
    Main function to check CloudWatch alarms across all regions
    
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
            # Perform the CloudWatch alarms check
            result = check_cloudwatch_alarms_all_regions(max_workers)
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        status, message = determine_cloudwatch_alarms_status(result)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'cloudwatch_alarms',
            'total_regions_checked': result['total_regions_checked'],
            'total_resources_missing_alarms': result['total_resources_missing_alarms'],
            'ec2_missing_alarms': result['ec2_missing_alarms'],
            'rds_missing_alarms': result['rds_missing_alarms'],
            'error_count': result['error_count'],
            'non_compliant_items': result['non_compliant_items']
        }
        
        return final_result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found or invalid',
            'check_type': 'cloudwatch_alarms',
            'non_compliant_items': []
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': 'Insufficient permissions to check CloudWatch alarms',
                'check_type': 'cloudwatch_alarms',
                'non_compliant_items': []
            }
        else:
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': f'AWS API error: {error_code}',
                'check_type': 'cloudwatch_alarms',
                'non_compliant_items': []
            }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error during CloudWatch alarms check: {str(e)}',
            'check_type': 'cloudwatch_alarms',
            'non_compliant_items': []
        }


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check CloudWatch alarms for AWS resources")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--max-workers', type=int, default=5,
                       help='Maximum number of concurrent workers (default: 5)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_cloudwatch_alarms(
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
