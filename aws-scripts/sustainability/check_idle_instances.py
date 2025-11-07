#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Sustainability Pillar
Check Idle EC2 Instances

This script checks for EC2 instances that have been stopped for more than
a specified number of days (default: 7 days), which may indicate resource waste
and unnecessary costs.
"""

import boto3
import json
import re
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError, NoCredentialsError
import sys


def get_available_regions():
    """
    Get all AWS regions where EC2 is available
    
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


def parse_iso_format(time_str):
    """Parse ISO format timestamps"""
    if time_str.endswith('Z'):
        if '.' in time_str:
            return datetime.strptime(time_str, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
        else:
            return datetime.strptime(time_str, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    return None


def parse_standard_format(time_str):
    """Parse standard format timestamps"""
    try:
        return datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def extract_timestamp_from_reason(state_transition_reason):
    """Extract timestamp string using regex patterns"""
    patterns = [
        r'\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)',
        r'\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\+00:00\)',
        r'\((\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\)',
        r'\((\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\)',
        r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT',
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, state_transition_reason)
        if match:
            return match.group(1)
    
    return None


def parse_instance_stop_time(state_transition_reason):
    """
    Parse stop time from StateTransitionReason field
    
    Args:
        state_transition_reason: StateTransitionReason from EC2 instance
        
    Returns:
        datetime: Parsed stop time or None if parsing fails
    """
    if not state_transition_reason:
        return None
    
    try:
        time_str = extract_timestamp_from_reason(state_transition_reason)
        if not time_str:
            return None
        
        # Try ISO format first
        if 'T' in time_str:
            result = parse_iso_format(time_str)
            if result:
                return result
        else:
            # Try standard format
            result = parse_standard_format(time_str)
            if result:
                return result
        
        return None
    except Exception:
        return None


def get_instance_name(instance):
    """
    Get instance name from tags
    
    Args:
        instance: EC2 instance dictionary
        
    Returns:
        str: Instance name or 'N/A' if not found
    """
    if 'Tags' in instance:
        for tag in instance['Tags']:
            if tag['Key'] == 'Name':
                return tag['Value']
    return 'N/A'


def calculate_days_stopped(stop_time):
    """Calculate days since instance was stopped"""
    if stop_time:
        return (datetime.now(timezone.utc) - stop_time).days
    return None


def is_instance_idle(stop_time, idle_threshold):
    """Check if instance is considered idle based on stop time"""
    if stop_time:
        return stop_time <= idle_threshold
    return False


def analyze_instance_idle_status(instance, region, idle_threshold_days):
    """
    Analyze instance for idle status
    
    Args:
        instance: EC2 instance dictionary
        region: AWS region name
        idle_threshold_days: Number of days to consider as idle threshold
        
    Returns:
        dict: Instance analysis result
    """
    instance_id = instance['InstanceId']
    instance_type = instance['InstanceType']
    launch_time = instance['LaunchTime']
    state = instance['State']['Name']
    state_transition_reason = instance.get('StateTransitionReason', '')
    instance_name = get_instance_name(instance)
    
    # Calculate idle threshold
    idle_threshold = datetime.now(timezone.utc) - timedelta(days=idle_threshold_days)
    
    # Initialize result
    result = {
        'instance_id': instance_id,
        'instance_name': instance_name,
        'instance_type': instance_type,
        'region': region,
        'state': state,
        'launch_time': launch_time.isoformat() if launch_time else None,
        'state_transition_reason': state_transition_reason,
        'is_idle': False,
        'is_stopped': state == 'stopped',
        'stopped_since': None,
        'days_stopped': None,
        'error': None
    }
    
    # Analyze stopped instances
    if state == 'stopped':
        stop_time = parse_instance_stop_time(state_transition_reason)
        
        if stop_time:
            result['stopped_since'] = stop_time.isoformat()
            result['days_stopped'] = calculate_days_stopped(stop_time)
            result['is_idle'] = is_instance_idle(stop_time, idle_threshold)
        else:
            # Fallback: use launch time if stop time cannot be parsed
            result['stopped_since'] = launch_time.isoformat() if launch_time else None
            result['days_stopped'] = calculate_days_stopped(launch_time) if launch_time else None
            result['is_idle'] = is_instance_idle(launch_time, idle_threshold) if launch_time else False
            result['error'] = 'Could not parse stop time from StateTransitionReason'
    
    return result


def check_instances_in_region(region, idle_threshold_days):
    """
    Check instances in a specific region for idle status
    
    Args:
        region: AWS region name
        idle_threshold_days: Number of days to consider as idle threshold
        
    Returns:
        list: List of instance analysis results
    """
    try:
        ec2_client = boto3.client('ec2', region_name=region)
        instances = []
        
        # Get all instances (excluding terminated)
        paginator = ec2_client.get_paginator('describe_instances')
        
        for page in paginator.paginate(
            Filters=[
                {
                    'Name': 'instance-state-name',
                    'Values': ['pending', 'running', 'shutting-down', 'stopping', 'stopped']
                }
            ]
        ):
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_analysis = analyze_instance_idle_status(
                        instance, region, idle_threshold_days
                    )
                    instances.append(instance_analysis)
        
        return instances
        
    except ClientError as e:
        error_msg = f"AWS API error in region {region}: {str(e)}"
        return [{
            'instance_id': 'Error',
            'instance_name': 'Error',
            'instance_type': 'Error',
            'region': region,
            'state': 'Error',
            'launch_time': None,
            'state_transition_reason': '',
            'is_idle': False,
            'is_stopped': False,
            'stopped_since': None,
            'days_stopped': None,
            'error': error_msg
        }]
    except Exception as e:
        error_msg = f"Unexpected error in region {region}: {str(e)}"
        return [{
            'instance_id': 'Error',
            'instance_name': 'Error',
            'instance_type': 'Error',
            'region': region,
            'state': 'Error',
            'launch_time': None,
            'state_transition_reason': '',
            'is_idle': False,
            'is_stopped': False,
            'stopped_since': None,
            'days_stopped': None,
            'error': error_msg
        }]


def categorize_instances(all_instances):
    """Categorize instances by their status"""
    idle_instances = []
    running_instances = []
    stopped_instances = []
    error_instances = []
    
    for instance in all_instances:
        if instance.get('error'):
            error_instances.append(instance)
        elif instance['is_idle']:
            idle_instances.append(instance)
        elif instance['state'] == 'running':
            running_instances.append(instance)
        elif instance['is_stopped']:
            stopped_instances.append(instance)
    
    return idle_instances, running_instances, stopped_instances, error_instances


def check_idle_instances_all_regions(idle_threshold_days=7, regions=None):
    """
    Check for idle instances across all or specified AWS regions
    
    Args:
        idle_threshold_days: Number of days to consider as idle threshold
        regions: Specific regions to check (optional)
        
    Returns:
        dict: Complete check results
    """
    try:
        # Get regions to check
        if regions:
            target_regions = regions
        else:
            target_regions = get_available_regions()
        
        # Collect instances from all regions
        all_instances = []
        region_errors = []
        
        for region in target_regions:
            try:
                instances = check_instances_in_region(region, idle_threshold_days)
                all_instances.extend(instances)
            except Exception as e:
                region_errors.append({
                    'region': region,
                    'error': str(e)
                })
        
        # Categorize instances
        idle_instances, running_instances, stopped_instances, error_instances = categorize_instances(all_instances)
        
        return {
            'total_regions_checked': len(target_regions),
            'total_instances': len(all_instances),
            'idle_instances': len(idle_instances),
            'running_instances': len(running_instances),
            'stopped_instances': len(stopped_instances),
            'error_instances': len(error_instances),
            'idle_threshold_days': idle_threshold_days,
            'instances': all_instances,
            'non_compliant_items': idle_instances,
            'running_items': running_instances,
            'stopped_items': stopped_instances,
            'error_items': error_instances,
            'region_errors': region_errors,
            'error': None
        }
        
    except ClientError as e:
        error_msg = f"AWS API error: {str(e)}"
        return {
            'total_regions_checked': 0,
            'total_instances': 0,
            'idle_instances': 0,
            'running_instances': 0,
            'stopped_instances': 0,
            'error_instances': 0,
            'idle_threshold_days': idle_threshold_days,
            'instances': [],
            'non_compliant_items': [],
            'running_items': [],
            'stopped_items': [],
            'error_items': [],
            'region_errors': [],
            'error': error_msg
        }
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        return {
            'total_regions_checked': 0,
            'total_instances': 0,
            'idle_instances': 0,
            'running_instances': 0,
            'stopped_instances': 0,
            'error_instances': 0,
            'idle_threshold_days': idle_threshold_days,
            'instances': [],
            'non_compliant_items': [],
            'running_items': [],
            'stopped_items': [],
            'error_items': [],
            'region_errors': [],
            'error': error_msg
        }


def determine_idle_status(stats):
    """Determine overall idle instances status and message"""
    total_instances = stats['total_instances']
    idle_instances = stats['idle_instances']
    error_instances = stats['error_instances']
    threshold_days = stats['idle_threshold_days']
    
    if total_instances == 0:
        status = 'Success'
        message = 'No EC2 instances found in any region.'
    elif idle_instances == 0 and error_instances == 0:
        status = 'Success'
        message = f'No instances have been stopped for more than {threshold_days} days out of {total_instances} total instances.'
    elif idle_instances > 0 and error_instances == 0:
        status = 'Warning'
        message = f'Found {idle_instances} instances stopped for more than {threshold_days} days out of {total_instances} total instances.'
    elif idle_instances == 0 and error_instances > 0:
        status = 'Warning'
        message = f'Could not determine idle status for {error_instances} instances out of {total_instances} total instances.'
    else:
        status = 'Warning'
        message = f'Found {idle_instances} idle and {error_instances} error instances out of {total_instances} total instances.'
    
    return status, message


def check_idle_instances(profile_name=None, idle_threshold_days=7, regions=None):
    """
    Main function to check for idle EC2 instances
    
    Args:
        profile_name: AWS profile name (optional)
        idle_threshold_days: Number of days to consider as idle threshold
        regions: Specific regions to check (optional)
        
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
            # Perform the idle instances check
            result = check_idle_instances_all_regions(idle_threshold_days, regions)
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        stats = {
            'total_instances': result['total_instances'],
            'idle_instances': result['idle_instances'],
            'error_instances': result['error_instances'],
            'idle_threshold_days': result['idle_threshold_days']
        }
        
        status, message = determine_idle_status(stats)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'idle_ec2_instances',
            'total_regions_checked': result['total_regions_checked'],
            'total_instances': result['total_instances'],
            'idle_instances': result['idle_instances'],
            'running_instances': result['running_instances'],
            'stopped_instances': result['stopped_instances'],
            'error_instances': result['error_instances'],
            'idle_threshold_days': result['idle_threshold_days'],
            'instances': result['instances'],
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
            'check_type': 'idle_ec2_instances',
            'total_regions_checked': 0,
            'total_instances': 0,
            'idle_instances': 0,
            'running_instances': 0,
            'stopped_instances': 0,
            'error_instances': 0,
            'idle_threshold_days': idle_threshold_days,
            'instances': [],
            'non_compliant_items': []
        }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'check_type': 'idle_ec2_instances',
            'total_regions_checked': 0,
            'total_instances': 0,
            'idle_instances': 0,
            'running_instances': 0,
            'stopped_instances': 0,
            'error_instances': 0,
            'idle_threshold_days': idle_threshold_days,
            'instances': [],
            'non_compliant_items': []
        }


def print_instance_details(instance, index):
    """Print detailed information about an instance"""
    print(f"\n{index}. Instance Details:")
    print(f"   Instance ID: {instance['instance_id']}")
    print(f"   Name: {instance['instance_name']}")
    print(f"   Type: {instance['instance_type']}")
    print(f"   Region: {instance['region']}")
    print(f"   State: {instance['state']}")
    print(f"   Launch Time: {instance['launch_time']}")
    
    if instance['is_stopped']:
        print(f"   Stopped Since: {instance['stopped_since']}")
        print(f"   Days Stopped: {instance['days_stopped']}")
        print(f"   Is Idle: {'Yes' if instance['is_idle'] else 'No'}")
    
    if instance.get('error'):
        print(f"   Error: {instance['error']}")


def print_basic_summary(result):
    """Print basic summary information"""
    print("\nIdle EC2 Instances Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Regions Checked: {result['total_regions_checked']}")
    print(f"Total Instances: {result['total_instances']}")
    print(f"Idle Instances: {result['idle_instances']}")
    print(f"Running Instances: {result['running_instances']}")
    print(f"Stopped Instances: {result['stopped_instances']}")
    print(f"Error Instances: {result['error_instances']}")
    print(f"Idle Threshold: {result['idle_threshold_days']} days")


def print_idle_instances(instances):
    """Print details of idle instances"""
    if instances:
        print(f"\nIdle Instances ({len(instances)}):")
        for i, instance in enumerate(instances, 1):
            print_instance_details(instance, i)


def print_error_instances(instances):
    """Print details of instances with errors"""
    if instances:
        print(f"\nInstances with Errors ({len(instances)}):")
        for i, instance in enumerate(instances, 1):
            print_instance_details(instance, i)


def print_summary_output(result):
    """Print human-readable summary output"""
    print_basic_summary(result)
    
    idle_instances = result.get('non_compliant_items', [])
    print_idle_instances(idle_instances)
    
    error_instances = result.get('error_items', [])
    print_error_instances(error_instances)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check for idle EC2 instances")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    parser.add_argument('--threshold', type=int, default=7,
                       help='Idle threshold in days (default: 7)')
    parser.add_argument('--regions', nargs='+', help='Specific regions to check (default: all regions)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_idle_instances(
        profile_name=args.profile,
        idle_threshold_days=args.threshold,
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