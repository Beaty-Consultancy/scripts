#!/usr/bin/env python3
"""
AWS EC2 Instance Type Check Script

This script checks AWS EC2 instances and identifies instances running on older generation
instance types that should be upgraded to newer, more efficient generations.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime

# Constants
OLDER_GENERATION_FAMILIES = {
    't2': 't3',
    't1': 't3',
    'm4': 'm5',
    'm3': 'm5',
    'm1': 'm5',
    'c4': 'c5',
    'c3': 'c5',
    'c1': 'c5',
    'r4': 'r5',
    'r3': 'r5',
    'i3': 'i4i',
    'i2': 'i4i',
    'd2': 'd3',
    'x1e': 'x2iezn',
    'x1': 'x2iezn',
    'p2': 'p4',
    'p3': 'p4',
    'g3': 'g4dn',
    'g2': 'g4dn',
    'f1': 'f1',  # No newer generation yet
    'h1': 'h1'   # No newer generation yet
}

RECOMMENDED_UPGRADE_MESSAGE = "Consider upgrading to newer generation instance types for better performance, efficiency, and cost savings"


def create_instance_entry(instance, region_name):
    """Create an instance entry from EC2 instance data"""
    instance_type = instance['InstanceType']
    instance_family = instance_type.split('.')[0]
    recommended_family = OLDER_GENERATION_FAMILIES.get(instance_family, instance_family)
    
    return {
        'instanceId': instance['InstanceId'],
        'instanceType': instance_type,
        'instanceFamily': instance_family,
        'recommendedFamily': recommended_family if recommended_family != instance_family else 'Already current generation',
        'state': instance['State']['Name'],
        'region': region_name,
        'availabilityZone': instance['Placement']['AvailabilityZone'],
        'launchTime': instance.get('LaunchTime', 'N/A').isoformat() if instance.get('LaunchTime') else 'N/A',
        'platform': instance.get('Platform', 'Linux/Unix'),
        'tags': [
            {
                'key': tag['Key'],
                'value': tag['Value']
            }
            for tag in instance.get('Tags', [])
        ]
    }


def process_instances(instances, region_name):
    """Process EC2 instances and identify those using older generation types"""
    older_generation_instances = []
    
    for reservation in instances:
        for instance in reservation.get('Instances', []):
            instance_type = instance['InstanceType']
            instance_family = instance_type.split('.')[0]
            
            # Check if instance family is in older generation list
            if instance_family in OLDER_GENERATION_FAMILIES:
                instance_entry = create_instance_entry(instance, region_name)
                older_generation_instances.append(instance_entry)
    
    return older_generation_instances


def get_all_regions(session):
    """Get all available AWS regions"""
    try:
        ec2_client = session.client('ec2', region_name='us-east-1')
        regions_response = ec2_client.describe_regions()
        return [region['RegionName'] for region in regions_response['Regions']]
    except Exception:
        # Fallback to common regions if API call fails
        return [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1',
            'ap-northeast-2', 'ap-south-1', 'ca-central-1',
            'sa-east-1'
        ]


def check_region_instances(session, region_name):
    """Check EC2 instances in a specific region"""
    try:
        ec2_client = session.client('ec2', region_name=region_name)
        
        # Get all EC2 instances in this region
        response = ec2_client.describe_instances()
        instances = response.get('Reservations', [])
        
        # Handle pagination if needed
        while 'NextToken' in response:
            response = ec2_client.describe_instances(NextToken=response['NextToken'])
            instances.extend(response.get('Reservations', []))
        
        return instances
    except Exception:
        # Return empty list if region check fails
        return []


def count_total_instances(all_reservations):
    """Count total instances from all reservations"""
    total = 0
    for reservation in all_reservations:
        total += len(reservation.get('Instances', []))
    return total


def create_success_response(total_instances, older_generation_instances, regions_checked):
    """Create success response structure"""
    older_generation_count = len(older_generation_instances)
    current_generation_count = total_instances - older_generation_count
    
    if older_generation_count == 0:
        message = f"All {total_instances} EC2 instances across {regions_checked} regions are using current generation instance types."
    else:
        message = f"{older_generation_count} out of {total_instances} EC2 instances across {regions_checked} regions are using older generation instance types."
    
    return {
        'status': 'Success',
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'total_instances': str(total_instances),
        'current_generation_instances': str(current_generation_count),
        'older_generation_instances': str(older_generation_count),
        'regions_checked': str(regions_checked),
        'details': {
            'older_generation_instances': older_generation_instances,
            'recommendations': [
                RECOMMENDED_UPGRADE_MESSAGE
            ] if older_generation_count > 0 else []
        }
    }


def check_ec2_instance_types(profile_name=None, region_name=None):
    """
    Check AWS EC2 instances for current generation instance types across all regions or specific region
    
    Args:
        profile_name (str): AWS profile name (optional)
        region_name (str): AWS region name (optional, if not provided checks all regions)
        
    Returns:
        dict: Structured result for dashboard compatibility
    """
    
    try:
        # Initialize session with profile
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
        else:
            session = boto3.Session()
        
        all_reservations = []
        all_older_generation_instances = []
        regions_to_check = []
        
        # Determine which regions to check
        if region_name:
            regions_to_check = [region_name]
        else:
            regions_to_check = get_all_regions(session)
        
        # Check each region
        for region in regions_to_check:
            try:
                reservations = check_region_instances(session, region)
                if reservations:
                    all_reservations.extend(reservations)
                    older_generation_instances = process_instances(reservations, region)
                    all_older_generation_instances.extend(older_generation_instances)
            except Exception:
                # Continue with other regions if one fails
                continue
        
        total_instances = count_total_instances(all_reservations)
        regions_checked = len(regions_to_check)
        
        if total_instances == 0:
            region_text = f"region {region_name}" if region_name else f"{regions_checked} regions"
            return {
                'status': 'Success',
                'message': f'No EC2 instances found in the specified {region_text}.',
                'timestamp': datetime.now().isoformat(),
                'total_instances': '0',
                'current_generation_instances': '0',
                'older_generation_instances': '0',
                'regions_checked': str(regions_checked),
                'details': {
                    'older_generation_instances': [],
                    'recommendations': []
                }
            }
        
        # Generate result
        return create_success_response(total_instances, all_older_generation_instances, regions_checked)
        
    except NoCredentialsError:
        return {
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'timestamp': datetime.now().isoformat(),
            'total_instances': '0',
            'current_generation_instances': '0',
            'older_generation_instances': '0',
            'regions_checked': '0',
            'details': {
                'error_type': 'NoCredentialsError',
                'error_message': 'AWS credentials not found',
                'older_generation_instances': [],
                'recommendations': []
            }
        }
    
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        return {
            'status': 'Error',
            'message': f'AWS API error: {error_message}',
            'timestamp': datetime.now().isoformat(),
            'total_instances': '0',
            'current_generation_instances': '0',
            'older_generation_instances': '0',
            'regions_checked': '0',
            'details': {
                'error_type': error_code,
                'error_message': error_message,
                'older_generation_instances': [],
                'recommendations': []
            }
        }
    
    except Exception as e:
        return {
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'total_instances': '0',
            'current_generation_instances': '0',
            'older_generation_instances': '0',
            'regions_checked': '0',
            'details': {
                'error_type': 'UnexpectedError',
                'error_message': str(e),
                'older_generation_instances': [],
                'recommendations': []
            }
        }


def print_summary_output(result):
    """Print summary output for EC2 instance types"""
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total EC2 Instances: {result['total_instances']}")
    print(f"Current Generation Instances: {result['current_generation_instances']}")
    print(f"Older Generation Instances: {result['older_generation_instances']}")
    print(f"Regions Checked: {result['regions_checked']}")
    
    if result['details']['older_generation_instances']:
        print("\nOlder Generation Instances:")
        for i, instance in enumerate(result['details']['older_generation_instances'], 1):
            print(f"  {i}. Instance ID: {instance['instanceId']}")
            print(f"     Type: {instance['instanceType']} (Family: {instance['instanceFamily']})")
            print(f"     Recommended: {instance['recommendedFamily']}")
            print(f"     State: {instance['state']}")
            print(f"     Region: {instance['region']}")
            print(f"     AZ: {instance['availabilityZone']}")
            print(f"     Platform: {instance['platform']}")
            print(f"     Launch Time: {instance['launchTime']}")
            
            if instance['tags']:
                print("     Tags:")
                for tag in instance['tags']:
                    print(f"       - {tag['key']}: {tag['value']}")
            else:
                print("     Tags: None")
            print()
    
    if result['details']['recommendations']:
        print("Recommendations:")
        for recommendation in result['details']['recommendations']:
            print(f"  - {recommendation}")


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check AWS EC2 instances for current generation instance types')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--region', help='AWS region name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_ec2_instance_types(
        profile_name=args.profile,
        region_name=args.region
    )
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        print_summary_output(result)


if __name__ == "__main__":
    main()
