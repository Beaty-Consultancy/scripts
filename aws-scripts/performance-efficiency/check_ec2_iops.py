#!/usr/bin/env python3
"""
AWS EC2 IOPS Performance Check Script

This script checks AWS EC2 instances and evaluates their IOPS performance
by analyzing attached EBS volumes and their IOPS configurations.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime

# Constants
DEFAULT_IOPS_MAPPING = {
    'gp2': {'base_iops': 100, 'iops_per_gb': 3, 'max_iops': 16000},
    'gp3': {'base_iops': 3000, 'iops_per_gb': 0, 'max_iops': 16000},
    'io1': {'base_iops': 0, 'iops_per_gb': 0, 'max_iops': 64000},
    'io2': {'base_iops': 0, 'iops_per_gb': 0, 'max_iops': 256000},
    'st1': {'base_iops': 0, 'iops_per_gb': 0, 'max_iops': 500},
    'sc1': {'base_iops': 0, 'iops_per_gb': 0, 'max_iops': 250},
    'standard': {'base_iops': 100, 'iops_per_gb': 0, 'max_iops': 100}
}

LOW_IOPS_THRESHOLD = 1000
RECOMMENDED_IOPS_MESSAGE = "Consider upgrading to higher IOPS volumes for better performance"


def get_instance_name(instance):
    """Extract instance name from tags"""
    for tag in instance.get('Tags', []):
        if tag['Key'].lower() == 'name':
            return tag['Value']
    return instance['InstanceId']


def calculate_volume_iops(volume):
    """Calculate effective IOPS for a volume"""
    volume_type = volume['VolumeType']
    size = volume['Size']
    
    # For provisioned IOPS volumes (io1, io2), use the provisioned IOPS
    if volume_type in ['io1', 'io2'] and 'Iops' in volume:
        return volume['Iops']
    
    # For gp3, use provisioned IOPS if specified, otherwise base IOPS
    if volume_type == 'gp3':
        return volume.get('Iops', DEFAULT_IOPS_MAPPING[volume_type]['base_iops'])
    
    # For gp2, calculate based on size
    if volume_type == 'gp2':
        calculated_iops = DEFAULT_IOPS_MAPPING[volume_type]['base_iops'] + (size * DEFAULT_IOPS_MAPPING[volume_type]['iops_per_gb'])
        return min(calculated_iops, DEFAULT_IOPS_MAPPING[volume_type]['max_iops'])
    
    # For other volume types, return max IOPS from mapping
    return DEFAULT_IOPS_MAPPING.get(volume_type, {}).get('max_iops', 0)


def get_volume_details(ec2_client, volume_id):
    """Get detailed volume information"""
    try:
        response = ec2_client.describe_volumes(VolumeIds=[volume_id])
        volumes = response.get('Volumes', [])
        return volumes[0] if volumes else None
    except Exception:
        return None


def create_instance_entry(instance, volumes_info, region_name):
    """Create an instance entry with IOPS information"""
    instance_name = get_instance_name(instance)
    instance_type = instance['InstanceType']
    instance_id = instance['InstanceId']
    
    # Calculate total IOPS from all attached volumes
    total_iops = 0
    volume_details = []
    
    for attachment in instance.get('BlockDeviceMappings', []):
        if 'Ebs' in attachment and attachment['Ebs'].get('VolumeId'):
            volume_id = attachment['Ebs']['VolumeId']
            volume_info = volumes_info.get(volume_id)
            
            if volume_info:
                volume_iops = calculate_volume_iops(volume_info)
                total_iops += volume_iops
                
                volume_details.append({
                    'volumeId': volume_id,
                    'volumeType': volume_info['VolumeType'],
                    'size': f"{volume_info['Size']} GB",
                    'iops': volume_iops,
                    'device': attachment['DeviceName']
                })
    
    return {
        'instanceName': instance_name,
        'instanceId': instance_id,
        'instanceType': instance_type,
        'state': instance['State']['Name'],
        'region': region_name,
        'availabilityZone': instance['Placement']['AvailabilityZone'],
        'totalIOPS': total_iops,
        'volumeDetails': volume_details,
        'lowIOPSWarning': total_iops < LOW_IOPS_THRESHOLD
    }


def get_all_volumes_in_region(ec2_client):
    """Get all volumes in a region for efficient lookup"""
    try:
        response = ec2_client.describe_volumes()
        volumes = response.get('Volumes', [])
        
        # Handle pagination if needed
        while 'NextToken' in response:
            response = ec2_client.describe_volumes(NextToken=response['NextToken'])
            volumes.extend(response.get('Volumes', []))
        
        # Create a lookup dictionary
        return {volume['VolumeId']: volume for volume in volumes}
    except Exception:
        return {}


def process_instances(instances, volumes_info, region_name):
    """Process EC2 instances and analyze their IOPS performance"""
    instance_iops_data = []
    
    for reservation in instances:
        for instance in reservation.get('Instances', []):
            # Only process running instances with attached volumes
            if (instance['State']['Name'] in ['running', 'stopped'] and 
                instance.get('BlockDeviceMappings')):
                
                instance_entry = create_instance_entry(instance, volumes_info, region_name)
                instance_iops_data.append(instance_entry)
    
    return instance_iops_data


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


def check_region_instances_iops(session, region_name):
    """Check EC2 instances IOPS in a specific region"""
    try:
        ec2_client = session.client('ec2', region_name=region_name)
        
        # Get all volumes first for efficient lookup
        volumes_info = get_all_volumes_in_region(ec2_client)
        
        # Get all EC2 instances in this region
        response = ec2_client.describe_instances()
        instances = response.get('Reservations', [])
        
        # Handle pagination if needed
        while 'NextToken' in response:
            response = ec2_client.describe_instances(NextToken=response['NextToken'])
            instances.extend(response.get('Reservations', []))
        
        return process_instances(instances, volumes_info, region_name)
    except Exception:
        # Return empty list if region check fails
        return []


def create_success_response(all_instances_iops, regions_checked):
    """Create success response structure"""
    total_instances = len(all_instances_iops)
    low_iops_instances = [inst for inst in all_instances_iops if inst['lowIOPSWarning']]
    low_iops_count = len(low_iops_instances)
    
    if total_instances == 0:
        message = f"No EC2 instances with attached volumes found across {regions_checked} regions."
    elif low_iops_count == 0:
        message = f"All {total_instances} EC2 instances across {regions_checked} regions have adequate IOPS performance."
    else:
        message = f"{low_iops_count} out of {total_instances} EC2 instances across {regions_checked} regions have low IOPS performance."
    
    return {
        'status': 'Success',
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'total_instances': str(total_instances),
        'low_iops_instances': str(low_iops_count),
        'regions_checked': str(regions_checked),
        'details': {
            'instances': all_instances_iops,
            'low_iops_threshold': LOW_IOPS_THRESHOLD,
            'recommendations': [
                RECOMMENDED_IOPS_MESSAGE
            ] if low_iops_count > 0 else []
        }
    }


def check_ec2_iops(profile_name=None, region_name=None):
    """
    Check AWS EC2 instances IOPS performance across all regions or specific region
    
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
        
        all_instances_iops = []
        regions_to_check = []
        
        # Determine which regions to check
        if region_name:
            regions_to_check = [region_name]
        else:
            regions_to_check = get_all_regions(session)
        
        # Check each region
        for region in regions_to_check:
            try:
                instances_iops = check_region_instances_iops(session, region)
                all_instances_iops.extend(instances_iops)
            except Exception:
                # Continue with other regions if one fails
                continue
        
        regions_checked = len(regions_to_check)
        
        if len(all_instances_iops) == 0:
            region_text = f"region {region_name}" if region_name else f"{regions_checked} regions"
            return {
                'status': 'Success',
                'message': f'No EC2 instances with attached volumes found in the specified {region_text}.',
                'timestamp': datetime.now().isoformat(),
                'total_instances': '0',
                'low_iops_instances': '0',
                'regions_checked': str(regions_checked),
                'details': {
                    'instances': [],
                    'low_iops_threshold': LOW_IOPS_THRESHOLD,
                    'recommendations': []
                }
            }
        
        # Generate result
        return create_success_response(all_instances_iops, regions_checked)
        
    except NoCredentialsError:
        return {
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'timestamp': datetime.now().isoformat(),
            'total_instances': '0',
            'low_iops_instances': '0',
            'regions_checked': '0',
            'details': {
                'error_type': 'NoCredentialsError',
                'error_message': 'AWS credentials not found',
                'instances': [],
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
            'low_iops_instances': '0',
            'regions_checked': '0',
            'details': {
                'error_type': error_code,
                'error_message': error_message,
                'instances': [],
                'recommendations': []
            }
        }
    
    except Exception as e:
        return {
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'total_instances': '0',
            'low_iops_instances': '0',
            'regions_checked': '0',
            'details': {
                'error_type': 'UnexpectedError',
                'error_message': str(e),
                'instances': [],
                'recommendations': []
            }
        }


def print_instance_details(instance, index):
    """Print detailed information for a single instance"""
    warning_indicator = " ⚠️" if instance['lowIOPSWarning'] else ""
    print(f"  {index}. {instance['instanceName']} ({instance['instanceId']}){warning_indicator}")
    print(f"     Instance Type: {instance['instanceType']}")
    print(f"     State: {instance['state']}")
    print(f"     Region: {instance['region']}")
    print(f"     Total IOPS: {instance['totalIOPS']}")
    
    if instance['volumeDetails']:
        print("     Volume Details:")
        for volume in instance['volumeDetails']:
            print(f"       - {volume['device']}: {volume['volumeId']} ({volume['volumeType']}, {volume['size']}, {volume['iops']} IOPS)")
    else:
        print("     Volume Details: None")
    print()


def print_summary_output(result):
    """Print summary output for EC2 IOPS performance"""
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Instances Analyzed: {result['total_instances']}")
    print(f"Low IOPS Instances: {result['low_iops_instances']}")
    print(f"Regions Checked: {result['regions_checked']}")
    
    if result['details']['instances']:
        print(f"\nIOPS Threshold: {result['details']['low_iops_threshold']}")
        print("\nInstance IOPS Analysis:")
        for i, instance in enumerate(result['details']['instances'], 1):
            print_instance_details(instance, i)
    
    if result['details']['recommendations']:
        print("Recommendations:")
        for recommendation in result['details']['recommendations']:
            print(f"  - {recommendation}")


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check AWS EC2 instances IOPS performance')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--region', help='AWS region name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_ec2_iops(
        profile_name=args.profile,
        region_name=args.region
    )
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        print_summary_output(result)


if __name__ == "__main__":
    main()
