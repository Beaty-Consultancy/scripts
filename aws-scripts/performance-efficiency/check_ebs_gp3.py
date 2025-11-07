#!/usr/bin/env python3
"""
AWS EBS GP3 Volume Type Check Script

This script checks AWS EBS volumes and identifies volumes that are not using GP3 type.
GP3 volumes typically offer better performance and cost efficiency compared to GP2.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime

# Constants
GP3_VOLUME_TYPE = 'gp3'
RECOMMENDED_VOLUME_TYPE = 'GP3'


def create_volume_entry(volume, region_name):
    """Create a volume entry from EBS volume data"""
    return {
        'volumeId': volume['VolumeId'],
        'volumeType': volume['VolumeType'],
        'size': f"{volume['Size']} GB",
        'state': volume['State'],
        'region': region_name,
        'availabilityZone': volume['AvailabilityZone'],
        'encrypted': volume['Encrypted'],
        'attachments': [
            {
                'instanceId': attachment.get('InstanceId', 'N/A'),
                'device': attachment.get('Device', 'N/A'),
                'state': attachment.get('State', 'N/A')
            }
            for attachment in volume.get('Attachments', [])
        ]
    }


def process_volumes(volumes, region_name):
    """Process EBS volumes and identify non-GP3 volumes"""
    non_gp3_volumes = []
    
    for volume in volumes:
        if volume['VolumeType'] != GP3_VOLUME_TYPE:
            volume_entry = create_volume_entry(volume, region_name)
            non_gp3_volumes.append(volume_entry)
    
    return non_gp3_volumes


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


def check_region_volumes(session, region_name):
    """Check EBS volumes in a specific region"""
    try:
        ec2_client = session.client('ec2', region_name=region_name)
        
        # Get all EBS volumes in this region
        response = ec2_client.describe_volumes()
        volumes = response.get('Volumes', [])
        
        # Handle pagination if needed
        while 'NextToken' in response:
            response = ec2_client.describe_volumes(NextToken=response['NextToken'])
            volumes.extend(response.get('Volumes', []))
        
        return volumes
    except Exception:
        # Return empty list if region check fails (region might not be accessible)
        return []


def create_success_response(total_volumes, non_gp3_volumes, regions_checked):
    """Create success response structure"""
    non_gp3_count = len(non_gp3_volumes)
    gp3_count = total_volumes - non_gp3_count
    
    if non_gp3_count == 0:
        message = f"All {total_volumes} EBS volumes across {regions_checked} regions are already using {RECOMMENDED_VOLUME_TYPE} type."
    else:
        message = f"{non_gp3_count} out of {total_volumes} EBS volumes across {regions_checked} regions are not using {RECOMMENDED_VOLUME_TYPE} type."
    
    return {
        'status': 'Success',
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'total_volumes': str(total_volumes),
        'gp3_volumes': str(gp3_count),
        'non_gp3_volumes': str(non_gp3_count),
        'regions_checked': str(regions_checked),
        'details': {
            'non_gp3_volumes': non_gp3_volumes,
            'recommendations': [
                f"Consider migrating non-{RECOMMENDED_VOLUME_TYPE} volumes to {RECOMMENDED_VOLUME_TYPE} for better performance and cost efficiency"
            ] if non_gp3_count > 0 else []
        }
    }


def check_ebs_gp3_volumes(profile_name=None, region_name=None):
    """
    Check AWS EBS volumes for GP3 type usage across all regions or specific region
    
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
        
        all_volumes = []
        all_non_gp3_volumes = []
        regions_to_check = []
        
        # Determine which regions to check
        if region_name:
            regions_to_check = [region_name]
        else:
            regions_to_check = get_all_regions(session)
        
        # Check each region
        for region in regions_to_check:
            try:
                volumes = check_region_volumes(session, region)
                if volumes:
                    all_volumes.extend(volumes)
                    non_gp3_volumes = process_volumes(volumes, region)
                    all_non_gp3_volumes.extend(non_gp3_volumes)
            except Exception:
                # Continue with other regions if one fails
                continue
        
        total_volumes = len(all_volumes)
        regions_checked = len(regions_to_check)
        
        if total_volumes == 0:
            region_text = f"region {region_name}" if region_name else f"{regions_checked} regions"
            return {
                'status': 'Success',
                'message': f'No EBS volumes found in the specified {region_text}.',
                'timestamp': datetime.now().isoformat(),
                'total_volumes': '0',
                'gp3_volumes': '0',
                'non_gp3_volumes': '0',
                'regions_checked': str(regions_checked),
                'details': {
                    'non_gp3_volumes': [],
                    'recommendations': []
                }
            }
        
        # Generate result
        return create_success_response(total_volumes, all_non_gp3_volumes, regions_checked)
        
    except NoCredentialsError:
        return {
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'timestamp': datetime.now().isoformat(),
            'total_volumes': '0',
            'gp3_volumes': '0',
            'non_gp3_volumes': '0',
            'regions_checked': '0',
            'details': {
                'error_type': 'NoCredentialsError',
                'error_message': 'AWS credentials not found',
                'non_gp3_volumes': [],
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
            'total_volumes': '0',
            'gp3_volumes': '0',
            'non_gp3_volumes': '0',
            'regions_checked': '0',
            'details': {
                'error_type': error_code,
                'error_message': error_message,
                'non_gp3_volumes': [],
                'recommendations': []
            }
        }
    
    except Exception as e:
        return {
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'total_volumes': '0',
            'gp3_volumes': '0',
            'non_gp3_volumes': '0',
            'regions_checked': '0',
            'details': {
                'error_type': 'UnexpectedError',
                'error_message': str(e),
                'non_gp3_volumes': [],
                'recommendations': []
            }
        }


def print_summary_output(result):
    """Print summary output for EBS GP3 volumes"""
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total EBS Volumes: {result['total_volumes']}")
    print(f"GP3 Volumes: {result['gp3_volumes']}")
    print(f"Non-GP3 Volumes: {result['non_gp3_volumes']}")
    print(f"Regions Checked: {result['regions_checked']}")
    
    if result['details']['non_gp3_volumes']:
        print("\nNon-GP3 Volumes:")
        for i, volume in enumerate(result['details']['non_gp3_volumes'], 1):
            print(f"  {i}. Volume ID: {volume['volumeId']}")
            print(f"     Type: {volume['volumeType']}")
            print(f"     Size: {volume['size']}")
            print(f"     State: {volume['state']}")
            print(f"     Region: {volume['region']}")
            print(f"     AZ: {volume['availabilityZone']}")
            print(f"     Encrypted: {volume['encrypted']}")
            
            if volume['attachments']:
                print("     Attachments:")
                for attachment in volume['attachments']:
                    print(f"       - Instance: {attachment['instanceId']}, Device: {attachment['device']}, State: {attachment['state']}")
            else:
                print("     Attachments: None")
            print()
    
    if result['details']['recommendations']:
        print("Recommendations:")
        for recommendation in result['details']['recommendations']:
            print(f"  - {recommendation}")


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check AWS EBS volumes for GP3 type usage')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--region', help='AWS region name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_ebs_gp3_volumes(
        profile_name=args.profile,
        region_name=args.region
    )
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        print_summary_output(result)


if __name__ == "__main__":
    main()
