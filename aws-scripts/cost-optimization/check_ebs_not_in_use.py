#!/usr/bin/env python3
"""
EBS Volumes Not In Use Check Script

This script checks for EBS volumes that are not attached to any EC2 instances
across all AWS regions, identifying potential cost optimization opportunities.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime


def check_ebs_not_in_use(profile_name=None):
    """
    Check for EBS volumes not attached to any EC2 instances
    
    Args:
        profile_name (str): AWS profile name (optional)
        
    Returns:
        dict: Structured result for dashboard compatibility
    """
    
    try:
        # Initialize session with profile
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
        else:
            session = boto3.Session()
        
        # Get all available regions
        ec2_client = session.client('ec2', region_name='us-east-1')
        regions_response = ec2_client.describe_regions()
        regions = [region['RegionName'] for region in regions_response['Regions']]
        
        unattached_volumes = []
        total_volumes = 0
        total_unattached = 0
        total_size_gb = 0
        total_unattached_size_gb = 0
        
        # Check each region
        for region in regions:
            try:
                ec2_client = session.client('ec2', region_name=region)
                
                # Get all volumes in the region
                volumes_response = ec2_client.describe_volumes()
                volumes = volumes_response['Volumes']
                
                for volume in volumes:
                    total_volumes += 1
                    volume_size = volume.get('Size', 0)
                    total_size_gb += volume_size
                    
                    # Check if volume is not attached (no attachments)
                    attachments = volume.get('Attachments', [])
                    if not attachments:
                        total_unattached += 1
                        total_unattached_size_gb += volume_size
                        
                        # Get volume tags
                        tags = {tag['Key']: tag['Value'] for tag in volume.get('Tags', [])}
                        
                        volume_info = {
                            'volume_id': volume['VolumeId'],
                            'region': region,
                            'size_gb': volume_size,
                            'volume_type': volume.get('VolumeType', 'Unknown'),
                            'state': volume.get('State', 'Unknown'),
                            'availability_zone': volume.get('AvailabilityZone', 'Unknown'),
                            'creation_date': volume.get('CreateTime', '').strftime('%Y-%m-%d') if volume.get('CreateTime') else 'Unknown',
                            'encrypted': volume.get('Encrypted', False),
                            'snapshot_id': volume.get('SnapshotId', 'N/A'),
                            'tags': tags,
                            'name': tags.get('Name', 'No Name')
                        }
                        
                        unattached_volumes.append(volume_info)
                        
            except ClientError as e:
                # Skip regions where we don't have access
                if e.response['Error']['Code'] in ['UnauthorizedOperation', 'AuthFailure']:
                    continue
                else:
                    raise
        
        # Determine overall status
        if total_unattached == 0:
            status = 'Optimized'
            message = 'All EBS volumes are attached to EC2 instances. No unused volumes found.'
        else:
            status = 'Action Required'
            message = f'{total_unattached} unattached EBS volume(s) found across all regions, totaling {total_unattached_size_gb} GB.'
        
        # Create structured result
        result = {
            'status': status,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'details': {
                'total_volumes': total_volumes,
                'total_unattached': total_unattached,
                'total_size_gb': total_size_gb,
                'total_unattached_size_gb': total_unattached_size_gb,
                'regions_checked': len(regions),
                'unattached_volumes': unattached_volumes
            }
        }
        
        return result
        
    except NoCredentialsError:
        return {
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'timestamp': datetime.now().isoformat(),
            'details': {
                'error_type': 'NoCredentialsError',
                'total_volumes': 0,
                'total_unattached': 0,
                'total_size_gb': 0,
                'total_unattached_size_gb': 0,
                'regions_checked': 0,
                'unattached_volumes': []
            }
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        return {
            'status': 'Error',
            'message': f'AWS API Error: {error_message}',
            'timestamp': datetime.now().isoformat(),
            'details': {
                'error_type': 'ClientError',
                'error_code': error_code,
                'error_message': error_message,
                'total_volumes': 0,
                'total_unattached': 0,
                'total_size_gb': 0,
                'total_unattached_size_gb': 0,
                'regions_checked': 0,
                'unattached_volumes': []
            }
        }
        
    except Exception as e:
        return {
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'details': {
                'error_type': 'UnexpectedError',
                'error_message': str(e),
                'total_volumes': 0,
                'total_unattached': 0,
                'total_size_gb': 0,
                'total_unattached_size_gb': 0,
                'regions_checked': 0,
                'unattached_volumes': []
            }
        }


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check for EBS volumes not in use')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_ebs_not_in_use(args.profile)
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        # Summary output
        print(f"Status: {result['status']}")
        print(f"Message: {result['message']}")
        print(f"Total Volumes: {result['details']['total_volumes']}")
        print(f"Unattached Volumes: {result['details']['total_unattached']}")
        print(f"Total Size: {result['details']['total_size_gb']} GB")
        print(f"Unattached Size: {result['details']['total_unattached_size_gb']} GB")
        print(f"Regions Checked: {result['details']['regions_checked']}")
        
        if result['details']['unattached_volumes']:
            print("\nUnattached Volumes:")
            for i, volume in enumerate(result['details']['unattached_volumes'], 1):
                print(f"  {i}. {volume['volume_id']} ({volume['name']}) - {volume['size_gb']} GB in {volume['region']}")


if __name__ == "__main__":
    main()
