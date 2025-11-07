#!/usr/bin/env python3
"""
EBS Volume Encryption Checker

Script to check if EBS volumes are encrypted in an AWS account.
"""

import boto3
import json
import sys
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime


def get_volume_name(tags):
    """Extract volume name from tags or return None if not found"""
    if tags:
        for tag in tags:
            if tag.get('Key', '').lower() == 'name':
                name = tag.get('Value', '').strip()
                return name if name else None
    return None


def get_volume_display_name(volume_id, volume_name):
    """Get display name for volume - show name and ID if name exists, just ID if not"""
    if volume_name:
        return f"{volume_name} ({volume_id})"
    else:
        return volume_id


def check_ebs_encryption_in_region(session, region_name):
    """
    Check EBS volume encryption in a specific region
    
    Args:
        session: boto3 session
        region_name: AWS region name
        
    Returns:
        list: List of volume encryption details
    """
    try:
        ec2_client = session.client('ec2', region_name=region_name)
        
        # Get all EBS volumes
        response = ec2_client.describe_volumes()
        volumes = response.get('Volumes', [])
        
        volume_results = []
        
        for volume in volumes:
            volume_id = volume.get('VolumeId', '')
            volume_name = get_volume_name(volume.get('Tags', []))
            volume_display_name = get_volume_display_name(volume_id, volume_name)
            encrypted = volume.get('Encrypted', False)
            size = volume.get('Size', 0)
            volume_type = volume.get('VolumeType', 'unknown')
            state = volume.get('State', 'unknown')
            availability_zone = volume.get('AvailabilityZone', 'unknown')
            kms_key_id = volume.get('KmsKeyId', '')
            
            # Get attachments info
            attachments = volume.get('Attachments', [])
            attached_instances = []
            for attachment in attachments:
                instance_id = attachment.get('InstanceId', '')
                device = attachment.get('Device', '')
                if instance_id:
                    attached_instances.append({
                        'instanceId': instance_id,
                        'device': device,
                        'state': attachment.get('State', 'unknown')
                    })
            
            volume_data = {
                'volumeId': volume_id,
                'volumeName': volume_name,
                'volumeDisplayName': volume_display_name,
                'encrypted': encrypted,
                'region': region_name,
                'availabilityZone': availability_zone,
                'size': size,
                'volumeType': volume_type,
                'state': state,
                'kmsKeyId': kms_key_id,
                'attachedInstances': attached_instances,
                'isAttached': len(attached_instances) > 0
            }
            
            volume_results.append(volume_data)
        
        return volume_results
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        return [{'error': f'Failed to check region {region_name}: {error_code}', 'region': region_name}]
    except Exception as e:
        return [{'error': f'Unexpected error in region {region_name}: {str(e)}', 'region': region_name}]


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


def process_volumes_in_regions(session, regions_to_check):
    """Process EBS volumes across multiple regions"""
    all_volumes = []
    regions_checked = 0
    regions_with_errors = []
    
    for region in regions_to_check:
        try:
            region_volumes = check_ebs_encryption_in_region(session, region)
            
            # Filter out error results and add them to error tracking
            valid_volumes = []
            for vol in region_volumes:
                if 'error' in vol:
                    regions_with_errors.append(f"{region}: {vol['error']}")
                else:
                    valid_volumes.append(vol)
            
            all_volumes.extend(valid_volumes)
            regions_checked += 1
            
        except Exception as e:
            regions_with_errors.append(f"{region}: {str(e)}")
            continue
    
    return all_volumes, regions_checked, regions_with_errors


def calculate_volume_statistics(volumes):
    """Calculate volume encryption statistics"""
    total_volumes = len(volumes)
    encrypted_volumes = len([v for v in volumes if v.get('encrypted', False)])
    unencrypted_volumes = total_volumes - encrypted_volumes
    attached_volumes = len([v for v in volumes if v.get('isAttached', False)])
    unattached_volumes = total_volumes - attached_volumes
    
    return {
        'total_volumes': total_volumes,
        'encrypted_volumes': encrypted_volumes,
        'unencrypted_volumes': unencrypted_volumes,
        'attached_volumes': attached_volumes,
        'unattached_volumes': unattached_volumes
    }


def determine_encryption_status(stats, regions_checked, regions_with_errors):
    """Determine overall encryption status and message"""
    total_volumes = stats['total_volumes']
    unencrypted_volumes = stats['unencrypted_volumes']
    
    if total_volumes == 0:
        status = 'Success'
        message = 'No EBS volumes found in the checked regions.'
    elif unencrypted_volumes == 0:
        status = 'Success'
        message = f'All {total_volumes} EBS volumes are encrypted across {regions_checked} regions.'
    else:
        status = 'Warning'
        message = f'Found {unencrypted_volumes} unencrypted volumes out of {total_volumes} total volumes. Enable encryption for security.'
    
    # Add error information to message if there were region errors
    if regions_with_errors:
        message += f" Note: {len(regions_with_errors)} regions had errors during check."
    
    return status, message


def create_encryption_error_result(error_type, message):
    """Create error result for EBS encryption check"""
    return {
        'status': 'Error',
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'regions_checked': 0,
        'total_volumes': 0,
        'encrypted_volumes': 0,
        'unencrypted_volumes': 0,
        'attached_volumes': 0,
        'unattached_volumes': 0,
        'volumes': [],
        'region_errors': [],
        'error': error_type
    }


def check_ebs_volumes_encryption(profile_name=None, region_name=None):
    """
    Check EBS volume encryption across regions or specific region
    
    Args:
        profile_name: AWS profile name to use (optional)
        region_name: AWS region name (optional, if not provided checks all regions)
        
    Returns:
        dict: Results in JSON format for dashboard compatibility
    """
    try:
        session = boto3.Session(profile_name=profile_name)
        
        # Determine which regions to check
        if region_name:
            regions_to_check = [region_name]
        else:
            regions_to_check = get_all_regions(session)
        
        # Process volumes across regions
        all_volumes, regions_checked, regions_with_errors = process_volumes_in_regions(session, regions_to_check)
        
        # Calculate statistics
        stats = calculate_volume_statistics(all_volumes)
        
        # Determine overall status
        status, message = determine_encryption_status(stats, regions_checked, regions_with_errors)
        
        return {
            'status': status,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'regions_checked': regions_checked,
            'total_volumes': stats['total_volumes'],
            'encrypted_volumes': stats['encrypted_volumes'],
            'unencrypted_volumes': stats['unencrypted_volumes'],
            'attached_volumes': stats['attached_volumes'],
            'unattached_volumes': stats['unattached_volumes'],
            'volumes': all_volumes,
            'region_errors': regions_with_errors
        }
        
    except NoCredentialsError:
        return create_encryption_error_result('NoCredentialsError', 
                                            'AWS credentials not found. Please configure your credentials.')
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        if error_code == 'AccessDenied':
            message = "Access denied. Please check your IAM permissions for EC2."
        else:
            message = f"AWS API error: {e.response.get('Error', {}).get('Message', str(e))}"
        
        return create_encryption_error_result(error_code, message)
    except Exception as e:
        return create_encryption_error_result('UnexpectedError', f'Unexpected error: {str(e)}')


def print_volume_details(volume, index):
    """Print detailed information for an EBS volume"""
    print(f"\n{index}. Volume: {volume['volumeDisplayName']}")
    print(f"   Region: {volume['region']}")
    print(f"   Availability Zone: {volume['availabilityZone']}")
    print(f"   Encrypted: {'✓' if volume['encrypted'] else '✗'}")
    print(f"   Size: {volume['size']} GB")
    print(f"   Type: {volume['volumeType']}")
    print(f"   State: {volume['state']}")
    
    if volume.get('kmsKeyId'):
        print(f"   KMS Key: {volume['kmsKeyId']}")
    
    if volume['attachedInstances']:
        print(f"   Attached to: {len(volume['attachedInstances'])} instance(s)")
        for attachment in volume['attachedInstances']:
            print(f"     - Instance: {attachment['instanceId']} (Device: {attachment['device']})")
    else:
        print("   Status: Unattached")


def print_summary_output(result):
    """Print human-readable summary output"""
    print("\nEBS Volume Encryption Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Regions Checked: {result['regions_checked']}")
    print(f"Total Volumes: {result['total_volumes']}")
    print(f"Encrypted Volumes: {result['encrypted_volumes']}")
    print(f"Unencrypted Volumes: {result['unencrypted_volumes']}")
    print(f"Attached Volumes: {result['attached_volumes']}")
    print(f"Unattached Volumes: {result['unattached_volumes']}")
    
    # Show region errors if any
    if result.get('region_errors'):
        print("\nRegion Errors:")
        for error in result['region_errors']:
            print(f"  - {error}")
    
    volumes = result.get('volumes', [])
    if volumes:
        print("\nVolume Details:")
        
        # Group volumes by encryption status for better readability
        encrypted_vols = [v for v in volumes if v.get('encrypted', False)]
        unencrypted_vols = [v for v in volumes if not v.get('encrypted', False)]
        
        if unencrypted_vols:
            print(f"\nUnencrypted Volumes ({len(unencrypted_vols)}):")
            for i, volume in enumerate(unencrypted_vols, 1):
                print_volume_details(volume, i)
        
        if encrypted_vols:
            print(f"\nEncrypted Volumes ({len(encrypted_vols)}):")
            for i, volume in enumerate(encrypted_vols, 1):
                print_volume_details(volume, i)
    
    # Summary recommendations
    if result['unencrypted_volumes'] > 0:
        print("\nRecommendations:")
        print("- Enable encryption for unencrypted volumes")
        print("- Consider enabling EBS encryption by default for the account")
        print("- Use AWS KMS keys for additional security control")


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check EBS volume encryption")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--region', help='AWS region to check (default: all regions)')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_ebs_volumes_encryption(
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
