#!/usr/bin/env python3
"""
Elastic IP (EIP) In Use Check Script

This script checks for Elastic IP addresses that are not attached to any
EC2 instances or NAT gateways across all AWS regions.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime


def check_eip_in_use(profile_name=None):
    """
    Check for unused Elastic IP addresses
    
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
        
        unused_eips = []
        total_eips = 0
        total_unused = 0
        
        # Check each region
        for region in regions:
            try:
                ec2_client = session.client('ec2', region_name=region)
                
                # Get all Elastic IPs in the region
                eips_response = ec2_client.describe_addresses()
                eips = eips_response['Addresses']
                
                for eip in eips:
                    total_eips += 1
                    
                    # Check if EIP is not attached to any instance or NAT gateway
                    instance_id = eip.get('InstanceId')
                    association_id = eip.get('AssociationId')
                    network_interface_id = eip.get('NetworkInterfaceId')
                    
                    # EIP is unused if it has no instance, association, or network interface
                    if not instance_id and not association_id and not network_interface_id:
                        total_unused += 1
                        
                        # Get EIP tags
                        tags = {tag['Key']: tag['Value'] for tag in eip.get('Tags', [])}
                        
                        eip_info = {
                            'allocation_id': eip.get('AllocationId', 'N/A'),
                            'public_ip': eip.get('PublicIp', 'Unknown'),
                            'region': region,
                            'domain': eip.get('Domain', 'Unknown'),
                            'network_border_group': eip.get('NetworkBorderGroup', 'Unknown'),
                            'public_ipv4_pool': eip.get('PublicIpv4Pool', 'Unknown'),
                            'tags': tags,
                            'name': tags.get('Name', 'No Name')
                        }
                        
                        unused_eips.append(eip_info)
                        
            except ClientError as e:
                # Skip regions where we don't have access
                if e.response['Error']['Code'] in ['UnauthorizedOperation', 'AuthFailure']:
                    continue
                else:
                    raise
        
        # Determine overall status
        if total_unused == 0:
            status = 'Optimized'
            message = 'All Elastic IP addresses are in use. No unused EIPs found.'
        else:
            status = 'Action Required'
            message = f'{total_unused} unused Elastic IP address(es) found across all regions.'
        
        # Create structured result
        result = {
            'status': status,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'details': {
                'total_eips': total_eips,
                'total_unused': total_unused,
                'regions_checked': len(regions),
                'unused_eips': unused_eips
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
                'total_eips': 0,
                'total_unused': 0,
                'regions_checked': 0,
                'unused_eips': []
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
                'total_eips': 0,
                'total_unused': 0,
                'regions_checked': 0,
                'unused_eips': []
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
                'total_eips': 0,
                'total_unused': 0,
                'regions_checked': 0,
                'unused_eips': []
            }
        }


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check for unused Elastic IP addresses')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_eip_in_use(args.profile)
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        # Summary output
        print(f"Status: {result['status']}")
        print(f"Message: {result['message']}")
        print(f"Total EIPs: {result['details']['total_eips']}")
        print(f"Unused EIPs: {result['details']['total_unused']}")
        print(f"Regions Checked: {result['details']['regions_checked']}")
        
        if result['details']['unused_eips']:
            print("\nUnused Elastic IPs:")
            for i, eip in enumerate(result['details']['unused_eips'], 1):
                print(f"  {i}. {eip['public_ip']} ({eip['name']}) - {eip['allocation_id']} in {eip['region']}")


if __name__ == "__main__":
    main()
