#!/usr/bin/env python3
"""
EC2 Instance Metadata Service (IMDS) v2 Checker

Script to check if EC2 instances have IMDSv2 set to required.
IMDSv2 provides additional security for instance metadata access.
"""

import boto3
import json
import sys
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime


def get_instance_name(tags):
    """Extract instance name from tags or return None if not found"""
    if tags:
        for tag in tags:
            if tag.get('Key', '').lower() == 'name':
                name = tag.get('Value', '').strip()
                return name if name else None
    return None


def get_instance_display_name(instance_id, instance_name):
    """Get display name for instance - show name and ID if name exists, just ID if not"""
    if instance_name:
        return f"{instance_name} ({instance_id})"
    else:
        return instance_id


def check_ec2_imds_in_region(session, region_name):
    """
    Check EC2 instances IMDS configuration in a specific region
    
    Args:
        session: boto3 session
        region_name: AWS region name
        
    Returns:
        list: List of instance IMDS configuration details
    """
    try:
        ec2_client = session.client('ec2', region_name=region_name)
        
        # Get all EC2 instances
        response = ec2_client.describe_instances()
        instances = []
        
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instances.append(instance)
        
        instance_results = []
        
        for instance in instances:
            instance_id = instance.get('InstanceId', '')
            instance_name = get_instance_name(instance.get('Tags', []))
            instance_display_name = get_instance_display_name(instance_id, instance_name)
            instance_type = instance.get('InstanceType', 'unknown')
            instance_state = instance.get('State', {}).get('Name', 'unknown')
            availability_zone = instance.get('Placement', {}).get('AvailabilityZone', 'unknown')
            
            # Get IMDS configuration
            metadata_options = instance.get('MetadataOptions', {})
            http_tokens = metadata_options.get('HttpTokens', 'optional')  # optional or required
            http_put_response_hop_limit = metadata_options.get('HttpPutResponseHopLimit', 1)
            http_endpoint = metadata_options.get('HttpEndpoint', 'enabled')  # enabled or disabled
            instance_metadata_tags = metadata_options.get('InstanceMetadataTags', 'disabled')
            
            # Determine IMDS version and security status
            imdsv2_required = http_tokens == 'required'
            imds_enabled = http_endpoint == 'enabled'
            
            if not imds_enabled:
                imds_status = 'disabled'
                imds_version = 'disabled'
            elif imdsv2_required:
                imds_status = 'enabled'
                imds_version = 'v2 (required)'
            else:
                imds_status = 'enabled'
                imds_version = 'v1/v2 (optional)'
            
            instance_data = {
                'instanceId': instance_id,
                'instanceName': instance_name,
                'instanceDisplayName': instance_display_name,
                'instanceType': instance_type,
                'instanceState': instance_state,
                'region': region_name,
                'availabilityZone': availability_zone,
                'imdsStatus': imds_status,
                'imdsVersion': imds_version,
                'imdsv2Required': imdsv2_required,
                'imdsEnabled': imds_enabled,
                'httpTokens': http_tokens,
                'httpEndpoint': http_endpoint,
                'httpPutResponseHopLimit': http_put_response_hop_limit,
                'instanceMetadataTags': instance_metadata_tags
            }
            
            instance_results.append(instance_data)
        
        return instance_results
        
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


def process_instances_in_regions(session, regions_to_check):
    """Process EC2 instances across multiple regions"""
    all_instances = []
    regions_checked = 0
    regions_with_errors = []
    
    for region in regions_to_check:
        try:
            region_instances = check_ec2_imds_in_region(session, region)
            
            # Filter out error results and add them to error tracking
            valid_instances = []
            for inst in region_instances:
                if 'error' in inst:
                    regions_with_errors.append(f"{region}: {inst['error']}")
                else:
                    valid_instances.append(inst)
            
            all_instances.extend(valid_instances)
            regions_checked += 1
            
        except Exception as e:
            regions_with_errors.append(f"{region}: {str(e)}")
            continue
    
    return all_instances, regions_checked, regions_with_errors


def calculate_imds_statistics(instances):
    """Calculate IMDS configuration statistics"""
    total_instances = len(instances)
    running_instances = len([i for i in instances if i.get('instanceState') == 'running'])
    imdsv2_required_instances = len([i for i in instances if i.get('imdsv2Required', False)])
    imdsv2_optional_instances = len([i for i in instances if i.get('imdsEnabled', False) and not i.get('imdsv2Required', False)])
    imds_disabled_instances = len([i for i in instances if not i.get('imdsEnabled', False)])
    
    return {
        'total_instances': total_instances,
        'running_instances': running_instances,
        'imdsv2_required_instances': imdsv2_required_instances,
        'imdsv2_optional_instances': imdsv2_optional_instances,
        'imds_disabled_instances': imds_disabled_instances
    }


def determine_imds_status(stats, regions_with_errors):
    """Determine overall IMDS security status and message"""
    total_instances = stats['total_instances']
    running_instances = stats['running_instances']
    imdsv2_required = stats['imdsv2_required_instances']
    imdsv2_optional = stats['imdsv2_optional_instances']
    imds_disabled = stats['imds_disabled_instances']
    
    if total_instances == 0:
        status = 'Success'
        message = 'No EC2 instances found in the checked regions.'
    elif imdsv2_optional == 0 and running_instances > 0:
        status = 'Success'
        message = f'All {running_instances} running instances have IMDSv2 required or IMDS disabled for enhanced security.'
    elif imdsv2_optional > 0:
        status = 'Warning'
        message = f'Found {imdsv2_optional} instances with IMDSv1 enabled (optional token). Configure IMDSv2 required for better security.'
    else:
        status = 'Success'
        message = f'All instances properly configured. {imdsv2_required} with IMDSv2 required, {imds_disabled} with IMDS disabled.'
    
    # Add error information to message if there were region errors
    if regions_with_errors:
        message += f" Note: {len(regions_with_errors)} regions had errors during check."
    
    return status, message


def create_imds_error_result(error_type, message):
    """Create error result for IMDS check"""
    return {
        'status': 'Error',
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'regions_checked': 0,
        'total_instances': 0,
        'running_instances': 0,
        'imdsv2_required_instances': 0,
        'imdsv2_optional_instances': 0,
        'imds_disabled_instances': 0,
        'instances': [],
        'region_errors': [],
        'error': error_type
    }


def check_ec2_metadata_v1(profile_name=None, region_name=None):
    """
    Check EC2 instances IMDS configuration across regions or specific region
    
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
        
        # Process instances across regions
        all_instances, regions_checked, regions_with_errors = process_instances_in_regions(session, regions_to_check)
        
        # Calculate statistics
        stats = calculate_imds_statistics(all_instances)
        
        # Determine overall status
        status, message = determine_imds_status(stats, regions_with_errors)
        
        return {
            'status': status,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'regions_checked': regions_checked,
            'total_instances': stats['total_instances'],
            'running_instances': stats['running_instances'],
            'imdsv2_required_instances': stats['imdsv2_required_instances'],
            'imdsv2_optional_instances': stats['imdsv2_optional_instances'],
            'imds_disabled_instances': stats['imds_disabled_instances'],
            'instances': all_instances,
            'region_errors': regions_with_errors
        }
        
    except NoCredentialsError:
        return create_imds_error_result('NoCredentialsError', 
                                       'AWS credentials not found. Please configure your credentials.')
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        if error_code == 'AccessDenied':
            message = "Access denied. Please check your IAM permissions for EC2."
        else:
            message = f"AWS API error: {e.response.get('Error', {}).get('Message', str(e))}"
        
        return create_imds_error_result(error_code, message)
    except Exception as e:
        return create_imds_error_result('UnexpectedError', f'Unexpected error: {str(e)}')


def print_instance_details(instance, index):
    """Print detailed information for an EC2 instance"""
    print(f"\n{index}. Instance: {instance['instanceDisplayName']}")
    print(f"   Region: {instance['region']}")
    print(f"   Availability Zone: {instance['availabilityZone']}")
    print(f"   Instance Type: {instance['instanceType']}")
    print(f"   State: {instance['instanceState']}")
    print(f"   IMDS Status: {instance['imdsStatus']}")
    print(f"   IMDS Version: {instance['imdsVersion']}")
    print(f"   HTTP Tokens: {instance['httpTokens']}")
    print(f"   HTTP Endpoint: {instance['httpEndpoint']}")
    
    if instance.get('httpPutResponseHopLimit'):
        print(f"   Hop Limit: {instance['httpPutResponseHopLimit']}")
    
    if instance.get('instanceMetadataTags') == 'enabled':
        print("   Instance Metadata Tags: Enabled")


def print_basic_summary(result):
    """Print basic summary information"""
    print("\nEC2 Instance Metadata Service (IMDS) Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Regions Checked: {result['regions_checked']}")
    print(f"Total Instances: {result['total_instances']}")
    print(f"Running Instances: {result['running_instances']}")
    print(f"IMDSv2 Required: {result['imdsv2_required_instances']}")
    print(f"IMDSv2 Optional (Vulnerable): {result['imdsv2_optional_instances']}")
    print(f"IMDS Disabled: {result['imds_disabled_instances']}")

def print_region_errors(result):
    """Print region errors if any"""
    if result.get('region_errors'):
        print("\nRegion Errors:")
        for error in result['region_errors']:
            print(f"  - {error}")

def print_instance_groups(instances):
    """Print grouped instance details"""
    vulnerable_instances = [i for i in instances if i.get('imdsEnabled', False) and not i.get('imdsv2Required', False)]
    secure_instances = [i for i in instances if i.get('imdsv2Required', False)]
    disabled_instances = [i for i in instances if not i.get('imdsEnabled', False)]
    
    if vulnerable_instances:
        print(f"\nInstances with IMDSv1 Enabled (Vulnerable) ({len(vulnerable_instances)}):")
        for i, instance in enumerate(vulnerable_instances, 1):
            print_instance_details(instance, i)
    
    if secure_instances:
        print(f"\nInstances with IMDSv2 Required (Secure) ({len(secure_instances)}):")
        for i, instance in enumerate(secure_instances, 1):
            print_instance_details(instance, i)
    
    if disabled_instances:
        print(f"\nInstances with IMDS Disabled ({len(disabled_instances)}):")
        for i, instance in enumerate(disabled_instances, 1):
            print_instance_details(instance, i)

def print_recommendations(result):
    """Print security recommendations"""
    if result['imdsv2_optional_instances'] > 0:
        print("\nRecommendations:")
        print("- Configure IMDSv2 required on instances with optional tokens")
        print("- Use AWS CLI: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required")
        print("- Consider disabling IMDS entirely if not needed")
        print("- Update instance launch templates to enforce IMDSv2")

def print_summary_output(result):
    """Print human-readable summary output"""
    print_basic_summary(result)
    print_region_errors(result)
    
    instances = result.get('instances', [])
    if instances:
        print("\nInstance Details:")
        print_instance_groups(instances)
    
    print_recommendations(result)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check EC2 Instance Metadata Service (IMDS) configuration")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--region', help='AWS region to check (default: all regions)')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_ec2_metadata_v1(
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
