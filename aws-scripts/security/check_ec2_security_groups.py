#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Security Pillar
Check EC2 Security Groups for Overly Permissive Rules

This script checks if common ports (22, 3389, 1433, 5432, 3306, 8080) are restricted 
from 0.0.0.0/0 on EC2 security groups.

Common Ports Checked:
- 20: FTP Data Transfer
- 21: FTP Command Control
- 22: SSH
- 3389: RDP  
- 1433: SQL Server
- 5432: PostgreSQL
- 3306: MySQL
- 4333: MySQL (Alternative)
- 8080: HTTP Alternative
"""

import boto3
import json
import sys
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError


# Common ports that should not be open to 0.0.0.0/0
# Based on AWS Config restricted-common-ports rule defaults
COMMON_PORTS = [20, 21, 22, 1433, 3306, 3389, 4333, 5432, 8080]


def get_security_group_name(sg):
    """Get security group name, handling cases where name might be missing"""
    return sg.get('GroupName', 'N/A')


def check_ingress_rule_for_open_access(rule):
    """
    Check if an ingress rule allows access from 0.0.0.0/0 on common ports
    
    Args:
        rule: Security group ingress rule
        
    Returns:
        list: List of open ports in this rule, empty if none
    """
    open_ports = []
    
    # Check if rule allows access from 0.0.0.0/0
    has_open_access = False
    for ip_range in rule.get('IpRanges', []):
        if ip_range.get('CidrIp') == '0.0.0.0/0':
            has_open_access = True
            break
    
    if not has_open_access:
        return open_ports
    
    # Check if rule covers any of our common ports
    from_port = rule.get('FromPort')
    to_port = rule.get('ToPort')
    
    # Handle rules without specific ports (protocol -1 or all traffic)
    if from_port is None or to_port is None:
        # If protocol is -1 (all traffic), all ports are open
        if rule.get('IpProtocol') == '-1':
            return COMMON_PORTS.copy()
        return open_ports
    
    # Check each common port against the rule's port range
    for port in COMMON_PORTS:
        if from_port <= port <= to_port:
            open_ports.append(port)
    
    return open_ports


def analyze_security_group(sg):
    """
    Analyze a security group for overly permissive rules
    
    Args:
        sg: Security group object
        
    Returns:
        dict: Analysis result with open ports and details
    """
    result = {
        'group_id': sg['GroupId'],
        'group_name': get_security_group_name(sg),
        'vpc_id': sg.get('VpcId', 'N/A'),
        'open_ports': [],
        'has_open_access': False
    }
    
    # Check all ingress rules
    for rule in sg.get('IpPermissions', []):
        open_ports = check_ingress_rule_for_open_access(rule)
        if open_ports:
            result['open_ports'].extend(open_ports)
            result['has_open_access'] = True
    
    # Remove duplicates and sort
    result['open_ports'] = sorted(set(result['open_ports']))
    
    return result


def check_security_groups_region(ec2_client, region):
    """
    Check security groups in a specific region
    
    Args:
        ec2_client: Boto3 EC2 client
        region: AWS region name
        
    Returns:
        dict: Region check results
    """
    try:
        # Get all security groups
        response = ec2_client.describe_security_groups()
        security_groups = response['SecurityGroups']
        
        vulnerable_groups = []
        total_groups = len(security_groups)
        
        # Analyze each security group
        for sg in security_groups:
            analysis = analyze_security_group(sg)
            if analysis['has_open_access']:
                vulnerable_groups.append(analysis)
        
        return {
            'region': region,
            'total_security_groups': total_groups,
            'vulnerable_groups': vulnerable_groups,
            'vulnerable_count': len(vulnerable_groups),
            'error': None
        }
        
    except ClientError as e:
        error_msg = f"AWS API error in {region}: {str(e)}"
        return {
            'region': region,
            'total_security_groups': 0,
            'vulnerable_groups': [],
            'vulnerable_count': 0,
            'error': error_msg
        }
    except Exception as e:
        error_msg = f"Unexpected error in {region}: {str(e)}"
        return {
            'region': region,
            'total_security_groups': 0,
            'vulnerable_groups': [],
            'vulnerable_count': 0,
            'error': error_msg
        }


def get_aws_regions(ec2_client):
    """Get list of all available AWS regions"""
    try:
        response = ec2_client.describe_regions()
        return [region['RegionName'] for region in response['Regions']]
    except Exception:
        # Fallback to common regions if describe_regions fails
        return [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-central-1', 'ap-south-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
        ]


def determine_security_status(stats, regions_with_errors):
    """Determine overall security status and message"""
    total_groups = stats['total_security_groups']
    vulnerable_groups = stats['vulnerable_security_groups']
    
    if total_groups == 0:
        status = 'Success'
        message = 'No security groups found in the checked regions.'
    elif vulnerable_groups == 0:
        status = 'Success'
        message = f'All {total_groups} security groups have properly restricted access to common ports.'
    else:
        status = 'Warning'
        message = f'Found {vulnerable_groups} security groups with overly permissive rules allowing 0.0.0.0/0 access to common ports.'
    
    # Add error information to message if there were region errors
    if regions_with_errors:
        message += f" Note: {len(regions_with_errors)} regions had errors during check."
    
    return status, message


def setup_aws_session_and_regions(profile_name, region_name):
    """Setup AWS session and determine regions to check"""
    session = boto3.Session(profile_name=profile_name)
    
    if region_name:
        regions_to_check = [region_name]
    else:
        temp_client = session.client('ec2', region_name='us-east-1')
        regions_to_check = get_aws_regions(temp_client)
    
    return session, regions_to_check

def process_regions(session, regions_to_check):
    """Process all regions and collect results"""
    region_results = []
    regions_with_errors = []
    
    for region in regions_to_check:
        try:
            ec2_client = session.client('ec2', region_name=region)
            result = check_security_groups_region(ec2_client, region)
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
                'total_security_groups': 0,
                'vulnerable_groups': [],
                'vulnerable_count': 0,
                'error': error_msg
            })
    
    return region_results, regions_with_errors

def build_final_result(timestamp, region_results, regions_with_errors, regions_to_check):
    """Build the final result structure"""
    # Calculate overall statistics
    stats = {
        'total_security_groups': sum(r['total_security_groups'] for r in region_results),
        'vulnerable_security_groups': sum(r['vulnerable_count'] for r in region_results),
        'regions_checked': len([r for r in region_results if not r['error']]),
        'regions_with_errors': len(regions_with_errors)
    }
    
    # Collect all vulnerable groups
    all_vulnerable_groups = []
    for result in region_results:
        if not result['error']:
            for group in result['vulnerable_groups']:
                group['region'] = result['region']
                all_vulnerable_groups.append(group)
    
    # Determine overall status
    status, message = determine_security_status(stats, regions_with_errors)
    
    # Build final result
    result = {
        'timestamp': timestamp,
        'status': status,
        'message': message,
        'check_type': 'ec2_security_groups',
        'regions_checked': len(regions_to_check),
        'total_security_groups': stats['total_security_groups'],
        'vulnerable_security_groups': stats['vulnerable_security_groups'],
        'security_groups': all_vulnerable_groups,
        'region_results': region_results
    }
    
    # Add error details if any
    if regions_with_errors:
        result['region_errors'] = regions_with_errors
    
    return result

def check_ec2_security_groups(profile_name=None, region_name=None):
    """
    Main function to check EC2 security groups for overly permissive rules
    
    Args:
        profile_name: AWS profile name (optional)
        region_name: Specific region to check (optional, default: all regions)
        
    Returns:
        dict: Complete check results in JSON format
    """
    timestamp = datetime.now(timezone.utc).isoformat() + 'Z'
    
    try:
        # Setup AWS session and regions
        session, regions_to_check = setup_aws_session_and_regions(profile_name, region_name)
        
        # Process all regions
        region_results, regions_with_errors = process_regions(session, regions_to_check)
        
        # Build and return final result
        return build_final_result(timestamp, region_results, regions_with_errors, regions_to_check)
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'check_type': 'ec2_security_groups',
            'regions_checked': 0,
            'total_security_groups': 0,
            'vulnerable_security_groups': 0,
            'security_groups': [],
            'region_results': []
        }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'check_type': 'ec2_security_groups',
            'regions_checked': 0,
            'total_security_groups': 0,
            'vulnerable_security_groups': 0,
            'security_groups': [],
            'region_results': []
        }


def print_group_details(group, index):
    """Print detailed information about a security group"""
    print(f"\n{index}. Security Group Details:")
    print(f"   Group ID: {group['group_id']}")
    print(f"   Group Name: {group['group_name']}")
    print(f"   VPC ID: {group['vpc_id']}")
    print(f"   Region: {group['region']}")
    print(f"   Open Ports: {', '.join(map(str, group['open_ports']))}")


def print_basic_summary(result):
    """Print basic summary information"""
    print("\nEC2 Security Groups Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Regions Checked: {result['regions_checked']}")
    print(f"Total Security Groups: {result['total_security_groups']}")
    print(f"Vulnerable Security Groups: {result['vulnerable_security_groups']}")


def print_region_errors(result):
    """Print region errors if any"""
    if result.get('region_errors'):
        print("\nRegion Errors:")
        for error in result['region_errors']:
            print(f"  - {error['region']}: {error['error']}")


def print_vulnerable_groups(security_groups):
    """Print details of vulnerable security groups"""
    if security_groups:
        print(f"\nVulnerable Security Groups ({len(security_groups)}):")
        for i, group in enumerate(security_groups, 1):
            print_group_details(group, i)


def print_summary_output(result):
    """Print human-readable summary output"""
    print_basic_summary(result)
    print_region_errors(result)
    
    security_groups = result.get('security_groups', [])
    print_vulnerable_groups(security_groups)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check EC2 Security Groups for overly permissive rules")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--region', help='AWS region to check (default: all regions)')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_ec2_security_groups(
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
