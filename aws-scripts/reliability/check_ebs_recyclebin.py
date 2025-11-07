#!/usr/bin/env python3
"""
EBS Recycle Bin Configuration Check Script

This script checks if EBS Recycle Bin is properly configured by examining:
- Recycle Bin retention rules for EBS snapshots
- Recycle Bin retention rules for AMIs

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime

# Constants
RESOURCE_TYPE_EBS_SNAPSHOT = "EBS_SNAPSHOT"
RESOURCE_TYPE_EC2_IMAGE = "EC2_IMAGE"


def get_resource_name(tags, resource_id):
    """Extract resource name from tags or use resource ID as fallback"""
    if tags:
        for tag in tags:
            if tag.get('Key', '').lower() == 'name':
                return tag.get('Value', resource_id)
    return resource_id



def get_rule_details_and_tags(rbin_client, rule_arn):
    """Get detailed rule information and tags"""
    try:
        # Get detailed rule information
        rule_details = rbin_client.get_rule(Identifier=rule_arn)
        rule_info = rule_details.get('Rule', {})
        
        # Get tags for this rule
        try:
            tags_response = rbin_client.list_tags_for_resource(ResourceArn=rule_arn)
            tags = tags_response.get('Tags', [])
            display_name = get_resource_name(tags, rule_arn.split('/')[-1])
        except Exception:
            display_name = rule_arn.split('/')[-1]
            tags = []
        
        return rule_info, display_name, tags, None
    except Exception as e:
        return None, rule_arn.split('/')[-1], [], str(e)


def create_rule_from_list_response(rule, resource_type, region_name, display_name, error):
    """Create rule data from list response and additional details"""
    rule_arn = rule.get('Identifier', '')
    rule_description = rule.get('Description', '')
    
    # Extract retention period directly from list response
    retention_period = rule.get('RetentionPeriod', {})
    retention_value = retention_period.get('RetentionPeriodValue', 0)
    retention_unit = retention_period.get('RetentionPeriodUnit', 'DAYS')
    
    # Create simplified rule info
    rule_data = {
        'ruleArn': rule_arn,
        'ruleId': rule_arn.split('/')[-1] if '/' in rule_arn else rule_arn,
        'displayName': display_name if display_name else rule_arn,
        'description': rule_description,
        'resourceType': resource_type,
        'region': region_name,
        'retentionValue': retention_value,
        'retentionUnit': retention_unit
    }
    
    if error:
        rule_data['error'] = f'Failed to get additional rule details: {error}'
    
    return rule_data

def process_rule_for_resource_type(rbin_client, resource_type, region_name):
    """Process rules for a specific resource type"""
    rules = []
    
    try:
        # List retention rules for this resource type
        paginator = rbin_client.get_paginator('list_rules')
        for page in paginator.paginate(ResourceType=resource_type):
            for rule in page.get('Rules', []):
                try:
                    rule_arn = rule.get('Identifier', '')
                    
                    # Get detailed rule information and tags (for additional metadata)
                    _, display_name, _, error = get_rule_details_and_tags(rbin_client, rule_arn)
                    
                    # Create rule data
                    rule_data = create_rule_from_list_response(
                        rule, resource_type, region_name, display_name, error
                    )
                    
                    rules.append(rule_data)
                    
                except Exception:
                    # Skip individual rule that can't be processed
                    continue
                    
    except ClientError as e:
        # If this resource type is not supported in this region, return empty list
        if e.response['Error']['Code'] in ['UnsupportedOperation', 'InvalidParameterValue']:
            return []
        else:
            raise e
    
    return rules

def get_recycle_bin_rules(session, region_name):
    """Get all recycle bin retention rules in a region"""
    try:
        rbin_client = session.client('rbin', region_name=region_name)
        
        all_rules = []
        
        # List retention rules for each resource type separately - EBS snapshots first, then AMIs
        resource_types = [RESOURCE_TYPE_EBS_SNAPSHOT, RESOURCE_TYPE_EC2_IMAGE]
        
        for resource_type in resource_types:
            rules = process_rule_for_resource_type(rbin_client, resource_type, region_name)
            all_rules.extend(rules)
        
        return all_rules
        
    except ClientError as e:
        return {'error': f'Recycle Bin error: {e.response["Error"]["Code"]}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


def check_region_recycle_bin(session, region_name):
    """Check recycle bin configuration in a specific region"""
    region_results = {
        'region': region_name,
        'retention_rules': [],
        'ebs_snapshot_rules': [],
        'ami_rules': [],
        'errors': []
    }
    
    # Get all retention rules
    rules_result = get_recycle_bin_rules(session, region_name)
    if isinstance(rules_result, dict) and 'error' in rules_result:
        region_results['errors'].append(f"Retention Rules: {rules_result['error']}")
    elif isinstance(rules_result, list):
        region_results['retention_rules'] = rules_result
        
        # Categorize rules by resource type
        for rule in rules_result:
            if isinstance(rule, dict) and rule.get('resourceType') == RESOURCE_TYPE_EBS_SNAPSHOT:
                region_results['ebs_snapshot_rules'].append(rule)
            elif isinstance(rule, dict) and rule.get('resourceType') == RESOURCE_TYPE_EC2_IMAGE:
                region_results['ami_rules'].append(rule)
    
    return region_results


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


def analyze_rule_stats(rules):
    """Analyze basic statistics for a set of rules"""
    return {
        'count': len(rules),
        'has_rules': len(rules) > 0
    }

def determine_overall_status(ebs_stats, ami_stats):
    """Determine overall status based on rule statistics"""
    has_ebs_recycle_bin = ebs_stats['has_rules']
    has_ami_recycle_bin = ami_stats['has_rules']
    
    if has_ebs_recycle_bin and has_ami_recycle_bin:
        return {
            'status': 'Success',
            'message': f"EBS Recycle Bin is configured for both snapshots and AMIs with {ebs_stats['count']} EBS rules and {ami_stats['count']} AMI rules across regions."
        }
    elif has_ebs_recycle_bin:
        return {
            'status': 'Warning',
            'message': f"EBS Recycle Bin is configured for snapshots ({ebs_stats['count']} rules) but not for AMIs. Consider adding AMI retention rules."
        }
    elif has_ami_recycle_bin:
        return {
            'status': 'Warning',
            'message': f"EBS Recycle Bin is configured for AMIs ({ami_stats['count']} rules) but not for EBS snapshots. Consider adding snapshot retention rules."
        }
    else:
        return {
            'status': 'Warning',
            'message': "EBS Recycle Bin is not configured. Enable retention rules for EBS snapshots and AMIs to prevent accidental data loss."
        }

def analyze_recycle_bin_configuration(all_region_results):
    """Analyze the recycle bin configuration across all regions"""
    all_ebs_rules = []
    all_ami_rules = []
    total_rules = 0
    regions_with_ebs_rules = 0
    regions_with_ami_rules = 0
    
    # Collect all rules from all regions
    for region_result in all_region_results:
        ebs_rules = region_result.get('ebs_snapshot_rules', [])
        ami_rules = region_result.get('ami_rules', [])
        all_rules = region_result.get('retention_rules', [])
        
        total_rules += len(all_rules)
        all_ebs_rules.extend(ebs_rules)
        all_ami_rules.extend(ami_rules)
        
        if ebs_rules:
            regions_with_ebs_rules += 1
        if ami_rules:
            regions_with_ami_rules += 1
    
    # Analyze statistics for each rule type
    ebs_stats = analyze_rule_stats(all_ebs_rules)
    ami_stats = analyze_rule_stats(all_ami_rules)
    
    # Determine overall status
    status_info = determine_overall_status(ebs_stats, ami_stats)
    
    return {
        'status': status_info['status'],
        'message': status_info['message'],
        'analysis': {
            'total_rules': total_rules,
            'total_ebs_snapshot_rules': ebs_stats['count'],
            'total_ami_rules': ami_stats['count'],
            'regions_with_ebs_rules': regions_with_ebs_rules,
            'regions_with_ami_rules': regions_with_ami_rules,
            'has_ebs_recycle_bin': ebs_stats['has_rules'],
            'has_ami_recycle_bin': ami_stats['has_rules'],
            'has_any_recycle_bin': ebs_stats['has_rules'] or ami_stats['has_rules']
        }
    }


def create_error_result(status, message, error_type, error_message):
    """Create error result dictionary"""
    return {
        'status': status,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'regions_checked': '0',
        'total_retention_rules': '0',
        'ebs_recycle_bin_enabled': False,
        'ami_recycle_bin_enabled': False,
        'details': {
            'error_type': error_type,
            'error_message': error_message,
            'region_results': []
        }
    }


def process_regions(session, regions_to_check):
    """Process all regions and collect results"""
    all_region_results = []
    
    for region in regions_to_check:
        try:
            region_result = check_region_recycle_bin(session, region)
            all_region_results.append(region_result)
        except Exception as e:
            # Add error info for this region
            all_region_results.append({
                'region': region,
                'retention_rules': [],
                'ebs_snapshot_rules': [],
                'ami_rules': [],
                'errors': [f'Region check failed: {str(e)}']
            })
    
    return all_region_results


def check_ebs_recyclebin(profile_name=None, region_name=None):
    """
    Check EBS Recycle Bin configuration across all regions or specific region
    
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
        
        # Determine which regions to check
        if region_name:
            regions_to_check = [region_name]
        else:
            regions_to_check = get_all_regions(session)
        
        # Check each region
        all_region_results = process_regions(session, regions_to_check)
        regions_checked = len(regions_to_check)
        
        # Analyze results
        analysis = analyze_recycle_bin_configuration(all_region_results)
        
        return {
            'status': analysis['status'],
            'message': analysis['message'],
            'timestamp': datetime.now().isoformat(),
            'regions_checked': str(regions_checked),
            'total_retention_rules': str(analysis['analysis']['total_rules']),
            'ebs_recycle_bin_enabled': analysis['analysis']['has_ebs_recycle_bin'],
            'ami_recycle_bin_enabled': analysis['analysis']['has_ami_recycle_bin'],
            'details': {
                'region_results': all_region_results,
                'analysis': analysis['analysis'],
                'resource_types': {
                    'ebs_snapshot': RESOURCE_TYPE_EBS_SNAPSHOT,
                    'ami': RESOURCE_TYPE_EC2_IMAGE
                }
            }
        }
        
    except NoCredentialsError:
        return create_error_result(
            'Error',
            'AWS credentials not found. Please configure your credentials.',
            'NoCredentialsError',
            'AWS credentials not found'
        )
    
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        return create_error_result(
            'Error',
            f'AWS API error: {error_message}',
            error_code,
            error_message
        )
    
    except Exception as e:
        return create_error_result(
            'Error',
            f'Unexpected error: {str(e)}',
            'UnexpectedError',
            str(e)
        )


def print_rule_details(rule, index):
    """Print detailed information for a retention rule"""
    print(f"  {index}. {rule['displayName']} ({rule['ruleId']})")
    print(f"     Resource Type: {rule['resourceType']}")
    print(f"     Region: {rule['region']}")
    print(f"     Retention: {rule['retentionValue']} {rule['retentionUnit']}")
    
    if rule['description']:
        print(f"     Description: {rule['description']}")
    
    if rule.get('error'):
        print(f"     Error: {rule['error']}")
    
    print()


def print_region_details(region_result):
    """Print details for a specific region"""
    region = region_result['region']
    ebs_rules = region_result.get('ebs_snapshot_rules', [])
    ami_rules = region_result.get('ami_rules', [])
    all_rules = region_result.get('retention_rules', [])
    errors = region_result.get('errors', [])
    
    print(f"\n  Region: {region}")
    print(f"    Total Rules: {len(all_rules)}")
    print(f"    EBS Snapshot Rules: {len(ebs_rules)}")
    print(f"    AMI Rules: {len(ami_rules)}")
    
    if errors:
        print(f"    Errors: {', '.join(errors)}")
    
    if ebs_rules:
        print("\n    EBS Snapshot Rules:")
        for i, rule in enumerate(ebs_rules, 1):
            print_rule_details(rule, i)
    
    if ami_rules:
        print("\n    AMI Rules:")
        for i, rule in enumerate(ami_rules, 1):
            print_rule_details(rule, i)


def print_summary_output(result):
    """Print summary output for EBS recycle bin check"""
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Regions Checked: {result['regions_checked']}")
    print(f"Total Retention Rules: {result['total_retention_rules']}")
    print(f"EBS Recycle Bin Enabled: {result['ebs_recycle_bin_enabled']}")
    print(f"AMI Recycle Bin Enabled: {result['ami_recycle_bin_enabled']}")
    
    if result['details']['region_results']:
        print("\nResource Types:")
        types = result['details']['resource_types']
        print(f"  - EBS Snapshots: {types['ebs_snapshot']}")
        print(f"  - AMIs: {types['ami']}")
        
        print("\nRegion-by-Region Results:")
        for region_result in result['details']['region_results']:
            print_region_details(region_result)


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check EBS Recycle Bin configuration')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--region', help='AWS region name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_ebs_recyclebin(
        profile_name=args.profile,
        region_name=args.region
    )
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        print_summary_output(result)


if __name__ == "__main__":
    main()
