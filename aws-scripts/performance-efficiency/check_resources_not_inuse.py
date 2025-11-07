#!/usr/bin/env python3
"""
AWS Unused Resources Check Script

This script checks for common AWS resources that are not in use across multiple categories:
- Unused Secrets Manager secrets
- Unattached EBS volumes
- Old EBS snapshots (older than 90 days)
- Unattached Elastic IP addresses
- Unattached NAT gateways
- Application Load Balancers with no targets
- Lambda functions not run in over 60 days

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timedelta, timezone

# Constants
DEFAULT_SNAPSHOT_AGE_DAYS = 90
DEFAULT_LAMBDA_INACTIVE_DAYS = 60
DEFAULT_SECRET_INACTIVE_DAYS = 90

# Resource type constants
RESOURCE_TYPE_SECRETS = 'SecretsManager'
RESOURCE_TYPE_EBS_VOLUME = 'EBS Volume'
RESOURCE_TYPE_EBS_SNAPSHOT = 'EBS Snapshot'
RESOURCE_TYPE_ELASTIC_IP = 'Elastic IP'
RESOURCE_TYPE_NAT_GATEWAY = 'NAT Gateway'
RESOURCE_TYPE_ALB = 'Application Load Balancer'
RESOURCE_TYPE_LAMBDA = 'Lambda Function'


def get_resource_name(tags, resource_id):
    """Extract resource name from tags or use resource ID as fallback"""
    if tags:
        for tag in tags:
            if tag.get('Key', '').lower() == 'name':
                return tag.get('Value', resource_id)
    return resource_id


def check_unused_secrets(session, region_name):
    """Check for unused Secrets Manager secrets"""
    try:
        secrets_client = session.client('secretsmanager', region_name=region_name)
        cloudtrail_client = session.client('cloudtrail', region_name=region_name)
        
        unused_secrets = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=DEFAULT_SECRET_INACTIVE_DAYS)
        
        # List all secrets
        paginator = secrets_client.get_paginator('list_secrets')
        for page in paginator.paginate():
            for secret in page.get('SecretList', []):
                secret_name = secret['Name']
                secret_arn = secret['ARN']
                
                try:
                    # Check CloudTrail for recent GetSecretValue events
                    events = cloudtrail_client.lookup_events(
                        LookupAttributes=[
                            {
                                'AttributeKey': 'EventName',
                                'AttributeValue': 'GetSecretValue'
                            }
                        ],
                        StartTime=cutoff_date,
                        EndTime=datetime.now(timezone.utc)
                    )
                    
                    # Check if this secret was accessed recently
                    secret_accessed = False
                    for event in events.get('Events', []):
                        if secret_arn in str(event.get('CloudTrailEvent', '')):
                            secret_accessed = True
                            break
                    
                    if not secret_accessed:
                        unused_secrets.append({
                            'resourceType': RESOURCE_TYPE_SECRETS,
                            'resourceName': secret_name,
                            'resourceId': secret_arn,
                            'region': region_name,
                            'lastModified': secret.get('LastChangedDate', 'N/A').isoformat() if secret.get('LastChangedDate') else 'N/A',
                            'reason': f'No access recorded in last {DEFAULT_SECRET_INACTIVE_DAYS} days'
                        })
                        
                except ClientError:
                    # If CloudTrail access fails, skip this secret
                    continue
                    
        return unused_secrets
        
    except ClientError:
        return []
    except Exception:
        return []


def check_unattached_ebs_volumes(session, region_name):
    """Check for unattached EBS volumes"""
    try:
        ec2_client = session.client('ec2', region_name=region_name)
        
        unused_volumes = []
        
        # Get all EBS volumes
        paginator = ec2_client.get_paginator('describe_volumes')
        for page in paginator.paginate():
            for volume in page.get('Volumes', []):
                # Check if volume is unattached
                if volume['State'] == 'available':  # available means unattached
                    volume_name = get_resource_name(volume.get('Tags', []), volume['VolumeId'])
                    
                    unused_volumes.append({
                        'resourceType': RESOURCE_TYPE_EBS_VOLUME,
                        'resourceName': volume_name,
                        'resourceId': volume['VolumeId'],
                        'region': region_name,
                        'size': f"{volume['Size']} GB",
                        'volumeType': volume['VolumeType'],
                        'createTime': volume['CreateTime'].isoformat(),
                        'reason': 'Volume is not attached to any instance'
                    })
                    
        return unused_volumes
        
    except ClientError:
        return []
    except Exception:
        return []


def check_old_ebs_snapshots(session, region_name):
    """Check for old EBS snapshots"""
    try:
        ec2_client = session.client('ec2', region_name=region_name)
        
        old_snapshots = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=DEFAULT_SNAPSHOT_AGE_DAYS)
        
        # Get snapshots owned by this account
        paginator = ec2_client.get_paginator('describe_snapshots')
        for page in paginator.paginate(OwnerIds=['self']):
            for snapshot in page.get('Snapshots', []):
                if snapshot['StartTime'] < cutoff_date:
                    snapshot_name = get_resource_name(snapshot.get('Tags', []), snapshot['SnapshotId'])
                    
                    old_snapshots.append({
                        'resourceType': RESOURCE_TYPE_EBS_SNAPSHOT,
                        'resourceName': snapshot_name,
                        'resourceId': snapshot['SnapshotId'],
                        'region': region_name,
                        'description': snapshot.get('Description', ''),
                        'volumeSize': f"{snapshot['VolumeSize']} GB",
                        'startTime': snapshot['StartTime'].isoformat(),
                        'ageInDays': (datetime.now(timezone.utc) - snapshot['StartTime']).days,
                        'reason': f'Snapshot is older than {DEFAULT_SNAPSHOT_AGE_DAYS} days'
                    })
                    
        return old_snapshots
        
    except ClientError:
        return []
    except Exception:
        return []


def check_unattached_elastic_ips(session, region_name):
    """Check for unattached Elastic IP addresses"""
    try:
        ec2_client = session.client('ec2', region_name=region_name)
        
        unused_eips = []
        
        # Get all Elastic IPs
        response = ec2_client.describe_addresses()
        for address in response.get('Addresses', []):
            # Check if EIP is not associated with any instance or network interface
            if 'InstanceId' not in address and 'NetworkInterfaceId' not in address:
                eip_name = get_resource_name(address.get('Tags', []), address.get('AllocationId', address.get('PublicIp', 'Unknown')))
                
                unused_eips.append({
                    'resourceType': RESOURCE_TYPE_ELASTIC_IP,
                    'resourceName': eip_name,
                    'resourceId': address.get('AllocationId', 'Classic'),
                    'region': region_name,
                    'publicIp': address['PublicIp'],
                    'domain': address.get('Domain', 'classic'),
                    'reason': 'Elastic IP is not associated with any resource'
                })
                
        return unused_eips
        
    except ClientError:
        return []
    except Exception:
        return []


def check_unattached_nat_gateways(session, region_name):
    """Check for NAT gateways that might be unused"""
    try:
        ec2_client = session.client('ec2', region_name=region_name)
        
        unused_nat_gateways = []
        
        # Get all NAT gateways
        paginator = ec2_client.get_paginator('describe_nat_gateways')
        for page in paginator.paginate():
            for nat_gateway in page.get('NatGateways', []):
                if nat_gateway['State'] == 'available':
                    nat_id = nat_gateway['NatGatewayId']
                    nat_name = get_resource_name(nat_gateway.get('Tags', []), nat_id)
                    
                    # Check if NAT gateway is referenced in route tables
                    route_tables = ec2_client.describe_route_tables()
                    is_used = False
                    
                    for route_table in route_tables.get('RouteTables', []):
                        for route in route_table.get('Routes', []):
                            if route.get('NatGatewayId') == nat_id:
                                is_used = True
                                break
                        if is_used:
                            break
                    
                    if not is_used:
                        unused_nat_gateways.append({
                            'resourceType': RESOURCE_TYPE_NAT_GATEWAY,
                            'resourceName': nat_name,
                            'resourceId': nat_id,
                            'region': region_name,
                            'subnetId': nat_gateway['SubnetId'],
                            'vpcId': nat_gateway['VpcId'],
                            'state': nat_gateway['State'],
                            'createTime': nat_gateway['CreateTime'].isoformat(),
                            'reason': 'NAT Gateway is not referenced in any route table'
                        })
                        
        return unused_nat_gateways
        
    except ClientError:
        return []
    except Exception:
        return []


def check_albs_with_no_targets(session, region_name):
    """Check for Application Load Balancers with no healthy targets"""
    try:
        elbv2_client = session.client('elbv2', region_name=region_name)
        
        unused_albs = []
        
        # Get all Application Load Balancers
        paginator = elbv2_client.get_paginator('describe_load_balancers')
        for page in paginator.paginate():
            for alb in page.get('LoadBalancers', []):
                if alb['Type'] == 'application':
                    alb_arn = alb['LoadBalancerArn']
                    alb_name = alb['LoadBalancerName']
                    
                    # Get target groups for this ALB
                    target_groups = elbv2_client.describe_target_groups(
                        LoadBalancerArn=alb_arn
                    )
                    
                    has_healthy_targets = False
                    total_targets = 0
                    
                    for tg in target_groups.get('TargetGroups', []):
                        tg_arn = tg['TargetGroupArn']
                        
                        # Check target health
                        targets = elbv2_client.describe_target_health(
                            TargetGroupArn=tg_arn
                        )
                        
                        for target in targets.get('TargetHealthDescriptions', []):
                            total_targets += 1
                            if target['TargetHealth']['State'] == 'healthy':
                                has_healthy_targets = True
                                break
                        
                        if has_healthy_targets:
                            break
                    
                    if not has_healthy_targets:
                        unused_albs.append({
                            'resourceType': RESOURCE_TYPE_ALB,
                            'resourceName': alb_name,
                            'resourceId': alb_arn,
                            'region': region_name,
                            'dnsName': alb['DNSName'],
                            'scheme': alb['Scheme'],
                            'state': alb['State']['Code'],
                            'totalTargets': total_targets,
                            'createTime': alb['CreatedTime'].isoformat(),
                            'reason': 'Load balancer has no healthy targets'
                        })
                        
        return unused_albs
        
    except ClientError:
        return []
    except Exception:
        return []


def check_inactive_lambda_functions(session, region_name):
    """Check for Lambda functions not invoked in the last 60 days"""
    try:
        lambda_client = session.client('lambda', region_name=region_name)
        cloudwatch_client = session.client('cloudwatch', region_name=region_name)
        
        inactive_lambdas = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=DEFAULT_LAMBDA_INACTIVE_DAYS)
        
        # Get all Lambda functions
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for function in page.get('Functions', []):
                function_name = function['FunctionName']
                
                try:
                    # Check CloudWatch metrics for invocations
                    response = cloudwatch_client.get_metric_statistics(
                        Namespace='AWS/Lambda',
                        MetricName='Invocations',
                        Dimensions=[
                            {
                                'Name': 'FunctionName',
                                'Value': function_name
                            }
                        ],
                        StartTime=cutoff_date,
                        EndTime=datetime.now(timezone.utc),
                        Period=86400,  # 1 day
                        Statistics=['Sum']
                    )
                    
                    # Check if there were any invocations
                    datapoints = response.get('Datapoints', [])
                    total_invocations = sum(point['Sum'] for point in datapoints)
                    
                    if total_invocations == 0:
                        # Get function tags for name
                        try:
                            tags_response = lambda_client.list_tags(Resource=function['FunctionArn'])
                            tags = [{'Key': k, 'Value': v} for k, v in tags_response.get('Tags', {}).items()]
                            function_display_name = get_resource_name(tags, function_name)
                        except Exception:
                            function_display_name = function_name
                        
                        inactive_lambdas.append({
                            'resourceType': RESOURCE_TYPE_LAMBDA,
                            'resourceName': function_display_name,
                            'resourceId': function['FunctionArn'],
                            'region': region_name,
                            'runtime': function.get('Runtime', 'Unknown'),
                            'lastModified': function['LastModified'],
                            'codeSize': function['CodeSize'],
                            'reason': f'Function has not been invoked in the last {DEFAULT_LAMBDA_INACTIVE_DAYS} days'
                        })
                        
                except ClientError:
                    # If we can't get metrics, skip this function
                    continue
                    
        return inactive_lambdas
        
    except ClientError:
        return []
    except Exception:
        return []


def check_region_unused_resources(session, region_name):
    """Check for unused resources in a specific region"""
    unused_resources = []
    
    # Check each resource type
    unused_resources.extend(check_unused_secrets(session, region_name))
    unused_resources.extend(check_unattached_ebs_volumes(session, region_name))
    unused_resources.extend(check_old_ebs_snapshots(session, region_name))
    unused_resources.extend(check_unattached_elastic_ips(session, region_name))
    unused_resources.extend(check_unattached_nat_gateways(session, region_name))
    unused_resources.extend(check_albs_with_no_targets(session, region_name))
    unused_resources.extend(check_inactive_lambda_functions(session, region_name))
    
    return unused_resources


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


def create_success_response(all_unused_resources, regions_checked):
    """Create success response structure"""
    total_resources = len(all_unused_resources)
    
    # Group resources by type
    resource_counts = {}
    for resource in all_unused_resources:
        resource_type = resource['resourceType']
        resource_counts[resource_type] = resource_counts.get(resource_type, 0) + 1
    
    if total_resources == 0:
        message = f"No unused resources found across {regions_checked} regions."
    else:
        type_summary = [f"{count} {res_type}" for res_type, count in resource_counts.items()]
        message = f"Found {total_resources} unused resources across {regions_checked} regions: {', '.join(type_summary)}."
    
    # Generate recommendations
    recommendations = []
    if resource_counts.get(RESOURCE_TYPE_EBS_VOLUME, 0) > 0:
        recommendations.append("Consider deleting unattached EBS volumes to reduce storage costs")
    if resource_counts.get(RESOURCE_TYPE_EBS_SNAPSHOT, 0) > 0:
        recommendations.append("Review and delete old EBS snapshots that are no longer needed")
    if resource_counts.get(RESOURCE_TYPE_ELASTIC_IP, 0) > 0:
        recommendations.append("Release unattached Elastic IPs to avoid charges")
    if resource_counts.get(RESOURCE_TYPE_NAT_GATEWAY, 0) > 0:
        recommendations.append("Remove unused NAT Gateways to reduce network costs")
    if resource_counts.get(RESOURCE_TYPE_ALB, 0) > 0:
        recommendations.append("Remove ALBs with no healthy targets to reduce costs")
    if resource_counts.get(RESOURCE_TYPE_LAMBDA, 0) > 0:
        recommendations.append("Consider archiving or deleting inactive Lambda functions")
    if resource_counts.get(RESOURCE_TYPE_SECRETS, 0) > 0:
        recommendations.append("Review unused secrets and delete those no longer needed")
    
    return {
        'status': 'Success',
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'total_unused_resources': str(total_resources),
        'regions_checked': str(regions_checked),
        'resource_type_counts': resource_counts,
        'details': {
            'unused_resources': all_unused_resources,
            'thresholds': {
                'snapshot_age_days': DEFAULT_SNAPSHOT_AGE_DAYS,
                'lambda_inactive_days': DEFAULT_LAMBDA_INACTIVE_DAYS,
                'secret_inactive_days': DEFAULT_SECRET_INACTIVE_DAYS
            },
            'recommendations': recommendations
        }
    }


def check_unused_resources(profile_name=None, region_name=None):
    """
    Check for unused AWS resources across all regions or specific region
    
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
        
        all_unused_resources = []
        regions_to_check = []
        
        # Determine which regions to check
        if region_name:
            regions_to_check = [region_name]
        else:
            regions_to_check = get_all_regions(session)
        
        # Check each region
        for region in regions_to_check:
            try:
                unused_resources = check_region_unused_resources(session, region)
                all_unused_resources.extend(unused_resources)
            except Exception:
                # Continue with other regions if one fails
                continue
        
        regions_checked = len(regions_to_check)
        
        if len(all_unused_resources) == 0:
            region_text = f"region {region_name}" if region_name else f"{regions_checked} regions"
            return {
                'status': 'Success',
                'message': f'No unused resources found in the specified {region_text}.',
                'timestamp': datetime.now().isoformat(),
                'total_unused_resources': '0',
                'regions_checked': str(regions_checked),
                'resource_type_counts': {},
                'details': {
                    'unused_resources': [],
                    'thresholds': {
                        'snapshot_age_days': DEFAULT_SNAPSHOT_AGE_DAYS,
                        'lambda_inactive_days': DEFAULT_LAMBDA_INACTIVE_DAYS,
                        'secret_inactive_days': DEFAULT_SECRET_INACTIVE_DAYS
                    },
                    'recommendations': []
                }
            }
        
        # Generate result
        return create_success_response(all_unused_resources, regions_checked)
        
    except NoCredentialsError:
        return {
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'timestamp': datetime.now().isoformat(),
            'total_unused_resources': '0',
            'regions_checked': '0',
            'resource_type_counts': {},
            'details': {
                'error_type': 'NoCredentialsError',
                'error_message': 'AWS credentials not found',
                'unused_resources': [],
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
            'total_unused_resources': '0',
            'regions_checked': '0',
            'resource_type_counts': {},
            'details': {
                'error_type': error_code,
                'error_message': error_message,
                'unused_resources': [],
                'recommendations': []
            }
        }
    
    except Exception as e:
        return {
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'total_unused_resources': '0',
            'regions_checked': '0',
            'resource_type_counts': {},
            'details': {
                'error_type': 'UnexpectedError',
                'error_message': str(e),
                'unused_resources': [],
                'recommendations': []
            }
        }


def print_resource_details(resource, index):
    """Print detailed information for a single unused resource"""
    print(f"  {index}. {resource['resourceName']} ({resource['resourceType']})")
    print(f"     Resource ID: {resource['resourceId']}")
    print(f"     Region: {resource['region']}")
    print(f"     Reason: {resource['reason']}")
    
    # Print resource-specific details
    if resource['resourceType'] == RESOURCE_TYPE_EBS_VOLUME:
        print(f"     Size: {resource['size']}")
        print(f"     Volume Type: {resource['volumeType']}")
        print(f"     Created: {resource['createTime']}")
    elif resource['resourceType'] == RESOURCE_TYPE_EBS_SNAPSHOT:
        print(f"     Volume Size: {resource['volumeSize']}")
        print(f"     Age: {resource['ageInDays']} days")
        print(f"     Description: {resource['description']}")
    elif resource['resourceType'] == RESOURCE_TYPE_ELASTIC_IP:
        print(f"     Public IP: {resource['publicIp']}")
        print(f"     Domain: {resource['domain']}")
    elif resource['resourceType'] == RESOURCE_TYPE_NAT_GATEWAY:
        print(f"     State: {resource['state']}")
        print(f"     VPC ID: {resource['vpcId']}")
        print(f"     Subnet ID: {resource['subnetId']}")
    elif resource['resourceType'] == RESOURCE_TYPE_ALB:
        print(f"     DNS Name: {resource['dnsName']}")
        print(f"     State: {resource['state']}")
        print(f"     Total Targets: {resource['totalTargets']}")
    elif resource['resourceType'] == RESOURCE_TYPE_LAMBDA:
        print(f"     Runtime: {resource['runtime']}")
        print(f"     Code Size: {resource['codeSize']} bytes")
        print(f"     Last Modified: {resource['lastModified']}")
    elif resource['resourceType'] == RESOURCE_TYPE_SECRETS:
        print(f"     Last Modified: {resource['lastModified']}")
    
    print()


def print_summary_output(result):
    """Print summary output for unused resources"""
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Unused Resources: {result['total_unused_resources']}")
    print(f"Regions Checked: {result['regions_checked']}")
    
    if result['resource_type_counts']:
        print("\nResource Type Breakdown:")
        for resource_type, count in result['resource_type_counts'].items():
            print(f"  - {resource_type}: {count}")
    
    if result['details']['unused_resources']:
        print("\nThresholds:")
        thresholds = result['details']['thresholds']
        print(f"  - EBS Snapshot Age: {thresholds['snapshot_age_days']} days")
        print(f"  - Lambda Inactive Period: {thresholds['lambda_inactive_days']} days")
        print(f"  - Secrets Inactive Period: {thresholds['secret_inactive_days']} days")
        
        print("\nUnused Resources Details:")
        for i, resource in enumerate(result['details']['unused_resources'], 1):
            print_resource_details(resource, i)
    
    if result['details']['recommendations']:
        print("Recommendations:")
        for recommendation in result['details']['recommendations']:
            print(f"  - {recommendation}")


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check for unused AWS resources')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--region', help='AWS region name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_unused_resources(
        profile_name=args.profile,
        region_name=args.region
    )
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        print_summary_output(result)


if __name__ == "__main__":
    main()
