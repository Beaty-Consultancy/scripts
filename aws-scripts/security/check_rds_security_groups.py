#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Security Pillar
Check RDS Security Groups for Internet Access

This script checks if RDS instances' security groups are restricting access from the internet (0.0.0.0/0)
on common database ports.

Database Ports Checked:
- 3306: MySQL/MariaDB
- 5432: PostgreSQL
- 1521: Oracle TNS Listener
- 1433: Microsoft SQL Server
- 27017: MongoDB
- 50000: IBM Db2
- 50001: IBM Db2 (SSL)
"""

import boto3
import json
import sys
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError


# Database ports that should not be open to 0.0.0.0/0
DATABASE_PORTS = [3306, 5432, 1521, 1433, 27017, 50000, 50001]


def get_rds_instances(rds_client, region):
    """
    Get all RDS instances in a region
    
    Args:
        rds_client: Boto3 RDS client
        region: AWS region name
        
    Returns:
        list: List of RDS instances
    """
    try:
        instances = []
        paginator = rds_client.get_paginator('describe_db_instances')
        
        for page in paginator.paginate():
            for instance in page['DBInstances']:
                instances.append(instance)
        
        return instances
    except ClientError as e:
        raise ClientError(e.response, e.operation_name) from e
    except Exception as e:
        raise RuntimeError(f"Failed to get RDS instances in {region}: {str(e)}") from e


def get_rds_clusters(rds_client, region):
    """
    Get all RDS Aurora clusters in a region
    
    Args:
        rds_client: Boto3 RDS client
        region: AWS region name
        
    Returns:
        list: List of RDS clusters
    """
    try:
        clusters = []
        paginator = rds_client.get_paginator('describe_db_clusters')
        
        for page in paginator.paginate():
            for cluster in page['DBClusters']:
                clusters.append(cluster)
        
        return clusters
    except ClientError as e:
        raise ClientError(e.response, e.operation_name) from e
    except Exception as e:
        raise RuntimeError(f"Failed to get RDS clusters in {region}: {str(e)}") from e


def get_security_groups(ec2_client, sg_ids):
    """
    Get security group details for given security group IDs
    
    Args:
        ec2_client: Boto3 EC2 client
        sg_ids: List of security group IDs
        
    Returns:
        dict: Security groups indexed by ID
    """
    try:
        if not sg_ids:
            return {}
        
        response = ec2_client.describe_security_groups(GroupIds=sg_ids)
        return {sg['GroupId']: sg for sg in response['SecurityGroups']}
    except ClientError as e:
        # Handle case where some security groups might not exist
        return {}
    except Exception as e:
        raise RuntimeError(f"Failed to get security groups: {str(e)}") from e


def check_ingress_rule_for_database_access(rule):
    """
    Check if an ingress rule allows access from 0.0.0.0/0 on database ports
    
    Args:
        rule: Security group ingress rule
        
    Returns:
        list: List of open database ports in this rule, empty if none
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
    
    # Check if rule covers any database ports
    from_port = rule.get('FromPort')
    to_port = rule.get('ToPort')
    
    # Handle rules without specific ports (protocol -1 or all traffic)
    if from_port is None or to_port is None:
        # If protocol is -1 (all traffic), all ports are open
        if rule.get('IpProtocol') == '-1':
            return DATABASE_PORTS.copy()
        return open_ports
    
    # Check each database port against the rule's port range
    for port in DATABASE_PORTS:
        if from_port <= port <= to_port:
            open_ports.append(port)
    
    return open_ports


def analyze_security_group_for_database_access(sg):
    """
    Analyze a security group for overly permissive database access
    
    Args:
        sg: Security group object
        
    Returns:
        dict: Analysis result with open database ports
    """
    open_ports = []
    
    # Check all ingress rules
    for rule in sg.get('IpPermissions', []):
        rule_open_ports = check_ingress_rule_for_database_access(rule)
        if rule_open_ports:
            open_ports.extend(rule_open_ports)
    
    # Remove duplicates and sort
    open_ports = sorted(set(open_ports))
    
    return {
        'group_id': sg['GroupId'],
        'group_name': sg.get('GroupName', 'N/A'),
        'vpc_id': sg.get('VpcId', 'N/A'),
        'open_database_ports': open_ports,
        'has_open_database_access': len(open_ports) > 0
    }


def analyze_rds_instance_security(instance, security_groups_data):
    """
    Analyze security configuration for an RDS instance
    
    Args:
        instance: RDS instance dict
        security_groups_data: Dict of security group data
        
    Returns:
        dict: Security analysis result
    """
    instance_id = instance['DBInstanceIdentifier']
    instance_port = instance.get('DbInstancePort', 'Unknown')
    
    # Get security groups for this instance
    sg_ids = [sg['VpcSecurityGroupId'] for sg in instance.get('VpcSecurityGroups', [])]
    
    vulnerable_security_groups = []
    all_open_ports = set()
    
    # Analyze each security group
    for sg_id in sg_ids:
        if sg_id in security_groups_data:
            sg_analysis = analyze_security_group_for_database_access(security_groups_data[sg_id])
            if sg_analysis['has_open_database_access']:
                vulnerable_security_groups.append(sg_analysis)
                all_open_ports.update(sg_analysis['open_database_ports'])
    
    # Check if the instance's actual port is exposed
    instance_port_exposed = False
    if isinstance(instance_port, int) and instance_port in all_open_ports:
        instance_port_exposed = True
    
    return {
        'resource_id': instance_id,
        'resource_type': 'rds_instance',
        'resource_arn': instance['DBInstanceArn'],
        'engine': instance.get('Engine', 'Unknown'),
        'instance_port': instance_port,
        'instance_status': instance.get('DBInstanceStatus', 'Unknown'),
        'security_groups': sg_ids,
        'vulnerable_security_groups': vulnerable_security_groups,
        'open_database_ports': sorted(all_open_ports),
        'instance_port_exposed': instance_port_exposed,
        'has_security_issue': len(vulnerable_security_groups) > 0
    }


def analyze_rds_cluster_security(cluster, security_groups_data):
    """
    Analyze security configuration for an RDS Aurora cluster
    
    Args:
        cluster: RDS cluster dict
        security_groups_data: Dict of security group data
        
    Returns:
        dict: Security analysis result
    """
    cluster_id = cluster['DBClusterIdentifier']
    cluster_port = cluster.get('Port', 'Unknown')
    
    # Get security groups for this cluster
    sg_ids = [sg['VpcSecurityGroupId'] for sg in cluster.get('VpcSecurityGroups', [])]
    
    vulnerable_security_groups = []
    all_open_ports = set()
    
    # Analyze each security group
    for sg_id in sg_ids:
        if sg_id in security_groups_data:
            sg_analysis = analyze_security_group_for_database_access(security_groups_data[sg_id])
            if sg_analysis['has_open_database_access']:
                vulnerable_security_groups.append(sg_analysis)
                all_open_ports.update(sg_analysis['open_database_ports'])
    
    # Check if the cluster's actual port is exposed
    cluster_port_exposed = False
    if isinstance(cluster_port, int) and cluster_port in all_open_ports:
        cluster_port_exposed = True
    
    return {
        'resource_id': cluster_id,
        'resource_type': 'rds_cluster',
        'resource_arn': cluster['DBClusterArn'],
        'engine': cluster.get('Engine', 'Unknown'),
        'cluster_port': cluster_port,
        'cluster_status': cluster.get('Status', 'Unknown'),
        'security_groups': sg_ids,
        'vulnerable_security_groups': vulnerable_security_groups,
        'open_database_ports': sorted(all_open_ports),
        'cluster_port_exposed': cluster_port_exposed,
        'has_security_issue': len(vulnerable_security_groups) > 0
    }


def check_rds_security_groups_region(rds_client, ec2_client, region):
    """
    Check RDS security groups in a specific region
    
    Args:
        rds_client: Boto3 RDS client
        ec2_client: Boto3 EC2 client
        region: AWS region name
        
    Returns:
        dict: Region check results
    """
    try:
        # Get all RDS instances and clusters
        instances = get_rds_instances(rds_client, region)
        clusters = get_rds_clusters(rds_client, region)
        
        # Collect all unique security group IDs
        all_sg_ids = set()
        
        for instance in instances:
            sg_ids = [sg['VpcSecurityGroupId'] for sg in instance.get('VpcSecurityGroups', [])]
            all_sg_ids.update(sg_ids)
        
        for cluster in clusters:
            sg_ids = [sg['VpcSecurityGroupId'] for sg in cluster.get('VpcSecurityGroups', [])]
            all_sg_ids.update(sg_ids)
        
        # Get security group details
        security_groups_data = get_security_groups(ec2_client, list(all_sg_ids))
        
        # Analyze instances
        instance_analyses = []
        vulnerable_instances = []
        
        for instance in instances:
            analysis = analyze_rds_instance_security(instance, security_groups_data)
            instance_analyses.append(analysis)
            
            if analysis['has_security_issue']:
                vulnerable_instances.append(analysis)
        
        # Analyze clusters
        cluster_analyses = []
        vulnerable_clusters = []
        
        for cluster in clusters:
            analysis = analyze_rds_cluster_security(cluster, security_groups_data)
            cluster_analyses.append(analysis)
            
            if analysis['has_security_issue']:
                vulnerable_clusters.append(analysis)
        
        # Combine results
        all_resources = instance_analyses + cluster_analyses
        vulnerable_resources = vulnerable_instances + vulnerable_clusters
        
        return {
            'region': region,
            'total_instances': len(instances),
            'total_clusters': len(clusters),
            'total_resources': len(all_resources),
            'vulnerable_resources': len(vulnerable_resources),
            'instances': instance_analyses,
            'clusters': cluster_analyses,
            'vulnerable_items': vulnerable_resources,
            'error': None
        }
        
    except ClientError as e:
        error_msg = f"AWS API error in {region}: {str(e)}"
        return {
            'region': region,
            'total_instances': 0,
            'total_clusters': 0,
            'total_resources': 0,
            'vulnerable_resources': 0,
            'instances': [],
            'clusters': [],
            'vulnerable_items': [],
            'error': error_msg
        }
    except Exception as e:
        error_msg = f"Unexpected error in {region}: {str(e)}"
        return {
            'region': region,
            'total_instances': 0,
            'total_clusters': 0,
            'total_resources': 0,
            'vulnerable_resources': 0,
            'instances': [],
            'clusters': [],
            'vulnerable_items': [],
            'error': error_msg
        }


def get_aws_regions(session):
    """Get list of all available AWS regions"""
    try:
        ec2_client = session.client('ec2', region_name='us-east-1')
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
    total_resources = stats['total_resources']
    vulnerable_resources = stats['vulnerable_resources']
    
    if total_resources == 0:
        status = 'Success'
        message = 'No RDS instances or clusters found in the checked regions.'
    elif vulnerable_resources == 0:
        status = 'Success'
        message = f'All {total_resources} RDS resources have properly restricted security groups.'
    else:
        status = 'Warning'
        message = f'Found {vulnerable_resources} RDS resources with security groups allowing internet access to database ports.'
    
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
        regions_to_check = get_aws_regions(session)
    
    return session, regions_to_check


def process_regions(session, regions_to_check):
    """Process all regions and collect results"""
    region_results = []
    regions_with_errors = []
    
    for region in regions_to_check:
        try:
            rds_client = session.client('rds', region_name=region)
            ec2_client = session.client('ec2', region_name=region)
            
            result = check_rds_security_groups_region(rds_client, ec2_client, region)
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
                'total_instances': 0,
                'total_clusters': 0,
                'total_resources': 0,
                'vulnerable_resources': 0,
                'instances': [],
                'clusters': [],
                'vulnerable_items': [],
                'error': error_msg
            })
    
    return region_results, regions_with_errors


def build_final_result(timestamp, region_results, regions_with_errors, regions_to_check):
    """Build the final result structure"""
    # Calculate overall statistics
    stats = {
        'total_instances': sum(r['total_instances'] for r in region_results),
        'total_clusters': sum(r['total_clusters'] for r in region_results),
        'total_resources': sum(r['total_resources'] for r in region_results),
        'vulnerable_resources': sum(r['vulnerable_resources'] for r in region_results),
        'regions_checked': len([r for r in region_results if not r['error']]),
        'regions_with_errors': len(regions_with_errors)
    }
    
    # Collect all vulnerable resources
    all_vulnerable_resources = []
    for result in region_results:
        if not result['error']:
            for resource in result['vulnerable_items']:
                resource['region'] = result['region']
                all_vulnerable_resources.append(resource)
    
    # Determine overall status
    status, message = determine_security_status(stats, regions_with_errors)
    
    # Build final result
    result = {
        'timestamp': timestamp,
        'status': status,
        'message': message,
        'check_type': 'rds_security_groups',
        'regions_checked': len(regions_to_check),
        'total_instances': stats['total_instances'],
        'total_clusters': stats['total_clusters'],
        'total_resources': stats['total_resources'],
        'vulnerable_resources': stats['vulnerable_resources'],
        'vulnerable_items': all_vulnerable_resources,
        'region_results': region_results
    }
    
    # Add error details if any
    if regions_with_errors:
        result['region_errors'] = regions_with_errors
    
    return result


def check_rds_security_groups(profile_name=None, region_name=None):
    """
    Main function to check RDS security groups for internet access
    
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
            'check_type': 'rds_security_groups',
            'regions_checked': 0,
            'total_instances': 0,
            'total_clusters': 0,
            'total_resources': 0,
            'vulnerable_resources': 0,
            'vulnerable_items': [],
            'region_results': []
        }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'check_type': 'rds_security_groups',
            'regions_checked': 0,
            'total_instances': 0,
            'total_clusters': 0,
            'total_resources': 0,
            'vulnerable_resources': 0,
            'vulnerable_items': [],
            'region_results': []
        }


def print_resource_details(resource, index):
    """Print detailed information about a vulnerable RDS resource"""
    print(f"\n{index}. RDS {resource['resource_type'].replace('_', ' ').title()} Details:")
    print(f"   Resource ID: {resource['resource_id']}")
    print(f"   Engine: {resource['engine']}")
    
    if resource['resource_type'] == 'rds_instance':
        print(f"   Instance Port: {resource['instance_port']}")
        print(f"   Status: {resource['instance_status']}")
        print(f"   Instance Port Exposed: {'Yes' if resource['instance_port_exposed'] else 'No'}")
    else:  # rds_cluster
        print(f"   Cluster Port: {resource['cluster_port']}")
        print(f"   Status: {resource['cluster_status']}")
        print(f"   Cluster Port Exposed: {'Yes' if resource['cluster_port_exposed'] else 'No'}")
    
    print(f"   Region: {resource['region']}")
    print(f"   Open Database Ports: {', '.join(map(str, resource['open_database_ports']))}")
    
    if resource['vulnerable_security_groups']:
        print("   Vulnerable Security Groups:")
        for sg in resource['vulnerable_security_groups']:
            print(f"     - {sg['group_id']} ({sg['group_name']}): ports {', '.join(map(str, sg['open_database_ports']))}")


def print_basic_summary(result):
    """Print basic summary information"""
    print("\nRDS Security Groups Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Regions Checked: {result['regions_checked']}")
    print(f"Total RDS Instances: {result['total_instances']}")
    print(f"Total RDS Clusters: {result['total_clusters']}")
    print(f"Total Resources: {result['total_resources']}")
    print(f"Vulnerable Resources: {result['vulnerable_resources']}")


def print_region_errors(result):
    """Print region errors if any"""
    if result.get('region_errors'):
        print("\nRegion Errors:")
        for error in result['region_errors']:
            print(f"  - {error['region']}: {error['error']}")


def print_vulnerable_resources(resources):
    """Print details of vulnerable RDS resources"""
    if resources:
        print(f"\nVulnerable RDS Resources ({len(resources)}):")
        for i, resource in enumerate(resources, 1):
            print_resource_details(resource, i)


def print_summary_output(result):
    """Print human-readable summary output"""
    print_basic_summary(result)
    print_region_errors(result)
    
    vulnerable_resources = result.get('vulnerable_items', [])
    print_vulnerable_resources(vulnerable_resources)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check RDS security groups for internet access")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--region', help='AWS region to check (default: all regions)')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_rds_security_groups(
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
