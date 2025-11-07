#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Security Pillar
Check RDS Encryption Configuration

This script checks if RDS instances and Aurora clusters are encrypted at rest.

Checks include:
- RDS DB instances encryption status
- RDS Aurora clusters encryption status
- KMS key information for encrypted resources
"""

import boto3
import json
import sys
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError


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


def analyze_rds_instance_encryption(instance):
    """
    Analyze encryption configuration for an RDS instance
    
    Args:
        instance: RDS instance dict
        
    Returns:
        dict: Encryption analysis result
    """
    return {
        'resource_id': instance['DBInstanceIdentifier'],
        'resource_type': 'rds_instance',
        'resource_arn': instance['DBInstanceArn'],
        'engine': instance.get('Engine', 'Unknown'),
        'engine_version': instance.get('EngineVersion', 'Unknown'),
        'instance_class': instance.get('DBInstanceClass', 'Unknown'),
        'instance_status': instance.get('DBInstanceStatus', 'Unknown'),
        'encrypted': instance.get('StorageEncrypted', False),
        'kms_key_id': instance.get('KmsKeyId', 'N/A') if instance.get('StorageEncrypted') else 'N/A',
        'cluster_identifier': instance.get('DBClusterIdentifier', 'N/A')
    }


def analyze_rds_cluster_encryption(cluster):
    """
    Analyze encryption configuration for an RDS Aurora cluster
    
    Args:
        cluster: RDS cluster dict
        
    Returns:
        dict: Encryption analysis result
    """
    return {
        'resource_id': cluster['DBClusterIdentifier'],
        'resource_type': 'rds_cluster',
        'resource_arn': cluster['DBClusterArn'],
        'engine': cluster.get('Engine', 'Unknown'),
        'engine_version': cluster.get('EngineVersion', 'Unknown'),
        'engine_mode': cluster.get('EngineMode', 'Unknown'),
        'cluster_status': cluster.get('Status', 'Unknown'),
        'encrypted': cluster.get('StorageEncrypted', False),
        'kms_key_id': cluster.get('KmsKeyId', 'N/A') if cluster.get('StorageEncrypted') else 'N/A',
        'cluster_members': len(cluster.get('DBClusterMembers', []))
    }


def check_rds_encryption_region(rds_client, region):
    """
    Check RDS encryption in a specific region
    
    Args:
        rds_client: Boto3 RDS client
        region: AWS region name
        
    Returns:
        dict: Region check results
    """
    try:
        # Get all RDS instances and clusters
        instances = get_rds_instances(rds_client, region)
        clusters = get_rds_clusters(rds_client, region)
        
        # Analyze encryption for instances
        instance_analyses = []
        unencrypted_instances = []
        
        for instance in instances:
            analysis = analyze_rds_instance_encryption(instance)
            instance_analyses.append(analysis)
            
            if not analysis['encrypted']:
                unencrypted_instances.append(analysis)
        
        # Analyze encryption for clusters
        cluster_analyses = []
        unencrypted_clusters = []
        
        for cluster in clusters:
            analysis = analyze_rds_cluster_encryption(cluster)
            cluster_analyses.append(analysis)
            
            if not analysis['encrypted']:
                unencrypted_clusters.append(analysis)
        
        # Combine all resources
        all_resources = instance_analyses + cluster_analyses
        unencrypted_resources = unencrypted_instances + unencrypted_clusters
        
        return {
            'region': region,
            'total_instances': len(instances),
            'total_clusters': len(clusters),
            'total_resources': len(all_resources),
            'encrypted_resources': len(all_resources) - len(unencrypted_resources),
            'unencrypted_resources': len(unencrypted_resources),
            'instances': instance_analyses,
            'clusters': cluster_analyses,
            'all_resources': all_resources,
            'unencrypted_items': unencrypted_resources,
            'error': None
        }
        
    except ClientError as e:
        error_msg = f"AWS API error in {region}: {str(e)}"
        return {
            'region': region,
            'total_instances': 0,
            'total_clusters': 0,
            'total_resources': 0,
            'encrypted_resources': 0,
            'unencrypted_resources': 0,
            'instances': [],
            'clusters': [],
            'all_resources': [],
            'unencrypted_items': [],
            'error': error_msg
        }
    except Exception as e:
        error_msg = f"Unexpected error in {region}: {str(e)}"
        return {
            'region': region,
            'total_instances': 0,
            'total_clusters': 0,
            'total_resources': 0,
            'encrypted_resources': 0,
            'unencrypted_resources': 0,
            'instances': [],
            'clusters': [],
            'all_resources': [],
            'unencrypted_items': [],
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


def determine_encryption_status(stats, regions_with_errors):
    """Determine overall encryption status and message"""
    total_resources = stats['total_resources']
    unencrypted_resources = stats['unencrypted_resources']
    
    if total_resources == 0:
        status = 'Success'
        message = 'No RDS instances or clusters found in the checked regions.'
    elif unencrypted_resources == 0:
        status = 'Success'
        message = f'All {total_resources} RDS resources are encrypted at rest.'
    else:
        status = 'Warning'
        message = f'Found {unencrypted_resources} unencrypted RDS resources out of {total_resources} total resources.'
    
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
            result = check_rds_encryption_region(rds_client, region)
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
                'encrypted_resources': 0,
                'unencrypted_resources': 0,
                'instances': [],
                'clusters': [],
                'all_resources': [],
                'unencrypted_items': [],
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
        'encrypted_resources': sum(r['encrypted_resources'] for r in region_results),
        'unencrypted_resources': sum(r['unencrypted_resources'] for r in region_results),
        'regions_checked': len([r for r in region_results if not r['error']]),
        'regions_with_errors': len(regions_with_errors)
    }
    
    # Collect all unencrypted resources
    all_unencrypted_resources = []
    for result in region_results:
        if not result['error']:
            for resource in result['unencrypted_items']:
                resource['region'] = result['region']
                all_unencrypted_resources.append(resource)
    
    # Determine overall status
    status, message = determine_encryption_status(stats, regions_with_errors)
    
    # Build final result
    result = {
        'timestamp': timestamp,
        'status': status,
        'message': message,
        'check_type': 'rds_encryption',
        'regions_checked': len(regions_to_check),
        'total_instances': stats['total_instances'],
        'total_clusters': stats['total_clusters'],
        'total_resources': stats['total_resources'],
        'encrypted_resources': stats['encrypted_resources'],
        'unencrypted_resources': stats['unencrypted_resources'],
        'unencrypted_items': all_unencrypted_resources,
        'region_results': region_results
    }
    
    # Add error details if any
    if regions_with_errors:
        result['region_errors'] = regions_with_errors
    
    return result


def check_rds_encryption(profile_name=None, region_name=None):
    """
    Main function to check RDS encryption configuration
    
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
            'check_type': 'rds_encryption',
            'regions_checked': 0,
            'total_instances': 0,
            'total_clusters': 0,
            'total_resources': 0,
            'encrypted_resources': 0,
            'unencrypted_resources': 0,
            'unencrypted_items': [],
            'region_results': []
        }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'check_type': 'rds_encryption',
            'regions_checked': 0,
            'total_instances': 0,
            'total_clusters': 0,
            'total_resources': 0,
            'encrypted_resources': 0,
            'unencrypted_resources': 0,
            'unencrypted_items': [],
            'region_results': []
        }


def print_resource_details(resource, index):
    """Print detailed information about an RDS resource"""
    print(f"\n{index}. RDS {resource['resource_type'].replace('_', ' ').title()} Details:")
    print(f"   Resource ID: {resource['resource_id']}")
    print(f"   Engine: {resource['engine']} {resource.get('engine_version', '')}")
    
    if resource['resource_type'] == 'rds_instance':
        print(f"   Instance Class: {resource['instance_class']}")
        print(f"   Status: {resource['instance_status']}")
        if resource['cluster_identifier'] != 'N/A':
            print(f"   Cluster: {resource['cluster_identifier']}")
    else:  # rds_cluster
        print(f"   Engine Mode: {resource['engine_mode']}")
        print(f"   Status: {resource['cluster_status']}")
        print(f"   Cluster Members: {resource['cluster_members']}")
    
    print(f"   Region: {resource['region']}")
    print(f"   Encrypted: {'Yes' if resource['encrypted'] else 'No'}")
    
    if resource['encrypted'] and resource['kms_key_id'] != 'N/A':
        print(f"   KMS Key: {resource['kms_key_id']}")


def print_basic_summary(result):
    """Print basic summary information"""
    print("\nRDS Encryption Configuration Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Regions Checked: {result['regions_checked']}")
    print(f"Total RDS Instances: {result['total_instances']}")
    print(f"Total RDS Clusters: {result['total_clusters']}")
    print(f"Total Resources: {result['total_resources']}")
    print(f"Encrypted Resources: {result['encrypted_resources']}")
    print(f"Unencrypted Resources: {result['unencrypted_resources']}")


def print_region_errors(result):
    """Print region errors if any"""
    if result.get('region_errors'):
        print("\nRegion Errors:")
        for error in result['region_errors']:
            print(f"  - {error['region']}: {error['error']}")


def print_unencrypted_resources(resources):
    """Print details of unencrypted RDS resources"""
    if resources:
        print(f"\nUnencrypted RDS Resources ({len(resources)}):")
        for i, resource in enumerate(resources, 1):
            print_resource_details(resource, i)


def print_summary_output(result):
    """Print human-readable summary output"""
    print_basic_summary(result)
    print_region_errors(result)
    
    unencrypted_resources = result.get('unencrypted_items', [])
    print_unencrypted_resources(unencrypted_resources)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check RDS encryption configuration")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--region', help='AWS region to check (default: all regions)')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_rds_encryption(
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
