#!/usr/bin/env python3
"""
RDS CPU Utilization Check Script

This script checks RDS instances and Aurora clusters for CPU utilization
across all AWS regions and flags instances with high CPU usage (>80%).

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timedelta


def check_rds_utilisation(profile_name=None):
    """
    Check RDS instances and Aurora clusters for CPU utilization
    
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
        
        high_cpu_instances = []
        total_instances = 0
        total_high_cpu = 0
        
        # Check each region
        for region in regions:
            try:
                rds_client = session.client('rds', region_name=region)
                cloudwatch_client = session.client('cloudwatch', region_name=region)
                
                # Get RDS instances
                instances_response = rds_client.describe_db_instances()
                instances = instances_response['DBInstances']
                
                # Get Aurora clusters
                clusters_response = rds_client.describe_db_clusters()
                clusters = clusters_response['DBClusters']
                
                # Check regular RDS instances
                for instance in instances:
                    total_instances += 1
                    instance_id = instance['DBInstanceIdentifier']
                    
                    # Get CPU utilization for the last 24 hours
                    cpu_utilization = get_cpu_utilization(
                        cloudwatch_client, 
                        instance_id, 
                        'AWS/RDS'
                    )
                    
                    if cpu_utilization is not None and cpu_utilization > 80:
                        total_high_cpu += 1
                        
                        # Get instance tags
                        tags = {}
                        try:
                            tags_response = rds_client.list_tags_for_resource(
                                ResourceName=instance['DBInstanceArn']
                            )
                            tags = {tag['Key']: tag['Value'] for tag in tags_response['TagList']}
                        except ClientError:
                            pass
                        
                        instance_info = {
                            'identifier': instance_id,
                            'type': 'RDS Instance',
                            'region': region,
                            'engine': instance.get('Engine', 'Unknown'),
                            'engine_version': instance.get('EngineVersion', 'Unknown'),
                            'instance_class': instance.get('DBInstanceClass', 'Unknown'),
                            'status': instance.get('DBInstanceStatus', 'Unknown'),
                            'availability_zone': instance.get('AvailabilityZone', 'Unknown'),
                            'multi_az': instance.get('MultiAZ', False),
                            'cpu_utilization': round(cpu_utilization, 2),
                            'tags': tags,
                            'name': tags.get('Name', 'No Name')
                        }
                        
                        high_cpu_instances.append(instance_info)
                
                # Check Aurora cluster instances
                for cluster in clusters:
                    cluster_members = cluster.get('DBClusterMembers', [])
                    
                    for member in cluster_members:
                        if member.get('IsClusterWriter', False):  # Check only writer instances
                            total_instances += 1
                            instance_id = member['DBInstanceIdentifier']
                            
                            # Get CPU utilization for Aurora instance
                            cpu_utilization = get_cpu_utilization(
                                cloudwatch_client, 
                                instance_id, 
                                'AWS/RDS'
                            )
                            
                            if cpu_utilization is not None and cpu_utilization > 80:
                                total_high_cpu += 1
                                
                                # Get cluster tags
                                tags = {}
                                try:
                                    tags_response = rds_client.list_tags_for_resource(
                                        ResourceName=cluster['DBClusterArn']
                                    )
                                    tags = {tag['Key']: tag['Value'] for tag in tags_response['TagList']}
                                except ClientError:
                                    pass
                                
                                cluster_info = {
                                    'identifier': instance_id,
                                    'type': 'Aurora Cluster Writer',
                                    'region': region,
                                    'engine': cluster.get('Engine', 'Unknown'),
                                    'engine_version': cluster.get('EngineVersion', 'Unknown'),
                                    'instance_class': 'Aurora Serverless' if cluster.get('EngineMode') == 'serverless' else 'Aurora',
                                    'status': cluster.get('Status', 'Unknown'),
                                    'availability_zones': cluster.get('AvailabilityZones', []),
                                    'multi_az': len(cluster.get('AvailabilityZones', [])) > 1,
                                    'cpu_utilization': round(cpu_utilization, 2),
                                    'tags': tags,
                                    'name': tags.get('Name', cluster.get('DBClusterIdentifier', 'No Name'))
                                }
                                
                                high_cpu_instances.append(cluster_info)
                        
            except ClientError as e:
                # Skip regions where we don't have access
                if e.response['Error']['Code'] in ['UnauthorizedOperation', 'AuthFailure']:
                    continue
                else:
                    raise
        
        # Determine overall status
        if total_high_cpu == 0:
            status = 'Optimized'
            message = 'All RDS instances and Aurora clusters have acceptable CPU utilization (<80%).'
        else:
            status = 'Warning'
            message = f'{total_high_cpu} RDS instance(s) with high CPU utilization (>80%) found across all regions.'
        
        # Create structured result
        result = {
            'status': status,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'details': {
                'total_instances': total_instances,
                'total_high_cpu': total_high_cpu,
                'regions_checked': len(regions),
                'high_cpu_instances': high_cpu_instances
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
                'total_instances': 0,
                'total_high_cpu': 0,
                'regions_checked': 0,
                'high_cpu_instances': []
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
                'total_instances': 0,
                'total_high_cpu': 0,
                'regions_checked': 0,
                'high_cpu_instances': []
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
                'total_instances': 0,
                'total_high_cpu': 0,
                'regions_checked': 0,
                'high_cpu_instances': []
            }
        }


def get_cpu_utilization(cloudwatch_client, instance_id, namespace):
    """
    Get average CPU utilization for an RDS instance over the last 24 hours
    
    Args:
        cloudwatch_client: CloudWatch client
        instance_id (str): RDS instance identifier
        namespace (str): CloudWatch namespace
        
    Returns:
        float: Average CPU utilization percentage, or None if no data
    """
    try:
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=24)
        
        response = cloudwatch_client.get_metric_statistics(
            Namespace=namespace,
            MetricName='CPUUtilization',
            Dimensions=[
                {
                    'Name': 'DBInstanceIdentifier',
                    'Value': instance_id
                }
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,  # 1 hour periods
            Statistics=['Average']
        )
        
        datapoints = response['Datapoints']
        if datapoints:
            # Calculate average CPU utilization over the period
            avg_cpu = sum(dp['Average'] for dp in datapoints) / len(datapoints)
            return avg_cpu
        else:
            return None
            
    except ClientError:
        return None


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check RDS CPU utilization')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_rds_utilisation(args.profile)
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        # Summary output
        print(f"Status: {result['status']}")
        print(f"Message: {result['message']}")
        print(f"Total RDS Instances: {result['details']['total_instances']}")
        print(f"High CPU Instances: {result['details']['total_high_cpu']}")
        print(f"Regions Checked: {result['details']['regions_checked']}")
        
        if result['details']['high_cpu_instances']:
            print("\nHigh CPU Utilization Instances:")
            for i, instance in enumerate(result['details']['high_cpu_instances'], 1):
                print(f"  {i}. {instance['identifier']} ({instance['type']}) - {instance['cpu_utilization']}% CPU in {instance['region']}")


if __name__ == "__main__":
    main()
