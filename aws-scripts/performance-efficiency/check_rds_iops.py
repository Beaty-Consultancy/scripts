#!/usr/bin/env python3
"""
AWS RDS IOPS Performance Check Script

This script checks AWS RDS instances and evaluates their IOPS performance
by analyzing their storage configuration and actual IOPS utilization.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timedelta, timezone

# Constants
DEFAULT_LOOKBACK_HOURS = 24
DEFAULT_METRIC_PERIOD = 300  # 5 minutes
HIGH_IOPS_UTILIZATION_THRESHOLD = 80.0  # 80% IOPS utilization warning
LOW_IOPS_THRESHOLD = 100  # Instances with very low provisioned IOPS

# RDS Engine to storage type mapping for IOPS calculation
RDS_ENGINE_STORAGE_DEFAULTS = {
    'mysql': {'default_iops': 3, 'max_iops_ratio': 50},
    'postgres': {'default_iops': 3, 'max_iops_ratio': 50}, 
    'mariadb': {'default_iops': 3, 'max_iops_ratio': 50},
    'oracle-ee': {'default_iops': 3, 'max_iops_ratio': 50},
    'oracle-se2': {'default_iops': 3, 'max_iops_ratio': 50},
    'sqlserver-ee': {'default_iops': 3, 'max_iops_ratio': 50},
    'sqlserver-se': {'default_iops': 3, 'max_iops_ratio': 50},
    'sqlserver-ex': {'default_iops': 3, 'max_iops_ratio': 50},
    'sqlserver-web': {'default_iops': 3, 'max_iops_ratio': 50}
}


def get_rds_instance_name(instance):
    """Extract RDS instance name from identifier or tags"""
    # Try to get name from tags first
    if 'TagList' in instance:
        for tag in instance['TagList']:
            if tag['Key'].lower() == 'name':
                return tag['Value']
    
    # Fall back to DB instance identifier
    return instance.get('DBInstanceIdentifier', 'Unknown')


def calculate_iops_per_gb(iops, allocated_storage):
    """Calculate IOPS per GB with safe division"""
    return round(iops / allocated_storage, 2) if allocated_storage > 0 else 0


def get_provisioned_iops_config(iops, storage_type, allocated_storage):
    """Get IOPS configuration for provisioned IOPS storage (io1/io2)"""
    return {
        'provisioned_iops': iops,
        'max_iops': iops,
        'storage_type': storage_type,
        'iops_per_gb': calculate_iops_per_gb(iops, allocated_storage)
    }


def get_gp2_iops_config(allocated_storage, storage_type):
    """Get IOPS configuration for gp2 storage"""
    baseline_iops = max(100, allocated_storage * 3)
    burst_iops = 3000 if allocated_storage < 1000 else baseline_iops
    return {
        'provisioned_iops': baseline_iops,
        'max_iops': burst_iops,
        'storage_type': storage_type,
        'iops_per_gb': 3.0
    }


def get_gp3_iops_config(iops, allocated_storage, storage_type):
    """Get IOPS configuration for gp3 storage"""
    baseline_iops = 3000
    provisioned_iops = iops if iops else baseline_iops
    return {
        'provisioned_iops': provisioned_iops,
        'max_iops': provisioned_iops,
        'storage_type': storage_type,
        'iops_per_gb': calculate_iops_per_gb(provisioned_iops, allocated_storage)
    }


def get_standard_iops_config(allocated_storage, storage_type):
    """Get IOPS configuration for standard (magnetic) storage"""
    return {
        'provisioned_iops': 100,
        'max_iops': 100,
        'storage_type': storage_type,
        'iops_per_gb': calculate_iops_per_gb(100, allocated_storage)
    }


def get_default_iops_config(engine, allocated_storage, storage_type):
    """Get default IOPS configuration for unknown storage types"""
    default_iops = RDS_ENGINE_STORAGE_DEFAULTS.get(engine, {}).get('default_iops', 3)
    calculated_iops = max(100, allocated_storage * default_iops)
    return {
        'provisioned_iops': calculated_iops,
        'max_iops': calculated_iops,
        'storage_type': storage_type,
        'iops_per_gb': default_iops
    }


def calculate_rds_iops(instance):
    """Calculate IOPS for RDS instance based on storage type and configuration"""
    storage_type = instance.get('StorageType', 'standard')
    allocated_storage = instance.get('AllocatedStorage', 0)
    iops = instance.get('Iops', 0)
    engine = instance.get('Engine', '').lower()
    
    if storage_type in ['io1', 'io2'] and iops:
        return get_provisioned_iops_config(iops, storage_type, allocated_storage)
    elif storage_type == 'gp2':
        return get_gp2_iops_config(allocated_storage, storage_type)
    elif storage_type == 'gp3':
        return get_gp3_iops_config(iops, allocated_storage, storage_type)
    elif storage_type == 'standard':
        return get_standard_iops_config(allocated_storage, storage_type)
    else:
        return get_default_iops_config(engine, allocated_storage, storage_type)


def get_rds_iops_utilization(cloudwatch_client, instance_id, hours_back=DEFAULT_LOOKBACK_HOURS):
    """Get IOPS utilization metrics for RDS instance"""
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)
        
        # Adjust period based on time range
        if hours_back <= 24:
            period = 300  # 5 minutes for last 24 hours
        elif hours_back <= 168:  # 7 days
            period = 3600  # 1 hour for last week
        else:
            period = 86400  # 1 day for longer periods
        
        # Get Read IOPS
        read_response = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/RDS',
            MetricName='ReadIOPS',
            Dimensions=[
                {
                    'Name': 'DBInstanceIdentifier',
                    'Value': instance_id
                }
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=period,
            Statistics=['Average', 'Maximum']
        )
        
        # Get Write IOPS
        write_response = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/RDS',
            MetricName='WriteIOPS',
            Dimensions=[
                {
                    'Name': 'DBInstanceIdentifier',
                    'Value': instance_id
                }
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=period,
            Statistics=['Average', 'Maximum']
        )
        
        read_datapoints = read_response.get('Datapoints', [])
        write_datapoints = write_response.get('Datapoints', [])
        
        if not read_datapoints and not write_datapoints:
            return None
        
        # Calculate metrics
        read_avg = sum(point['Average'] for point in read_datapoints) / len(read_datapoints) if read_datapoints else 0
        read_max = max(point['Maximum'] for point in read_datapoints) if read_datapoints else 0
        
        write_avg = sum(point['Average'] for point in write_datapoints) / len(write_datapoints) if write_datapoints else 0
        write_max = max(point['Maximum'] for point in write_datapoints) if write_datapoints else 0
        
        total_avg = read_avg + write_avg
        total_max = read_max + write_max
        
        return {
            'read_iops_avg': round(read_avg, 2),
            'read_iops_max': round(read_max, 2),
            'write_iops_avg': round(write_avg, 2),
            'write_iops_max': round(write_max, 2),
            'total_iops_avg': round(total_avg, 2),
            'total_iops_max': round(total_max, 2),
            'datapoint_count': len(read_datapoints) + len(write_datapoints),
            'period_minutes': period // 60
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        return {'error': f'CloudWatch error: {error_code}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


def create_rds_instance_entry(instance, iops_metrics, region_name):
    """Create an RDS instance entry with IOPS information"""
    instance_name = get_rds_instance_name(instance)
    instance_id = instance['DBInstanceIdentifier']
    instance_class = instance['DBInstanceClass']
    engine = instance['Engine']
    engine_version = instance.get('EngineVersion', 'Unknown')
    status = instance['DBInstanceStatus']
    
    # Calculate IOPS configuration
    iops_config = calculate_rds_iops(instance)
    
    # Default values for utilization metrics
    utilization_data = {
        'read_iops_avg': 0.0,
        'read_iops_max': 0.0,
        'write_iops_avg': 0.0,
        'write_iops_max': 0.0,
        'total_iops_avg': 0.0,
        'total_iops_max': 0.0,
        'metricsAvailable': False,
        'period_minutes': 5
    }
    
    error_message = None
    
    # Add utilization metrics if available
    if iops_metrics:
        if 'error' in iops_metrics:
            error_message = iops_metrics['error']
        else:
            utilization_data.update(iops_metrics)
            utilization_data['metricsAvailable'] = True
    
    # Calculate utilization percentage
    utilization_percentage = 0.0
    iops_warning = False
    
    if utilization_data['metricsAvailable'] and iops_config['max_iops'] > 0:
        utilization_percentage = round((utilization_data['total_iops_max'] / iops_config['max_iops']) * 100, 2)
        iops_warning = utilization_percentage >= HIGH_IOPS_UTILIZATION_THRESHOLD
    
    # Check for low IOPS configuration
    low_iops_warning = iops_config['provisioned_iops'] <= LOW_IOPS_THRESHOLD
    
    entry = {
        'instanceName': instance_name,
        'instanceId': instance_id,
        'instanceClass': instance_class,
        'engine': engine,
        'engineVersion': engine_version,
        'status': status,
        'region': region_name,
        'availabilityZone': instance.get('AvailabilityZone', 'Unknown'),
        'storageInfo': {
            'storageType': iops_config['storage_type'],
            'allocatedStorage': instance.get('AllocatedStorage', 0),
            'storageEncrypted': instance.get('StorageEncrypted', False)
        },
        'iopsConfiguration': {
            'provisionedIOPS': iops_config['provisioned_iops'],
            'maxIOPS': iops_config['max_iops'],
            'iopsPerGB': iops_config['iops_per_gb']
        },
        'iopsUtilization': utilization_data,
        'performanceAnalysis': {
            'utilizationPercentage': utilization_percentage,
            'highUtilizationWarning': iops_warning,
            'lowIOPSWarning': low_iops_warning
        },
        'createdTime': instance.get('InstanceCreateTime', 'N/A').isoformat() if instance.get('InstanceCreateTime') else 'N/A'
    }
    
    if error_message:
        entry['iopsUtilization']['error'] = error_message
    
    return entry


def process_rds_instances(instances, cloudwatch_client, region_name):
    """Process RDS instances and analyze their IOPS performance"""
    rds_iops_data = []
    
    for instance in instances:
        # Only process instances that are available or in other active states
        if instance['DBInstanceStatus'] not in ['deleting', 'deleted']:
            # Get IOPS metrics for available instances
            iops_metrics = None
            if instance['DBInstanceStatus'] == 'available':
                iops_metrics = get_rds_iops_utilization(cloudwatch_client, instance['DBInstanceIdentifier'])
            
            instance_entry = create_rds_instance_entry(instance, iops_metrics, region_name)
            rds_iops_data.append(instance_entry)
    
    return rds_iops_data


def get_all_regions(session):
    """Get all available AWS regions"""
    try:
        ec2_client = session.client('ec2', region_name='eu-west-2')
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


def check_region_rds_iops(session, region_name):
    """Check RDS instances IOPS performance in a specific region"""
    try:
        rds_client = session.client('rds', region_name=region_name)
        cloudwatch_client = session.client('cloudwatch', region_name=region_name)
        
        # Get all RDS instances in this region
        response = rds_client.describe_db_instances()
        instances = response.get('DBInstances', [])
        
        # Handle pagination if needed
        while 'Marker' in response:
            response = rds_client.describe_db_instances(Marker=response['Marker'])
            instances.extend(response.get('DBInstances', []))
        
        # Fetch tags for each instance
        for instance in instances:
            try:
                db_instance_arn = instance.get('DBInstanceArn')
                if db_instance_arn:
                    tags_response = rds_client.list_tags_for_resource(ResourceName=db_instance_arn)
                    instance['TagList'] = tags_response.get('TagList', [])
            except Exception:
                # If we can't get tags, continue without them
                instance['TagList'] = []
        
        return process_rds_instances(instances, cloudwatch_client, region_name)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        # Log specific error for debugging but return empty list to continue with other regions
        print(f"Error in region {region_name}: {error_code}", file=__import__('sys').stderr)
        return []
    except Exception as e:
        # Log error for debugging but return empty list to continue with other regions
        print(f"Unexpected error in region {region_name}: {str(e)}", file=__import__('sys').stderr)
        return []


def create_success_response(all_rds_iops, regions_checked):
    """Create success response structure"""
    total_instances = len(all_rds_iops)
    high_utilization_instances = [inst for inst in all_rds_iops if inst['performanceAnalysis']['highUtilizationWarning']]
    high_utilization_count = len(high_utilization_instances)
    low_iops_instances = [inst for inst in all_rds_iops if inst['performanceAnalysis']['lowIOPSWarning']]
    low_iops_count = len(low_iops_instances)
    available_instances = [inst for inst in all_rds_iops if inst['status'] == 'available']
    available_count = len(available_instances)
    
    if total_instances == 0:
        message = f"No RDS instances found across {regions_checked} regions."
    elif high_utilization_count == 0 and low_iops_count == 0:
        message = f"All {available_count} available RDS instances across {regions_checked} regions have optimal IOPS configuration."
    else:
        warnings = []
        if high_utilization_count > 0:
            warnings.append(f"{high_utilization_count} instances with high IOPS utilization")
        if low_iops_count > 0:
            warnings.append(f"{low_iops_count} instances with low IOPS configuration")
        message = f"Found {', '.join(warnings)} across {regions_checked} regions."
    
    recommendations = []
    if high_utilization_count > 0:
        recommendations.append("Consider upgrading storage or increasing provisioned IOPS for high utilization instances")
    if low_iops_count > 0:
        recommendations.append("Consider upgrading from standard storage or increasing IOPS allocation for low IOPS instances")
    
    return {
        'status': 'Success',
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'total_instances': str(total_instances),
        'available_instances': str(available_count),
        'high_utilization_instances': str(high_utilization_count),
        'low_iops_instances': str(low_iops_count),
        'regions_checked': str(regions_checked),
        'details': {
            'instances': all_rds_iops,
            'high_utilization_threshold': HIGH_IOPS_UTILIZATION_THRESHOLD,
            'low_iops_threshold': LOW_IOPS_THRESHOLD,
            'metric_period_hours': DEFAULT_LOOKBACK_HOURS,
            'recommendations': recommendations
        }
    }


def check_rds_iops(profile_name=None, region_name=None, hours_back=DEFAULT_LOOKBACK_HOURS):
    """
    Check AWS RDS instances IOPS performance across all regions or specific region
    
    Args:
        profile_name (str): AWS profile name (optional)
        region_name (str): AWS region name (optional, if not provided checks all regions)
        hours_back (int): Number of hours to look back for metrics (default: 24)
        
    Returns:
        dict: Structured result for dashboard compatibility
    """
    
    try:
        # Initialize session with profile
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
        else:
            session = boto3.Session()
        
        all_rds_iops = []
        regions_to_check = []
        
        # Determine which regions to check
        if region_name:
            regions_to_check = [region_name]
        else:
            regions_to_check = get_all_regions(session)
        
        # Check each region
        for region in regions_to_check:
            try:
                rds_iops = check_region_rds_iops(session, region)
                all_rds_iops.extend(rds_iops)
            except ClientError as e:
                # Log specific AWS errors for debugging
                error_code = e.response['Error']['Code']
                print(f"AWS error in region {region}: {error_code}", file=__import__('sys').stderr)
                continue
            except Exception as e:
                # Log unexpected errors for debugging
                print(f"Unexpected error in region {region}: {str(e)}", file=__import__('sys').stderr)
                continue
        
        regions_checked = len(regions_to_check)
        
        if len(all_rds_iops) == 0:
            region_text = f"region {region_name}" if region_name else f"{regions_checked} regions"
            return {
                'status': 'Success',
                'message': f'No RDS instances found in the specified {region_text}.',
                'timestamp': datetime.now().isoformat(),
                'total_instances': '0',
                'available_instances': '0',
                'high_utilization_instances': '0',
                'low_iops_instances': '0',
                'regions_checked': str(regions_checked),
                'details': {
                    'instances': [],
                    'high_utilization_threshold': HIGH_IOPS_UTILIZATION_THRESHOLD,
                    'low_iops_threshold': LOW_IOPS_THRESHOLD,
                    'metric_period_hours': hours_back,
                    'recommendations': []
                }
            }
        
        # Generate result
        return create_success_response(all_rds_iops, regions_checked)
        
    except NoCredentialsError:
        return {
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'timestamp': datetime.now().isoformat(),
            'total_instances': '0',
            'available_instances': '0',
            'high_utilization_instances': '0',
            'low_iops_instances': '0',
            'regions_checked': '0',
            'details': {
                'error_type': 'NoCredentialsError',
                'error_message': 'AWS credentials not found',
                'instances': [],
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
            'total_instances': '0',
            'available_instances': '0',
            'high_utilization_instances': '0',
            'low_iops_instances': '0',
            'regions_checked': '0',
            'details': {
                'error_type': error_code,
                'error_message': error_message,
                'instances': [],
                'recommendations': []
            }
        }
    
    except Exception as e:
        return {
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'total_instances': '0',
            'available_instances': '0',
            'high_utilization_instances': '0',
            'low_iops_instances': '0',
            'regions_checked': '0',
            'details': {
                'error_type': 'UnexpectedError',
                'error_message': str(e),
                'instances': [],
                'recommendations': []
            }
        }


def print_rds_iops_details(instance, index):
    """Print detailed IOPS information for a single RDS instance"""
    warning_indicators = []
    if instance['performanceAnalysis']['highUtilizationWarning']:
        warning_indicators.append("⚠️ High IOPS Utilization")
    if instance['performanceAnalysis']['lowIOPSWarning']:
        warning_indicators.append("💾 Low IOPS Configuration")
    
    warning_text = f" ({', '.join(warning_indicators)})" if warning_indicators else ""
    
    print(f"  {index}. {instance['instanceName']} ({instance['instanceId']}){warning_text}")
    print(f"     Instance Class: {instance['instanceClass']}")
    print(f"     Engine: {instance['engine']} {instance['engineVersion']}")
    print(f"     Status: {instance['status']}")
    print(f"     Region: {instance['region']}")
    
    # Storage and IOPS information
    storage = instance['storageInfo']
    iops_config = instance['iopsConfiguration']
    print(f"     Storage: {storage['storageType']} ({storage['allocatedStorage']} GB)")
    print(f"     IOPS Configuration: {iops_config['provisionedIOPS']} provisioned, {iops_config['maxIOPS']} max")
    print(f"     IOPS per GB: {iops_config['iopsPerGB']}")
    
    # Utilization metrics
    utilization = instance['iopsUtilization']
    if utilization['metricsAvailable']:
        period_text = f" (Period: {utilization['period_minutes']} min)" if 'period_minutes' in utilization else ""
        print(f"     IOPS Utilization{period_text}:")
        print(f"       Read IOPS - Avg: {utilization['read_iops_avg']}, Max: {utilization['read_iops_max']}")
        print(f"       Write IOPS - Avg: {utilization['write_iops_avg']}, Max: {utilization['write_iops_max']}")
        print(f"       Total IOPS - Avg: {utilization['total_iops_avg']}, Max: {utilization['total_iops_max']}")
        print(f"       Utilization: {instance['performanceAnalysis']['utilizationPercentage']}%")
    elif 'error' in utilization:
        print(f"     IOPS Utilization: Error - {utilization['error']}")
    else:
        print("     IOPS Utilization: No metrics available (instance may not be available)")
    
    print(f"     Created Time: {instance['createdTime']}")
    print()


def print_summary_output(result):
    """Print summary output for RDS IOPS analysis"""
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total RDS Instances: {result['total_instances']}")
    print(f"Available Instances: {result['available_instances']}")
    print(f"High Utilization Instances: {result['high_utilization_instances']}")
    print(f"Low IOPS Instances: {result['low_iops_instances']}")
    print(f"Regions Checked: {result['regions_checked']}")
    
    if result['details']['instances']:
        print(f"\nHigh Utilization Threshold: {result['details']['high_utilization_threshold']}%")
        print(f"Low IOPS Threshold: {result['details']['low_iops_threshold']} IOPS")
        print(f"Metric Period: Last {result['details']['metric_period_hours']} hours")
        print("\nRDS Instance IOPS Analysis:")
        for i, instance in enumerate(result['details']['instances'], 1):
            print_rds_iops_details(instance, i)
    
    if result['details']['recommendations']:
        print("Recommendations:")
        for recommendation in result['details']['recommendations']:
            print(f"  - {recommendation}")


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check AWS RDS instances IOPS performance')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--region', help='AWS region name', default=None)
    parser.add_argument('--hours', type=int, default=DEFAULT_LOOKBACK_HOURS,
                       help=f'Number of hours to look back for metrics (default: {DEFAULT_LOOKBACK_HOURS})')
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_rds_iops(
        profile_name=args.profile,
        region_name=args.region,
        hours_back=args.hours
    )
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        print_summary_output(result)


if __name__ == "__main__":
    main()
