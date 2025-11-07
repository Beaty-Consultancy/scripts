#!/usr/bin/env python3
"""
AWS EC2 CPU Utilization Check Script

This script checks AWS EC2 instances and evaluates their CPU utilization performance
by analyzing CloudWatch CPUUtilization metrics.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timedelta, timezone

# Constants
HIGH_CPU_THRESHOLD = 80.0
DEFAULT_METRIC_PERIOD = 300  # 5 minutes
DEFAULT_LOOKBACK_HOURS = 24
CPU_METRIC_NAME = 'CPUUtilization'
HIGH_CPU_WARNING_MESSAGE = "Consider investigating high CPU utilization or scaling up the instance"


def get_instance_name(instance):
    """Extract instance name from tags"""
    for tag in instance.get('Tags', []):
        if tag['Key'].lower() == 'name':
            return tag['Value']
    return instance['InstanceId']


def get_cpu_utilization_metrics(cloudwatch_client, instance_id, hours_back=DEFAULT_LOOKBACK_HOURS):
    """Get CPU utilization metrics for an instance"""
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)
        
        # Adjust period based on time range to avoid too many data points
        # CloudWatch limits: max 1440 data points per request
        if hours_back <= 24:
            period = 300  # 5 minutes for last 24 hours (288 data points)
        elif hours_back <= 168:  # 7 days
            period = 3600  # 1 hour for last week (168 data points)
        else:
            period = 86400  # 1 day for longer periods
        
        response = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/EC2',
            MetricName=CPU_METRIC_NAME,
            Dimensions=[
                {
                    'Name': 'InstanceId',
                    'Value': instance_id
                }
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=period,
            Statistics=['Average', 'Maximum']
        )
        
        datapoints = response.get('Datapoints', [])
        if not datapoints:
            return None
        
        # Calculate average and maximum CPU utilization
        avg_cpu = sum(point['Average'] for point in datapoints) / len(datapoints)
        max_cpu = max(point['Maximum'] for point in datapoints)
        
        return {
            'average_cpu': round(avg_cpu, 2),
            'maximum_cpu': round(max_cpu, 2),
            'datapoint_count': len(datapoints),
            'period_minutes': period // 60
        }
    except ClientError as e:
        # Log specific CloudWatch errors for debugging
        error_code = e.response['Error']['Code']
        return {'error': f'CloudWatch error: {error_code}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


def create_instance_entry(instance, cpu_metrics, region_name):
    """Create an instance entry with CPU utilization information"""
    instance_name = get_instance_name(instance)
    instance_type = instance['InstanceType']
    instance_id = instance['InstanceId']
    instance_state = instance['State']['Name']
    
    # Default values if metrics are not available
    avg_cpu = 0.0
    max_cpu = 0.0
    high_cpu_warning = False
    metrics_available = False
    error_message = None
    period_minutes = 5  # default
    
    if cpu_metrics:
        if 'error' in cpu_metrics:
            error_message = cpu_metrics['error']
        else:
            avg_cpu = cpu_metrics['average_cpu']
            max_cpu = cpu_metrics['maximum_cpu']
            high_cpu_warning = max_cpu >= HIGH_CPU_THRESHOLD
            metrics_available = True
            period_minutes = cpu_metrics.get('period_minutes', 5)
    
    entry = {
        'instanceName': instance_name,
        'instanceId': instance_id,
        'instanceType': instance_type,
        'state': instance_state,
        'region': region_name,
        'availabilityZone': instance['Placement']['AvailabilityZone'],
        'cpuUtilization': {
            'average': avg_cpu,
            'maximum': max_cpu,
            'metricsAvailable': metrics_available,
            'periodMinutes': period_minutes
        },
        'highCPUWarning': high_cpu_warning,
        'launchTime': instance.get('LaunchTime', 'N/A').isoformat() if instance.get('LaunchTime') else 'N/A'
    }
    
    if error_message:
        entry['cpuUtilization']['error'] = error_message
    
    return entry


def process_instances(instances, cloudwatch_client, region_name):
    """Process EC2 instances and analyze their CPU utilization"""
    instance_utilization_data = []
    
    for reservation in instances:
        for instance in reservation.get('Instances', []):
            # Only process instances that are not terminated
            if instance['State']['Name'] != 'terminated':
                # Get CPU metrics for running instances
                cpu_metrics = None
                if instance['State']['Name'] == 'running':
                    cpu_metrics = get_cpu_utilization_metrics(cloudwatch_client, instance['InstanceId'])
                
                instance_entry = create_instance_entry(instance, cpu_metrics, region_name)
                instance_utilization_data.append(instance_entry)
    
    return instance_utilization_data


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


def check_region_instances_utilization(session, region_name):
    """Check EC2 instances CPU utilization in a specific region"""
    try:
        ec2_client = session.client('ec2', region_name=region_name)
        cloudwatch_client = session.client('cloudwatch', region_name=region_name)
        
        # Get all EC2 instances in this region
        response = ec2_client.describe_instances()
        instances = response.get('Reservations', [])
        
        # Handle pagination if needed
        while 'NextToken' in response:
            response = ec2_client.describe_instances(NextToken=response['NextToken'])
            instances.extend(response.get('Reservations', []))
        
        return process_instances(instances, cloudwatch_client, region_name)
    except Exception:
        # Return empty list if region check fails
        return []


def create_success_response(all_instances_utilization, regions_checked):
    """Create success response structure"""
    total_instances = len(all_instances_utilization)
    high_cpu_instances = [inst for inst in all_instances_utilization if inst['highCPUWarning']]
    high_cpu_count = len(high_cpu_instances)
    running_instances = [inst for inst in all_instances_utilization if inst['state'] == 'running']
    running_count = len(running_instances)
    
    if total_instances == 0:
        message = f"No EC2 instances found across {regions_checked} regions."
    elif high_cpu_count == 0:
        message = f"All {running_count} running EC2 instances across {regions_checked} regions have normal CPU utilization."
    else:
        message = f"{high_cpu_count} out of {running_count} running EC2 instances across {regions_checked} regions have high CPU utilization (>{HIGH_CPU_THRESHOLD}%)."
    
    return {
        'status': 'Success',
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'total_instances': str(total_instances),
        'running_instances': str(running_count),
        'high_cpu_instances': str(high_cpu_count),
        'regions_checked': str(regions_checked),
        'details': {
            'instances': all_instances_utilization,
            'high_cpu_threshold': HIGH_CPU_THRESHOLD,
            'metric_period_hours': DEFAULT_LOOKBACK_HOURS,
            'recommendations': [
                HIGH_CPU_WARNING_MESSAGE
            ] if high_cpu_count > 0 else []
        }
    }


def check_ec2_utilization(profile_name=None, region_name=None, hours_back=DEFAULT_LOOKBACK_HOURS):
    """
    Check AWS EC2 instances CPU utilization across all regions or specific region
    
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
        
        all_instances_utilization = []
        regions_to_check = []
        
        # Set the global lookback period
        global DEFAULT_LOOKBACK_HOURS
        DEFAULT_LOOKBACK_HOURS = hours_back
        
        # Determine which regions to check
        if region_name:
            regions_to_check = [region_name]
        else:
            regions_to_check = get_all_regions(session)
        
        # Check each region
        for region in regions_to_check:
            try:
                instances_utilization = check_region_instances_utilization(session, region)
                all_instances_utilization.extend(instances_utilization)
            except Exception:
                # Continue with other regions if one fails
                continue
        
        regions_checked = len(regions_to_check)
        
        if len(all_instances_utilization) == 0:
            region_text = f"region {region_name}" if region_name else f"{regions_checked} regions"
            return {
                'status': 'Success',
                'message': f'No EC2 instances found in the specified {region_text}.',
                'timestamp': datetime.now().isoformat(),
                'total_instances': '0',
                'running_instances': '0',
                'high_cpu_instances': '0',
                'regions_checked': str(regions_checked),
                'details': {
                    'instances': [],
                    'high_cpu_threshold': HIGH_CPU_THRESHOLD,
                    'metric_period_hours': hours_back,
                    'recommendations': []
                }
            }
        
        # Generate result
        return create_success_response(all_instances_utilization, regions_checked)
        
    except NoCredentialsError:
        return {
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'timestamp': datetime.now().isoformat(),
            'total_instances': '0',
            'running_instances': '0',
            'high_cpu_instances': '0',
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
            'running_instances': '0',
            'high_cpu_instances': '0',
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
            'running_instances': '0',
            'high_cpu_instances': '0',
            'regions_checked': '0',
            'details': {
                'error_type': 'UnexpectedError',
                'error_message': str(e),
                'instances': [],
                'recommendations': []
            }
        }


def print_instance_utilization(instance, index):
    """Print detailed utilization information for a single instance"""
    warning_indicator = " ⚠️" if instance['highCPUWarning'] else ""
    print(f"  {index}. {instance['instanceName']} ({instance['instanceId']}){warning_indicator}")
    print(f"     Instance Type: {instance['instanceType']}")
    print(f"     State: {instance['state']}")
    print(f"     Region: {instance['region']}")
    
    cpu_util = instance['cpuUtilization']
    if cpu_util['metricsAvailable']:
        period_text = f" (Period: {cpu_util['periodMinutes']} min)" if 'periodMinutes' in cpu_util else ""
        print(f"     CPU Utilization - Average: {cpu_util['average']}%, Maximum: {cpu_util['maximum']}%{period_text}")
    elif 'error' in cpu_util:
        print(f"     CPU Utilization: Error - {cpu_util['error']}")
    else:
        print("     CPU Utilization: No metrics available (instance may be stopped or newly launched)")
    
    print(f"     Launch Time: {instance['launchTime']}")
    print()


def print_summary_output(result):
    """Print summary output for EC2 CPU utilization"""
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Instances: {result['total_instances']}")
    print(f"Running Instances: {result['running_instances']}")
    print(f"High CPU Instances: {result['high_cpu_instances']}")
    print(f"Regions Checked: {result['regions_checked']}")
    
    if result['details']['instances']:
        print(f"\nCPU Threshold: {result['details']['high_cpu_threshold']}%")
        print(f"Metric Period: Last {result['details']['metric_period_hours']} hours")
        print("\nInstance CPU Utilization Analysis:")
        for i, instance in enumerate(result['details']['instances'], 1):
            print_instance_utilization(instance, i)
    
    if result['details']['recommendations']:
        print("Recommendations:")
        for recommendation in result['details']['recommendations']:
            print(f"  - {recommendation}")


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check AWS EC2 instances CPU utilization')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--region', help='AWS region name', default=None)
    parser.add_argument('--hours', type=int, default=DEFAULT_LOOKBACK_HOURS,
                       help=f'Number of hours to look back for metrics (default: {DEFAULT_LOOKBACK_HOURS})')
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_ec2_utilization(
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
