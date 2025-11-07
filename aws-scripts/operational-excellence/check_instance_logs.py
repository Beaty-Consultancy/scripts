#!/usr/bin/env python3
"""
Instance Log Activity Checker

Simple script to check if EC2 instances are outputting logs to CloudWatch.
"""

import boto3
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError


def get_enabled_regions() -> List[str]:
    """Get list of enabled AWS regions."""
    try:
        ec2_client = boto3.client('ec2', region_name='eu-west-2')
        regions_response = ec2_client.describe_regions()
        return [region['RegionName'] for region in regions_response['Regions']]
    except Exception:
        # Fallback to common regions if describe_regions fails
        return [
            'eu-west-2', 'us-west-2', 'eu-west-1', 'eu-central-1', 
            'ap-southeast-1', 'ap-northeast-1'
        ]


def check_instance_logs_in_region(region: str, hours_back: int = 48) -> List[Dict[str, Any]]:
    """
    Check instance log activity in a specific region.
    
    Args:
        region: AWS region to check
        hours_back: Hours back to check for log activity
        
    Returns:
        List of instances without recent logs
    """
    instances_without_logs = []
    
    try:
        ec2_client = boto3.client('ec2', region_name=region)
        logs_client = boto3.client('logs', region_name=region)
        
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        cutoff_timestamp = int(cutoff_time.timestamp() * 1000)
        
        # Get running instances
        instances_response = ec2_client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        
        for reservation in instances_response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_type = instance.get('InstanceType', 'unknown')
                
                # Check for log activity
                has_recent_logs = check_instance_log_activity(
                    logs_client, instance_id, cutoff_timestamp
                )
                
                if not has_recent_logs:
                    instances_without_logs.append({
                        'instance_id': instance_id,
                        'instance_type': instance_type,
                        'region': region,
                        'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
                    })
    
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code not in ['UnauthorizedOperation', 'AccessDenied']:
            instances_without_logs.append({
                'region': region,
                'error': f'Failed to check region {region}: {error_code}',
                'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
            })
    
    return instances_without_logs


def check_instance_log_activity(logs_client, instance_id: str, cutoff_timestamp: int) -> bool:
    """
    Check if an instance has recent log activity.
    
    Args:
        logs_client: CloudWatch Logs client
        instance_id: EC2 instance ID
        cutoff_timestamp: Timestamp cutoff for recent logs
        
    Returns:
        True if instance has recent logs, False otherwise
    """
    try:
        # Common log group patterns
        log_group_patterns = [
            f"/aws/ec2/{instance_id}",
            f"/var/log/messages-{instance_id}",
            f"/aws/ec2/instance/{instance_id}",
            instance_id
        ]
        
        # Get all log groups and check for instance association
        log_groups_response = logs_client.describe_log_groups()
        
        for log_group in log_groups_response.get('logGroups', []):
            log_group_name = log_group['logGroupName']
            
            # Check if log group is associated with this instance
            if (instance_id in log_group_name or 
                any(pattern in log_group_name for pattern in log_group_patterns)):
                
                try:
                    # Check for recent log streams
                    streams_response = logs_client.describe_log_streams(
                        logGroupName=log_group_name,
                        orderBy='LastEventTime',
                        descending=True,
                        limit=5
                    )
                    
                    for stream in streams_response.get('logStreams', []):
                        last_event_time = stream.get('lastEventTime', 0)
                        if last_event_time > cutoff_timestamp:
                            return True
                            
                except ClientError:
                    # Skip if we can't access log streams
                    continue
    
    except ClientError:
        # Skip if we can't access log groups
        pass
    
    return False


def check_instance_logs_all_regions(max_workers: int = 5, hours_back: int = 48) -> Dict[str, Any]:
    """
    Check instance log activity across all regions.
    
    Args:
        max_workers: Maximum number of concurrent workers
        hours_back: Hours back to check for log activity
        
    Returns:
        Dictionary containing aggregated results
    """
    regions = get_enabled_regions()
    all_instances_without_logs = []
    total_regions_checked = 0
    error_count = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit tasks for all regions
        future_to_region = {
            executor.submit(check_instance_logs_in_region, region, hours_back): region 
            for region in regions
        }
        
        # Collect results
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            total_regions_checked += 1
            
            try:
                region_results = future.result()
                if region_results:
                    # Check if any results contain errors
                    error_results = [item for item in region_results if 'error' in item]
                    
                    error_count += len(error_results)
                    all_instances_without_logs.extend(region_results)
                
            except Exception as e:
                error_count += 1
                all_instances_without_logs.append({
                    'region': region,
                    'error': f'Failed to process region {region}: {str(e)}',
                    'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
                })
    
    # Filter out error entries for statistics
    valid_instances = [item for item in all_instances_without_logs if 'error' not in item]
    
    return {
        'total_regions_checked': total_regions_checked,
        'instances_without_logs': len(valid_instances),
        'error_count': error_count,
        'instance_items': all_instances_without_logs
    }


def determine_instance_logs_status(stats: Dict[str, Any]) -> Tuple[str, str]:
    """
    Determine the overall status based on instance log check results.
    
    Args:
        stats: Dictionary containing check statistics
        
    Returns:
        Tuple of (status, message)
    """
    instances_without_logs = stats['instances_without_logs']
    error_count = stats['error_count']
    total_regions = stats['total_regions_checked']
    
    if error_count > 0:
        if error_count == total_regions:
            return 'Error', f'Failed to check instance logs in all {total_regions} regions'
        else:
            return 'Warning', f'Failed to check instance logs in {error_count} out of {total_regions} regions'
    
    if instances_without_logs == 0:
        return 'Pass', 'All instances are outputting logs to CloudWatch'
    else:
        return 'Fail', f'Found {instances_without_logs} instances without recent log activity'


def check_instance_logs(profile_name: Optional[str] = None, max_workers: int = 5, hours_back: int = 48) -> Dict[str, Any]:
    """
    Main function to check instance log activity across all regions
    
    Args:
        profile_name: AWS profile name (optional)
        max_workers: Maximum number of concurrent workers
        hours_back: Hours back to check for log activity
        
    Returns:
        dict: Complete check results in JSON format
    """
    timestamp = datetime.now(timezone.utc).isoformat() + 'Z'
    
    try:
        # Create session
        session = boto3.Session(profile_name=profile_name)
        
        # Override the default client creation for this specific check
        original_client = boto3.client
        boto3.client = lambda service, **kwargs: session.client(service, **kwargs)
        
        try:
            # Perform the instance logs check
            result = check_instance_logs_all_regions(max_workers, hours_back)
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        status, message = determine_instance_logs_status(result)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'instance_logs',
            'hours_checked': hours_back,
            'total_regions_checked': result['total_regions_checked'],
            'instances_without_logs': result['instances_without_logs'],
            'error_count': result['error_count'],
            'non_compliant_items': result['instance_items']
        }
        
        return final_result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found or invalid',
            'check_type': 'instance_logs',
            'non_compliant_items': []
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': 'Insufficient permissions to check instance logs',
                'check_type': 'instance_logs',
                'non_compliant_items': []
            }
        else:
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': f'AWS API error: {error_code}',
                'check_type': 'instance_logs',
                'non_compliant_items': []
            }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error during instance logs check: {str(e)}',
            'check_type': 'instance_logs',
            'non_compliant_items': []
        }


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check if EC2 instances are outputting logs")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--hours', type=int, default=48, 
                       help='Hours back to check for log activity (default: 48)')
    parser.add_argument('--max-workers', type=int, default=5,
                       help='Maximum number of concurrent workers (default: 5)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_instance_logs(
        profile_name=args.profile,
        max_workers=args.max_workers,
        hours_back=args.hours
    )
    
    # Output JSON
    print(json.dumps(result, indent=2))
    
    # Exit with appropriate code
    if result['status'] == 'Error':
        sys.exit(1)
    elif result['status'] == 'Fail':
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
