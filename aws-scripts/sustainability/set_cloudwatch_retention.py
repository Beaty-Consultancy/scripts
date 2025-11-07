#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Sustainability Pillar
CloudWatch Log Group Retention Policy Setter

This script sets retention policies for CloudWatch log groups that don't have
retention policies configured across all AWS regions.
"""

import boto3
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError
import sys


def get_available_regions():
    """
    Get all AWS regions where CloudWatch Logs is available
    
    Returns:
        list: List of AWS region names
    """
    try:
        ec2_client = boto3.client('ec2', region_name='us-east-1')
        response = ec2_client.describe_regions()
        return [region['RegionName'] for region in response['Regions']]
    except ClientError as e:
        raise ClientError(e.response, e.operation_name) from e
    except Exception as e:
        raise RuntimeError(f"Failed to get AWS regions: {str(e)}") from e


def get_log_groups_without_retention(region_name: str) -> List[Dict[str, Any]]:
    """
    Get all log groups without retention policy for a specific region
    
    Args:
        region_name: AWS region name
        
    Returns:
        list: List of log group information without retention policies
    """
    try:
        logs_client = boto3.client('logs', region_name=region_name)
        log_groups_without_retention = []
        
        paginator = logs_client.get_paginator('describe_log_groups')
        
        for page in paginator.paginate():
            for log_group in page['logGroups']:
                # Check if retention policy is not set
                if 'retentionInDays' not in log_group:
                    log_group_info = {
                        'log_group_name': log_group['logGroupName'],
                        'stored_bytes': log_group.get('storedBytes', 0),
                        'creation_time': log_group.get('creationTime', 0),
                        'region': region_name
                    }
                    log_groups_without_retention.append(log_group_info)
        
        return log_groups_without_retention
    except ClientError:
        return []
    except Exception:
        return []


def set_retention_policy(region_name: str, log_group_name: str, retention_days: int) -> Dict[str, Any]:
    """
    Set retention policy for a specific log group
    
    Args:
        region_name: AWS region name
        log_group_name: Name of the log group
        retention_days: Retention period in days
        
    Returns:
        dict: Result of the operation
    """
    try:
        logs_client = boto3.client('logs', region_name=region_name)
        logs_client.put_retention_policy(
            logGroupName=log_group_name,
            retentionInDays=retention_days
        )
        return {
            'success': True,
            'message': f'Successfully set retention to {retention_days} days'
        }
    except ClientError as e:
        return {
            'success': False,
            'message': f'AWS API error: {e.response["Error"]["Code"]} - {e.response["Error"]["Message"]}'
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'Unexpected error: {str(e)}'
        }


def format_bytes(bytes_value: int) -> str:
    """
    Convert bytes to human readable format
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        str: Human readable format
    """
    if bytes_value == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = bytes_value
    unit_index = 0
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    return f"{size:.2f} {units[unit_index]}"


def process_log_groups_in_region(region_name: str, retention_days: int, dry_run: bool = False) -> Dict[str, Any]:
    """
    Process log groups in a specific region to set retention policies
    
    Args:
        region_name: AWS region name
        retention_days: Retention period in days
        dry_run: If True, don't make actual changes
        
    Returns:
        dict: Region processing results
    """
    try:
        # Get log groups without retention
        log_groups = get_log_groups_without_retention(region_name)
        
        results = []
        successful_count = 0
        failed_count = 0
        
        for log_group in log_groups:
            log_group_name = log_group['log_group_name']
            stored_bytes = log_group['stored_bytes']
            
            if dry_run:
                # Dry run mode - just simulate the action
                result = {
                    'log_group_name': log_group_name,
                    'region': region_name,
                    'stored_bytes': stored_bytes,
                    'stored_bytes_readable': format_bytes(stored_bytes),
                    'action': 'dry_run',
                    'success': True,
                    'message': f'DRY RUN: Would set retention to {retention_days} days',
                    'retention_days': retention_days
                }
                successful_count += 1
            else:
                # Actually set the retention policy
                operation_result = set_retention_policy(region_name, log_group_name, retention_days)
                
                result = {
                    'log_group_name': log_group_name,
                    'region': region_name,
                    'stored_bytes': stored_bytes,
                    'stored_bytes_readable': format_bytes(stored_bytes),
                    'action': 'set_retention',
                    'success': operation_result['success'],
                    'message': operation_result['message'],
                    'retention_days': retention_days if operation_result['success'] else None
                }
                
                if operation_result['success']:
                    successful_count += 1
                else:
                    failed_count += 1
            
            results.append(result)
        
        return {
            'region': region_name,
            'total_log_groups': len(log_groups),
            'successful_updates': successful_count,
            'failed_updates': failed_count,
            'log_groups': results,
            'error': None
        }
        
    except Exception as e:
        return {
            'region': region_name,
            'total_log_groups': 0,
            'successful_updates': 0,
            'failed_updates': 0,
            'log_groups': [],
            'error': str(e)
        }


def set_cloudwatch_retention_all_regions(retention_days: int, dry_run: bool = False, 
                                        max_workers: int = 5) -> Dict[str, Any]:
    """
    Set CloudWatch log group retention policies across all AWS regions
    
    Args:
        retention_days: Retention period in days
        dry_run: If True, don't make actual changes
        max_workers: Maximum number of concurrent workers
        
    Returns:
        dict: Complete operation results
    """
    try:
        regions = get_available_regions()
        all_results = []
        error_regions = []
        
        # Use ThreadPoolExecutor for parallel region processing
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_region = {
                executor.submit(process_log_groups_in_region, region, retention_days, dry_run): region 
                for region in regions
            }
            
            for future in as_completed(future_to_region):
                region = future_to_region[future]
                try:
                    result = future.result()
                    if result['error']:
                        error_regions.append(result)
                    else:
                        all_results.extend(result['log_groups'])
                except Exception as e:
                    error_regions.append({
                        "region": region,
                        "error": str(e),
                        "log_groups": []
                    })
        
        # Calculate statistics
        total_log_groups = len(all_results)
        successful_updates = len([item for item in all_results if item.get('success', False)])
        failed_updates = len([item for item in all_results if not item.get('success', False)])
        
        # Calculate total storage impact
        total_storage_bytes = sum(item.get('stored_bytes', 0) for item in all_results if item.get('success', False))
        
        return {
            'total_regions_checked': len(regions),
            'total_log_groups_processed': total_log_groups,
            'successful_updates': successful_updates,
            'failed_updates': failed_updates,
            'total_storage_affected_bytes': total_storage_bytes,
            'total_storage_affected_readable': format_bytes(total_storage_bytes),
            'retention_days': retention_days,
            'dry_run': dry_run,
            'all_results': all_results,
            'processed_items': all_results,  # For consistency with check scripts
            'error_regions': error_regions
        }
        
    except Exception as e:
        raise RuntimeError(f"Failed to set CloudWatch retention across regions: {str(e)}") from e


def determine_retention_operation_status(stats: Dict[str, Any]) -> tuple:
    """
    Determine overall status based on retention operation statistics
    
    Args:
        stats: Dictionary containing operation statistics
        
    Returns:
        tuple: (status, message)
    """
    total_processed = stats['total_log_groups_processed']
    successful = stats['successful_updates']
    failed = stats['failed_updates']
    dry_run = stats['dry_run']
    
    if total_processed == 0:
        return ('Pass', 'No log groups without retention policies found')
    elif failed == 0:
        if dry_run:
            return ('Pass', f'DRY RUN: Would successfully set retention for all {total_processed} log groups')
        else:
            return ('Pass', f'Successfully set retention policies for all {total_processed} log groups')
    elif successful == 0:
        if dry_run:
            return ('Error', f'DRY RUN validation failed for all {total_processed} log groups')
        else:
            return ('Error', f'Failed to set retention policies for all {total_processed} log groups')
    else:
        if dry_run:
            return ('Warning', f'DRY RUN: Would succeed for {successful} out of {total_processed} log groups')
        else:
            return ('Warning', f'Set retention for {successful} out of {total_processed} log groups ({failed} failed)')


def set_cloudwatch_retention(profile_name: Optional[str] = None, retention_days: int = 400, 
                            dry_run: bool = False, max_workers: int = 5) -> Dict[str, Any]:
    """
    Main function to set CloudWatch log group retention policies across all regions
    
    Args:
        profile_name: AWS profile name (optional)
        retention_days: Retention period in days
        dry_run: If True, don't make actual changes
        max_workers: Maximum number of concurrent workers
        
    Returns:
        dict: Complete operation results in JSON format
    """
    timestamp = datetime.now(timezone.utc).isoformat() + 'Z'
    
    try:
        # Create session
        session = boto3.Session(profile_name=profile_name)
        
        # Override the default client creation for this specific operation
        original_client = boto3.client
        boto3.client = lambda service, **kwargs: session.client(service, **kwargs)
        
        try:
            # Perform the retention setting operation
            result = set_cloudwatch_retention_all_regions(retention_days, dry_run, max_workers)
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        status, message = determine_retention_operation_status(result)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'cloudwatch_retention_setter',
            'operation_type': 'dry_run' if dry_run else 'set_retention',
            'total_regions_checked': result['total_regions_checked'],
            'total_log_groups_processed': result['total_log_groups_processed'],
            'successful_updates': result['successful_updates'],
            'failed_updates': result['failed_updates'],
            'total_storage_affected_bytes': result['total_storage_affected_bytes'],
            'total_storage_affected_readable': result['total_storage_affected_readable'],
            'retention_days': result['retention_days'],
            'dry_run': result['dry_run'],
            'processed_items': result['processed_items']
        }
        
        return final_result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found or invalid',
            'check_type': 'cloudwatch_retention_setter',
            'processed_items': []
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': 'Insufficient permissions to set CloudWatch log retention',
                'check_type': 'cloudwatch_retention_setter',
                'processed_items': []
            }
        else:
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': f'AWS API error: {error_code}',
                'check_type': 'cloudwatch_retention_setter',
                'processed_items': []
            }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error during retention setting: {str(e)}',
            'check_type': 'cloudwatch_retention_setter',
            'processed_items': []
        }


# Console output functions for backwards compatibility
def print_log_group_details(log_group_info: Dict[str, Any], index: int) -> None:
    """Print detailed information about a log group operation"""
    print(f"  {index}. Log Group: {log_group_info['log_group_name']}")
    print(f"     Region: {log_group_info['region']}")
    print(f"     Storage: {log_group_info['stored_bytes_readable']}")
    print(f"     Action: {log_group_info['action']}")
    
    if log_group_info['success']:
        if log_group_info['action'] == 'dry_run':
            print(f"     Status: ✅ {log_group_info['message']}")
        else:
            print(f"     Status: ✅ Set to {log_group_info['retention_days']} days")
    else:
        print(f"     Status: ❌ {log_group_info['message']}")


def print_basic_summary(result: Dict[str, Any]) -> None:
    """Print basic summary information"""
    print("CloudWatch Log Retention Policy Setter Summary")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Operation: {result.get('operation_type', 'unknown')}")
    print(f"Retention Days: {result.get('retention_days', 'N/A')}")
    print(f"Regions Checked: {result.get('total_regions_checked', 'N/A')}")
    print(f"Log Groups Processed: {result.get('total_log_groups_processed', 'N/A')}")
    print(f"Successful Updates: {result.get('successful_updates', 'N/A')}")
    print(f"Failed Updates: {result.get('failed_updates', 'N/A')}")
    print(f"Storage Affected: {result.get('total_storage_affected_readable', 'N/A')}")


def print_processed_log_groups(log_groups: List[Dict[str, Any]]) -> None:
    """Print details of processed log groups"""
    if log_groups:
        print(f"\nProcessed Log Groups ({len(log_groups)}):")
        for i, log_group in enumerate(log_groups, 1):
            print_log_group_details(log_group, i)


def print_summary_output(result: Dict[str, Any]) -> None:
    """Print human-readable summary output"""
    print_basic_summary(result)
    
    processed_items = result.get('processed_items', [])
    print_processed_log_groups(processed_items)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Set CloudWatch log group retention policies")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    parser.add_argument('--retention-days', type=int, default=400,
                       help='Retention period in days (default: 400)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be changed without making changes')
    parser.add_argument('--max-workers', type=int, default=5,
                       help='Maximum number of concurrent workers (default: 5)')
    
    args = parser.parse_args()
    
    # Execute the operation
    result = set_cloudwatch_retention(
        profile_name=args.profile,
        retention_days=args.retention_days,
        dry_run=args.dry_run,
        max_workers=args.max_workers
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
