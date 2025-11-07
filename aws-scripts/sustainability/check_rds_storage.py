#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Sustainability Pillar
RDS Storage Usage and Trend Monitor

This script monitors storage usage for RDS instances and Aurora clusters
across all AWS regions to identify optimization opportunities.
"""

import boto3
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError
import sys


def get_available_regions():
    """
    Get all AWS regions where RDS is available
    
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


def get_rds_instances(region_name: str) -> List[Dict[str, Any]]:
    """
    Get all RDS instances for a specific region
    
    Args:
        region_name: AWS region name
        
    Returns:
        list: List of RDS instance information
    """
    try:
        rds_client = boto3.client('rds', region_name=region_name)
        response = rds_client.describe_db_instances()
        return response['DBInstances']
    except ClientError:
        return []
    except Exception:
        return []


def get_aurora_clusters(region_name: str) -> List[Dict[str, Any]]:
    """
    Get all Aurora clusters for a specific region
    
    Args:
        region_name: AWS region name
        
    Returns:
        list: List of Aurora cluster information
    """
    try:
        rds_client = boto3.client('rds', region_name=region_name)
        response = rds_client.describe_db_clusters()
        return response['DBClusters']
    except ClientError:
        return []
    except Exception:
        return []


def get_cloudwatch_metrics(region_name: str, instance_name: str, metric_name: str, 
                          namespace: str = 'AWS/RDS', days: int = 7) -> List[Dict]:
    """
    Get CloudWatch metrics for storage usage
    
    Args:
        region_name: AWS region name
        instance_name: Instance or cluster name
        metric_name: CloudWatch metric name
        namespace: CloudWatch namespace
        days: Number of days to look back
        
    Returns:
        list: List of metric datapoints
    """
    try:
        cloudwatch = boto3.client('cloudwatch', region_name=region_name)
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days)
        
        # Try standard dimension first
        try:
            response = cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=[{
                    'Name': 'DBInstanceIdentifier',
                    'Value': instance_name
                }],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,  # 1 hour intervals
                Statistics=['Average', 'Maximum']
            )
            
            datapoints = sorted(response['Datapoints'], key=lambda x: x['Timestamp'])
            if datapoints:
                return datapoints
        except Exception:
            pass
        
        # Try daily periods if hourly fails
        try:
            response = cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=[{
                    'Name': 'DBInstanceIdentifier',
                    'Value': instance_name
                }],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,  # Daily intervals
                Statistics=['Average']
            )
            datapoints = sorted(response['Datapoints'], key=lambda x: x['Timestamp'])
            return datapoints
        except Exception:
            pass
            
        return []
        
    except Exception:
        return []


def get_aurora_cluster_metrics(region_name: str, cluster_name: str, metric_name: str, days: int = 7) -> List[Dict]:
    """
    Get CloudWatch metrics for Aurora clusters
    
    Args:
        region_name: AWS region name
        cluster_name: Aurora cluster name
        metric_name: CloudWatch metric name
        days: Number of days to look back
        
    Returns:
        list: List of metric datapoints
    """
    try:
        cloudwatch = boto3.client('cloudwatch', region_name=region_name)
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days)
        
        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/RDS',
            MetricName=metric_name,
            Dimensions=[{
                'Name': 'DBClusterIdentifier',
                'Value': cluster_name
            }],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,
            Statistics=['Average', 'Maximum']
        )
        
        return sorted(response['Datapoints'], key=lambda x: x['Timestamp'])
    except Exception:
        return []


def format_bytes(bytes_value: float) -> str:
    """
    Format bytes to human readable format
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        str: Human readable format
    """
    if bytes_value is None or bytes_value == 0:
        return "0 B"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def calculate_storage_trend(metrics: List[Dict]) -> Dict[str, Any]:
    """
    Calculate storage usage trend from metrics
    
    Args:
        metrics: List of CloudWatch metric datapoints
        
    Returns:
        dict: Trend analysis data
    """
    if len(metrics) < 2:
        return {
            "trend": "insufficient_data", 
            "change_rate_mb_per_day": 0,
            "change_rate": 0,
            "first_value_gb": 0,
            "last_value_gb": 0
        }
    
    # Get first and last data points
    first_point = metrics[0]['Average']
    last_point = metrics[-1]['Average']
    
    # Calculate change rate (bytes per day)
    time_diff = (metrics[-1]['Timestamp'] - metrics[0]['Timestamp']).total_seconds() / 86400  # days
    change_rate = (last_point - first_point) / time_diff if time_diff > 0 else 0
    
    # Determine trend
    if abs(change_rate) < 1024 * 1024:  # Less than 1MB per day
        trend = "stable"
    elif change_rate > 0:
        trend = "increasing"
    else:
        trend = "decreasing"
    
    return {
        "trend": trend,
        "change_rate_mb_per_day": change_rate / (1024 * 1024),
        "change_rate": change_rate,
        "first_value_gb": first_point / (1024 * 1024 * 1024),
        "last_value_gb": last_point / (1024 * 1024 * 1024)
    }


def analyze_storage_autoscaling(instance: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze storage auto-scaling configuration
    
    Args:
        instance: RDS instance information
        
    Returns:
        dict: Auto-scaling analysis data
    """
    autoscaling_info = {
        "enabled": False,
        "max_allocated_storage": None,
        "storage_threshold": None,
        "storage_encrypted": instance.get('StorageEncrypted', False)
    }
    
    # Check if storage auto-scaling is enabled
    max_allocated_storage = instance.get('MaxAllocatedStorage')
    if max_allocated_storage and max_allocated_storage > instance.get('AllocatedStorage', 0):
        autoscaling_info["enabled"] = True
        autoscaling_info["max_allocated_storage"] = max_allocated_storage
        
        # Calculate remaining auto-scaling capacity
        current_storage = instance.get('AllocatedStorage', 0)
        remaining_capacity = max_allocated_storage - current_storage
        autoscaling_info["remaining_autoscale_capacity_gb"] = remaining_capacity
        
        # Storage auto-scaling typically triggers at 90% usage
        autoscaling_info["storage_threshold"] = "90% (AWS default)"
    
    return autoscaling_info


def analyze_provisioned_storage(instance: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze provisioned storage details
    
    Args:
        instance: RDS instance information
        
    Returns:
        dict: Storage configuration analysis
    """
    allocated_storage = instance.get('AllocatedStorage', 0)
    
    storage_info = {
        "storage_type": instance.get('StorageType', 'Unknown'),
        "allocated_storage_gb": allocated_storage,
        "provisioned_iops": None,
        "iops_ratio": None,
        "storage_throughput": None
    }
    
    # Get IOPS information
    if instance.get('Iops'):
        storage_info["provisioned_iops"] = instance.get('Iops')
        if allocated_storage > 0:
            storage_info["iops_ratio"] = instance.get('Iops') / allocated_storage
    
    # Get storage throughput for gp3
    if instance.get('StorageThroughput'):
        storage_info["storage_throughput"] = instance.get('StorageThroughput')
    
    # Analyze storage type capabilities
    storage_type = instance.get('StorageType', '')
    if storage_type == 'gp2':
        storage_info["baseline_iops"] = min(3000, max(100, allocated_storage * 3))
        storage_info["burst_capable"] = allocated_storage <= 1000
    elif storage_type == 'gp3':
        storage_info["baseline_iops"] = 3000  # Default for gp3
        storage_info["baseline_throughput"] = 125  # Default MB/s for gp3
    elif storage_type in ('io1', 'io2'):
        storage_info["consistent_iops"] = True
    
    return storage_info


def analyze_rds_instance(region_name: str, instance: Dict[str, Any], days: int = 7) -> Dict[str, Any]:
    """
    Analyze storage usage for a single RDS instance
    
    Args:
        region_name: AWS region name
        instance: RDS instance information
        days: Number of days to analyze
        
    Returns:
        dict: Instance analysis data
    """
    instance_id = instance['DBInstanceIdentifier']
    
    # Get current storage info
    allocated_storage = instance.get('AllocatedStorage', 0)
    storage_type = instance.get('StorageType', 'Unknown')
    engine = instance.get('Engine', 'Unknown')
    
    # Get CloudWatch metrics
    free_storage_metrics = get_cloudwatch_metrics(
        region_name, instance_id, 'FreeStorageSpace', days=days
    )
    
    # Calculate current usage
    if free_storage_metrics:
        current_free_bytes = free_storage_metrics[-1]['Average']
        current_used_bytes = (allocated_storage * 1024 * 1024 * 1024) - current_free_bytes
        usage_percentage = (current_used_bytes / (allocated_storage * 1024 * 1024 * 1024)) * 100 if allocated_storage > 0 else 0
    else:
        current_free_bytes = 0
        current_used_bytes = 0
        usage_percentage = 0

    # Calculate used storage trend from free storage metrics
    used_storage_data = []
    for metric in free_storage_metrics:
        used_bytes = (allocated_storage * 1024 * 1024 * 1024) - metric['Average']
        used_storage_data.append({
            'Timestamp': metric['Timestamp'],
            'Average': used_bytes
        })
    
    trend_analysis = calculate_storage_trend(used_storage_data)
    
    # Analyze storage configuration
    autoscaling_info = analyze_storage_autoscaling(instance)
    provisioned_storage_info = analyze_provisioned_storage(instance)
    
    result = {
        "instance_id": instance_id,
        "engine": engine,
        "storage_type": storage_type,
        "allocated_storage_gb": allocated_storage,
        "current_used_storage": format_bytes(current_used_bytes),
        "current_free_storage": format_bytes(current_free_bytes),
        "usage_percentage": f"{usage_percentage:.2f}%",
        "trend": trend_analysis,
        "autoscaling": autoscaling_info,
        "provisioned_storage": provisioned_storage_info,
        "multi_az": instance.get('MultiAZ', False),
        "backup_retention_period": instance.get('BackupRetentionPeriod', 0),
        "region": region_name
    }
    
    # Check for issues that make this non-compliant
    non_compliant_reasons = []
    
    # High storage usage without autoscaling
    if usage_percentage > 80 and not autoscaling_info['enabled']:
        non_compliant_reasons.append(f"High storage usage ({usage_percentage:.1f}%) without auto-scaling")
    
    # Growing storage trend without autoscaling
    if trend_analysis['trend'] == 'increasing' and not autoscaling_info['enabled']:
        non_compliant_reasons.append("Increasing storage trend without auto-scaling")
    
    # Old storage types
    if storage_type in ['gp1', 'standard']:
        non_compliant_reasons.append(f"Using legacy storage type: {storage_type}")
    
    result['non_compliant'] = len(non_compliant_reasons) > 0
    result['non_compliant_reasons'] = non_compliant_reasons
    
    return result


def analyze_aurora_cluster(region_name: str, cluster: Dict[str, Any], days: int = 7) -> Dict[str, Any]:
    """
    Analyze storage usage for Aurora cluster
    
    Args:
        region_name: AWS region name
        cluster: Aurora cluster information
        days: Number of days to analyze
        
    Returns:
        dict: Cluster analysis data
    """
    cluster_id = cluster['DBClusterIdentifier']
    engine = cluster.get('Engine', 'Unknown')
    
    # Aurora storage metrics
    volume_bytes_metrics = get_aurora_cluster_metrics(
        region_name, cluster_id, 'VolumeBytesUsed', days=days
    )
    
    free_local_storage_metrics = get_aurora_cluster_metrics(
        region_name, cluster_id, 'FreeLocalStorage', days=days
    )
    
    # Calculate trend based on VolumeBytesUsed
    trend_analysis = calculate_storage_trend(volume_bytes_metrics)
    
    # Calculate free local storage trend
    free_storage_trend = calculate_storage_trend(free_local_storage_metrics)
    
    # Current usage
    current_volume_usage = volume_bytes_metrics[-1]['Average'] if volume_bytes_metrics else 0
    current_free_local = free_local_storage_metrics[-1]['Average'] if free_local_storage_metrics else 0
    
    result = {
        "cluster_id": cluster_id,
        "engine": engine,
        "storage_type": "Aurora",
        "current_storage_usage": format_bytes(current_volume_usage),
        "current_free_local_storage": format_bytes(current_free_local),
        "trend": trend_analysis,
        "free_storage_trend": free_storage_trend,
        "storage_encrypted": cluster.get('StorageEncrypted', False),
        "backup_retention_period": cluster.get('BackupRetentionPeriod', 0),
        "multi_az": cluster.get('MultiAZ', False),
        "region": region_name
    }
    
    # Check for issues
    non_compliant_reasons = []
    
    # Low free local storage
    if current_free_local > 0:
        free_gb = current_free_local / (1024 * 1024 * 1024)
        if free_gb < 10:  # Less than 10GB free
            non_compliant_reasons.append(f"Low free local storage: {format_bytes(current_free_local)}")
    
    result['non_compliant'] = len(non_compliant_reasons) > 0
    result['non_compliant_reasons'] = non_compliant_reasons
    
    return result


def check_rds_storage_for_region(region_name: str, days: int = 7) -> Dict[str, Any]:
    """
    Check RDS storage for a specific region
    
    Args:
        region_name: AWS region name
        days: Number of days to analyze
        
    Returns:
        dict: Region analysis data
    """
    try:
        # Get instances and clusters
        instances = get_rds_instances(region_name)
        clusters = get_aurora_clusters(region_name)
        
        region_results = []
        
        # Analyze RDS instances (excluding Aurora instances)
        for instance in instances:
            if instance.get('Engine', '').startswith('aurora'):
                continue  # Skip Aurora instances (handled in clusters)
            
            try:
                analysis = analyze_rds_instance(region_name, instance, days)
                region_results.append(analysis)
            except Exception as e:
                error_item = {
                    "instance_id": instance.get('DBInstanceIdentifier', 'Unknown'),
                    "error": str(e),
                    "region": region_name,
                    "resource_type": "rds_instance"
                }
                region_results.append(error_item)
        
        # Analyze Aurora clusters
        for cluster in clusters:
            try:
                analysis = analyze_aurora_cluster(region_name, cluster, days)
                region_results.append(analysis)
            except Exception as e:
                error_item = {
                    "cluster_id": cluster.get('DBClusterIdentifier', 'Unknown'),
                    "error": str(e),
                    "region": region_name,
                    "resource_type": "aurora_cluster"
                }
                region_results.append(error_item)
        
        return {
            "region": region_name,
            "results": region_results,
            "error": None
        }
        
    except Exception as e:
        return {
            "region": region_name,
            "results": [],
            "error": str(e)
        }


def check_rds_storage_all_regions(days: int = 7, max_workers: int = 5) -> Dict[str, Any]:
    """
    Check RDS storage usage across all AWS regions
    
    Args:
        days: Number of days to analyze for trends
        max_workers: Maximum number of concurrent workers
        
    Returns:
        dict: Complete analysis results
    """
    try:
        regions = get_available_regions()
        all_results = []
        error_regions = []
        
        # Use ThreadPoolExecutor for parallel region checking
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_region = {
                executor.submit(check_rds_storage_for_region, region, days): region 
                for region in regions
            }
            
            for future in as_completed(future_to_region):
                region = future_to_region[future]
                try:
                    result = future.result()
                    if result['error']:
                        error_regions.append(result)
                    else:
                        all_results.extend(result['results'])
                except Exception as e:
                    error_regions.append({
                        "region": region,
                        "error": str(e),
                        "results": []
                    })
        
        # Categorize results
        non_compliant_items = []
        compliant_items = []
        error_items = []
        
        for item in all_results:
            if 'error' in item:
                error_items.append(item)
            elif item.get('non_compliant', False):
                non_compliant_items.append(item)
            else:
                compliant_items.append(item)
        
        # Calculate statistics
        total_databases = len(all_results)
        non_compliant_count = len(non_compliant_items)
        compliant_count = len(compliant_items)
        error_count = len(error_items)
        
        # Count autoscaling adoption (RDS instances only)
        rds_instances = [item for item in all_results if 'instance_id' in item and 'error' not in item]
        autoscaling_enabled = len([item for item in rds_instances if item.get('autoscaling', {}).get('enabled', False)])
        
        # Count growing storage
        growing_storage = len([item for item in all_results if 'error' not in item and item.get('trend', {}).get('trend') == 'increasing'])
        
        return {
            'total_regions_checked': len(regions),
            'total_databases': total_databases,
            'total_rds_instances': len(rds_instances),
            'total_aurora_clusters': len([item for item in all_results if 'cluster_id' in item and 'error' not in item]),
            'compliant_databases': compliant_count,
            'non_compliant_databases': non_compliant_count,
            'error_databases': error_count,
            'autoscaling_enabled_instances': autoscaling_enabled,
            'databases_with_growing_storage': growing_storage,
            'analysis_period_days': days,
            'all_results': all_results,
            'non_compliant_items': non_compliant_items,
            'error_items': error_items,
            'error_regions': error_regions
        }
        
    except Exception as e:
        raise RuntimeError(f"Failed to check RDS storage across regions: {str(e)}") from e


def determine_rds_storage_status(stats: Dict[str, Any]) -> tuple:
    """
    Determine overall status based on RDS storage analysis statistics
    
    Args:
        stats: Dictionary containing analysis statistics
        
    Returns:
        tuple: (status, message)
    """
    total_databases = stats['total_databases']
    non_compliant_count = stats['non_compliant_databases']
    error_count = stats['error_databases']
    
    if error_count > 0 and total_databases == 0:
        return ('Error', f'Failed to analyze RDS storage: {error_count} regions had errors')
    elif total_databases == 0:
        return ('Pass', 'No RDS databases found in any region')
    elif non_compliant_count == 0:
        return ('Pass', f'All {total_databases} RDS databases have optimal storage configuration')
    elif non_compliant_count == total_databases:
        return ('Fail', f'All {total_databases} RDS databases have storage optimization opportunities')
    else:
        return ('Warning', f'{non_compliant_count} out of {total_databases} RDS databases have storage optimization opportunities')


def check_rds_storage(profile_name: Optional[str] = None, days: int = 7, max_workers: int = 5) -> Dict[str, Any]:
    """
    Main function to check RDS storage optimization across all regions
    
    Args:
        profile_name: AWS profile name (optional)
        days: Number of days to analyze for trends
        max_workers: Maximum number of concurrent workers
        
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
            # Perform the RDS storage check
            result = check_rds_storage_all_regions(days, max_workers)
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        status, message = determine_rds_storage_status(result)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'rds_storage_optimization',
            'total_regions_checked': result['total_regions_checked'],
            'total_databases': result['total_databases'],
            'total_rds_instances': result['total_rds_instances'],
            'total_aurora_clusters': result['total_aurora_clusters'],
            'compliant_databases': result['compliant_databases'],
            'non_compliant_databases': result['non_compliant_databases'],
            'error_databases': result['error_databases'],
            'autoscaling_enabled_instances': result['autoscaling_enabled_instances'],
            'databases_with_growing_storage': result['databases_with_growing_storage'],
            'analysis_period_days': result['analysis_period_days'],
            'non_compliant_items': result['non_compliant_items']
        }
        
        return final_result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found or invalid',
            'check_type': 'rds_storage_optimization',
            'non_compliant_items': []
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': 'Insufficient permissions to check RDS storage',
                'check_type': 'rds_storage_optimization',
                'non_compliant_items': []
            }
        else:
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': f'AWS API error: {error_code}',
                'check_type': 'rds_storage_optimization',
                'non_compliant_items': []
            }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error during RDS storage check: {str(e)}',
            'check_type': 'rds_storage_optimization',
            'non_compliant_items': []
        }


# Console output functions for backwards compatibility
def print_database_details(db_info: Dict[str, Any], index: int) -> None:
    """Print detailed information about a database"""
    if 'instance_id' in db_info:
        print(f"  {index}. RDS Instance: {db_info['instance_id']}")
        print(f"     Engine: {db_info['engine']}")
        print(f"     Storage: {db_info['current_used_storage']} / {db_info['allocated_storage_gb']}GB ({db_info['usage_percentage']})")
        print(f"     Type: {db_info['provisioned_storage']['storage_type']}")
        if db_info['autoscaling']['enabled']:
            print(f"     Auto-scaling: Enabled (Max: {db_info['autoscaling']['max_allocated_storage']}GB)")
        else:
            print("     Auto-scaling: Disabled")
        print(f"     Trend: {db_info['trend']['trend']} ({db_info['trend']['change_rate_mb_per_day']:.2f} MB/day)")
    elif 'cluster_id' in db_info:
        print(f"  {index}. Aurora Cluster: {db_info['cluster_id']}")
        print(f"     Engine: {db_info['engine']}")
        print(f"     Storage: {db_info['current_storage_usage']}")
        print(f"     Trend: {db_info['trend']['trend']} ({db_info['trend']['change_rate_mb_per_day']:.2f} MB/day)")
    
    if db_info.get('non_compliant_reasons'):
        print(f"     Issues: {', '.join(db_info['non_compliant_reasons'])}")
    
    print(f"     Region: {db_info['region']}")


def print_basic_summary(result: Dict[str, Any]) -> None:
    """Print basic summary information"""
    print("RDS Storage Analysis Summary")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Analysis Period: {result.get('analysis_period_days', 'N/A')} days")
    print(f"Regions Checked: {result.get('total_regions_checked', 'N/A')}")
    print(f"Total Databases: {result.get('total_databases', 'N/A')}")
    print(f"  RDS Instances: {result.get('total_rds_instances', 'N/A')}")
    print(f"  Aurora Clusters: {result.get('total_aurora_clusters', 'N/A')}")
    print(f"Compliant: {result.get('compliant_databases', 'N/A')}")
    print(f"Non-Compliant: {result.get('non_compliant_databases', 'N/A')}")
    print(f"Auto-scaling Enabled: {result.get('autoscaling_enabled_instances', 'N/A')} instances")
    print(f"Growing Storage: {result.get('databases_with_growing_storage', 'N/A')} databases")


def print_non_compliant_databases(databases: List[Dict[str, Any]]) -> None:
    """Print details of non-compliant databases"""
    if databases:
        print(f"\nDatabases with Storage Optimization Opportunities ({len(databases)}):")
        for i, db in enumerate(databases, 1):
            print_database_details(db, i)


def print_summary_output(result: Dict[str, Any]) -> None:
    """Print human-readable summary output"""
    print_basic_summary(result)
    
    non_compliant_items = result.get('non_compliant_items', [])
    print_non_compliant_databases(non_compliant_items)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check RDS storage optimization opportunities")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    parser.add_argument('--days', type=int, default=7,
                       help='Number of days to analyze for storage trends (default: 7)')
    parser.add_argument('--max-workers', type=int, default=5,
                       help='Maximum number of concurrent workers (default: 5)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_rds_storage(
        profile_name=args.profile,
        days=args.days,
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
