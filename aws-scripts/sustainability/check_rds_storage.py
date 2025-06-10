"""
RDS Storage Usage and Trend Monitor
Monitors storage usage for RDS instances and Aurora clusters
"""

import boto3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any
import argparse
import sys

class RDSStorageMonitor:
    def __init__(self, region_name: str = None):
        """Initialize the RDS Storage Monitor"""
        self.session = boto3.Session()
        self.region_name = region_name or self.session.region_name or 'eu-west-2'
        self.rds_client = boto3.client('rds', region_name=self.region_name)
        self.cloudwatch = boto3.client('cloudwatch', region_name=self.region_name)
    
    def get_rds_instances(self) -> List[Dict[str, Any]]:
        """Get all RDS instances"""
        try:
            response = self.rds_client.describe_db_instances()
            return response['DBInstances']
        except Exception as e:
            print(f"Error fetching RDS instances: {e}")
            return []
    
    def get_aurora_clusters(self) -> List[Dict[str, Any]]:
        """Get all Aurora clusters"""
        try:
            response = self.rds_client.describe_db_clusters()
            return response['DBClusters']
        except Exception as e:
            print(f"Error fetching Aurora clusters: {e}")
            return []
    
    def get_cloudwatch_metrics(self, instance_name: str, metric_name: str, 
                             namespace: str = 'AWS/RDS', days: int = 7) -> List[Dict]:
        """Get CloudWatch metrics for storage usage"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=days)
            
            response = self.cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=[
                    {
                        'Name': 'DBInstanceIdentifier',
                        'Value': instance_name
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,  # 1 hour intervals
                Statistics=['Average', 'Maximum']
            )
            
            return sorted(response['Datapoints'], key=lambda x: x['Timestamp'])
        except Exception as e:
            print(f"Error fetching CloudWatch metrics for {instance_name}: {e}")
            return []
    
    def get_aurora_cluster_metrics(self, cluster_name: str, metric_name: str, days: int = 7) -> List[Dict]:
        """Get CloudWatch metrics for Aurora clusters"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=days)
            
            response = self.cloudwatch.get_metric_statistics(
                Namespace='AWS/RDS',
                MetricName=metric_name,
                Dimensions=[
                    {
                        'Name': 'DBClusterIdentifier',
                        'Value': cluster_name
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Average', 'Maximum']
            )
            
            return sorted(response['Datapoints'], key=lambda x: x['Timestamp'])
        except Exception as e:
            print(f"Error fetching Aurora cluster metrics for {cluster_name}: {e}")
            return []
    
    def get_provisioned_iops_metrics(self, instance_name: str, days: int = 7) -> List[Dict]:
        """Get Provisioned IOPS metrics for instances"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=days)
            
            response = self.cloudwatch.get_metric_statistics(
                Namespace='AWS/RDS',
                MetricName='ProvisionedThroughputExceeded',
                Dimensions=[
                    {
                        'Name': 'DBInstanceIdentifier',
                        'Value': instance_name
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Sum']
            )
            
            return sorted(response['Datapoints'], key=lambda x: x['Timestamp'])
        except Exception as e:
            print(f"Error fetching Provisioned IOPS metrics for {instance_name}: {e}")
            return []
    
    def analyze_storage_autoscaling(self, instance: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze storage auto-scaling configuration"""
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
    
    def analyze_provisioned_storage(self, instance: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze provisioned storage details"""
        allocated_storage = instance.get('AllocatedStorage', 0)  # Move this line up
        
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
        elif storage_type == 'io1' or storage_type == 'io2':
            storage_info["consistent_iops"] = True
        
        return storage_info

    def calculate_storage_trend(self, metrics: List[Dict]) -> Dict[str, Any]:
        """Calculate storage usage trend"""
        if len(metrics) < 2:
            return {"trend": "insufficient_data", "change_rate": 0}
        
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
            "first_value_gb": first_point / (1024 * 1024 * 1024),
            "last_value_gb": last_point / (1024 * 1024 * 1024)
        }
    
    def format_bytes(self, bytes_value: float) -> str:
        """Format bytes to human readable format"""
        if bytes_value is None or bytes_value == 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
    
    def analyze_rds_instance(self, instance: Dict[str, Any], days: int = 7) -> Dict[str, Any]:
        """Analyze storage usage for a single RDS instance"""
        instance_id = instance['DBInstanceIdentifier']
        
        # Get current storage info
        allocated_storage = instance.get('AllocatedStorage', 0)
        storage_type = instance.get('StorageType', 'Unknown')
        engine = instance.get('Engine', 'Unknown')
        
        # Get CloudWatch metrics
        free_storage_metrics = self.get_cloudwatch_metrics(
            instance_id, 'FreeStorageSpace', days=days
        )
        
        # Calculate used storage from free storage
        used_storage_data = []
        for metric in free_storage_metrics:
            used_bytes = (allocated_storage * 1024 * 1024 * 1024) - metric['Average']
            used_storage_data.append({
                'Timestamp': metric['Timestamp'],
                'Average': used_bytes
            })
        
        trend_analysis = self.calculate_storage_trend(used_storage_data)
        
        # Current usage
        current_free = free_storage_metrics[-1]['Average'] if free_storage_metrics else 0
        current_used = (allocated_storage * 1024 * 1024 * 1024) - current_free
        usage_percentage = (current_used / (allocated_storage * 1024 * 1024 * 1024)) * 100 if allocated_storage > 0 else 0
        
        # Analyze storage configuration
        autoscaling_info = self.analyze_storage_autoscaling(instance)
        provisioned_storage_info = self.analyze_provisioned_storage(instance)
        
        # Get IOPS metrics if available
        iops_exceeded_metrics = self.get_provisioned_iops_metrics(instance_id, days)
        iops_exceeded_count = sum(metric['Sum'] for metric in iops_exceeded_metrics)
        
        return {
            "instance_id": instance_id,
            "engine": engine,
            "storage_type": storage_type,
            "allocated_storage_gb": allocated_storage,
            "current_used_storage": self.format_bytes(current_used),
            "current_free_storage": self.format_bytes(current_free),
            "usage_percentage": f"{usage_percentage:.2f}%",
            "trend": trend_analysis,
            "autoscaling": autoscaling_info,
            "provisioned_storage": provisioned_storage_info,
            "iops_exceeded_events": iops_exceeded_count,
            "multi_az": instance.get('MultiAZ', False),
            "backup_retention_period": instance.get('BackupRetentionPeriod', 0)
        }
    
    def analyze_aurora_cluster(self, cluster: Dict[str, Any], days: int = 7) -> Dict[str, Any]:
        """Analyze storage usage for Aurora cluster"""
        cluster_id = cluster['DBClusterIdentifier']
        engine = cluster.get('Engine', 'Unknown')
        
        # Aurora storage metrics - using both VolumeBytesUsed and FreeLocalStorage
        volume_bytes_metrics = self.get_aurora_cluster_metrics(
            cluster_id, 'VolumeBytesUsed', days=days
        )
        
        free_local_storage_metrics = self.get_aurora_cluster_metrics(
            cluster_id, 'FreeLocalStorage', days=days
        )
        
        # Calculate trend based on VolumeBytesUsed (total storage growth)
        trend_analysis = self.calculate_storage_trend(volume_bytes_metrics)
        
        # Calculate free local storage trend
        free_storage_trend = self.calculate_storage_trend(free_local_storage_metrics)
        
        # Current usage
        current_volume_usage = volume_bytes_metrics[-1]['Average'] if volume_bytes_metrics else 0
        current_free_local = free_local_storage_metrics[-1]['Average'] if free_local_storage_metrics else 0
        
        # Aurora-specific storage information
        aurora_storage_info = {
            "storage_type": "Aurora",
            "auto_scaling": "Built-in (up to 128TB for Aurora MySQL, 64TB for Aurora PostgreSQL)",
            "storage_encrypted": cluster.get('StorageEncrypted', False),
            "backup_retention_period": cluster.get('BackupRetentionPeriod', 0),
            "multi_az": cluster.get('MultiAZ', False),
            "current_free_local_storage": self.format_bytes(current_free_local),
            "free_storage_trend": free_storage_trend
        }
        
        return {
            "cluster_id": cluster_id,
            "engine": engine,
            "storage_type": "Aurora",
            "current_storage_usage": self.format_bytes(current_volume_usage),
            "current_free_local_storage": self.format_bytes(current_free_local),
            "trend": trend_analysis,
            "free_storage_trend": free_storage_trend,
            "aurora_storage": aurora_storage_info
        }
    
    def generate_report(self, days: int = 7, output_format: str = 'json') -> None:
        """Generate comprehensive storage usage report"""
        print(f"🔍 Analyzing RDS Storage Usage (Last {days} days)")
        print(f"📍 Region: {self.region_name}")
        print("=" * 80)
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "region": self.region_name,
            "analysis_period_days": days,
            "rds_instances": [],
            "aurora_clusters": []
        }
        
        # Analyze RDS Instances
        print("\n📊 RDS Instances Analysis:")
        print("-" * 40)
        
        instances = self.get_rds_instances()
        for instance in instances:
            if instance.get('Engine', '').startswith('aurora'):
                continue  # Skip Aurora instances (handled in clusters)
            
            analysis = self.analyze_rds_instance(instance, days)
            report["rds_instances"].append(analysis)
            
            if output_format == 'console':
                self.print_instance_analysis(analysis)
        
        # Analyze Aurora Clusters
        print("\n🌟 Aurora Clusters Analysis:")
        print("-" * 40)
        
        clusters = self.get_aurora_clusters()
        for cluster in clusters:
            analysis = self.analyze_aurora_cluster(cluster, days)
            report["aurora_clusters"].append(analysis)
            
            if output_format == 'console':
                self.print_cluster_analysis(analysis)
        
        # Output report
        if output_format == 'json':
            print("\n📋 Full Report (JSON):")
            print(json.dumps(report, indent=2, default=str))
        
        # Summary
        total_instances = len(report["rds_instances"]) + len(report["aurora_clusters"])
        increasing_trend = sum(1 for inst in report["rds_instances"] + report["aurora_clusters"] 
                              if inst["trend"]["trend"] == "increasing")
        
        autoscaling_enabled = sum(1 for inst in report["rds_instances"] 
                                 if inst.get("autoscaling", {}).get("enabled", False))
        
        print(f"\n📈 Summary:")
        print(f"   Total Databases: {total_instances}")
        print(f"   Growing Storage: {increasing_trend}")
        print(f"   Stable Storage: {total_instances - increasing_trend}")
        print(f"   Auto-scaling Enabled: {autoscaling_enabled} RDS instances")
    
    def print_instance_analysis(self, analysis: Dict[str, Any]) -> None:
        """Print RDS instance analysis in console format"""
        print(f"🗄️  {analysis['instance_id']} ({analysis['engine']})")
        print(f"   Storage: {analysis['current_used_storage']} / {analysis['allocated_storage_gb']}GB "
              f"({analysis['usage_percentage']})")
        print(f"   Type: {analysis['provisioned_storage']['storage_type']}")
        
        # Provisioned IOPS info
        if analysis['provisioned_storage'].get('provisioned_iops'):
            print(f"   Provisioned IOPS: {analysis['provisioned_storage']['provisioned_iops']}")
        if analysis['provisioned_storage'].get('storage_throughput'):
            print(f"   Storage Throughput: {analysis['provisioned_storage']['storage_throughput']} MB/s")
        
        # Auto-scaling info
        if analysis['autoscaling']['enabled']:
            print(f"   🔄 Auto-scaling: Enabled (Max: {analysis['autoscaling']['max_allocated_storage']}GB)")
            print(f"   📈 Remaining capacity: {analysis['autoscaling'].get('remaining_autoscale_capacity_gb', 0)}GB")
        else:
            print(f"   🔄 Auto-scaling: Disabled")
        
        print(f"   📊 Trend: {analysis['trend']['trend']} "
              f"({analysis['trend']['change_rate_mb_per_day']:.2f} MB/day)")
        
        if analysis['iops_exceeded_events'] > 0:
            print(f"   ⚠️  IOPS Exceeded Events: {analysis['iops_exceeded_events']}")
        
        print()
    
    def print_cluster_analysis(self, analysis: Dict[str, Any]) -> None:
        """Print Aurora cluster analysis in console format"""
        print(f"⭐ {analysis['cluster_id']} ({analysis['engine']})")
        print(f"   Total Storage: {analysis['current_storage_usage']}")
        print(f"   Free Local Storage: {analysis['current_free_local_storage']}")
        print(f"   🔄 Auto-scaling: {analysis['aurora_storage']['auto_scaling']}")
        print(f"   📊 Volume Trend: {analysis['trend']['trend']} "
              f"({analysis['trend']['change_rate_mb_per_day']:.2f} MB/day)")
        print(f"   💾 Free Storage Trend: {analysis['free_storage_trend']['trend']} "
              f"({analysis['free_storage_trend']['change_rate_mb_per_day']:.2f} MB/day)")
        
        # Alert if free local storage is getting low
        if analysis['current_free_local_storage'] != "0 B":
            free_bytes = 0
            if 'GB' in analysis['current_free_local_storage']:
                free_gb = float(analysis['current_free_local_storage'].split()[0])
                if free_gb < 10:  # Less than 10GB free
                    print(f"   ⚠️  Low free local storage: {analysis['current_free_local_storage']}")
        
        print()

def main():
    parser = argparse.ArgumentParser(description='RDS Storage Usage Monitor')
    parser.add_argument('--region', '-r', help='AWS region', default=None)
    parser.add_argument('--days', '-d', type=int, default=7, 
                       help='Number of days to analyze (default: 7)')
    parser.add_argument('--format', '-f', choices=['json', 'console'], 
                       default='console', help='Output format')
    
    args = parser.parse_args()
    
    try:
        monitor = RDSStorageMonitor(args.region)
        monitor.generate_report(args.days, args.format)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()