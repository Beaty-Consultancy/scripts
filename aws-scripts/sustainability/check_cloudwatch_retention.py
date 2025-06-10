import boto3
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import sys

def get_all_regions():
    """Get all AWS regions where CloudWatch Logs is available."""
    ec2 = boto3.client('ec2', region_name='us-east-1')
    regions = ec2.describe_regions()['Regions']
    return [region['RegionName'] for region in regions]

def check_log_groups_in_region(region_name):
    """Check all log groups in a specific region for retention settings."""
    try:
        logs_client = boto3.client('logs', region_name=region_name)
        log_groups = []
        
        paginator = logs_client.get_paginator('describe_log_groups')
        
        for page in paginator.paginate():
            for log_group in page['logGroups']:
                log_group_info = {
                    'region': region_name,
                    'logGroupName': log_group['logGroupName'],
                    'retentionInDays': log_group.get('retentionInDays', None),
                    'storedBytes': log_group.get('storedBytes', 0),
                    'creationTime': log_group.get('creationTime', 0)
                }
                log_groups.append(log_group_info)
        
        return log_groups
    
    except Exception as e:
        print(f"Error checking region {region_name}: {str(e)}")
        return []

def format_bytes(bytes_value):
    """Convert bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def main():
    print("🔍 Checking CloudWatch Log Retention across all AWS regions...")
    print("=" * 80)
    
    # Get all regions
    regions = get_all_regions()
    print(f"Checking {len(regions)} regions...")
    
    # Collect all log groups from all regions
    all_log_groups = []
    no_retention_groups = []
    with_retention_groups = []
    
    # Use ThreadPoolExecutor for parallel processing
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Submit tasks for all regions
        future_to_region = {executor.submit(check_log_groups_in_region, region): region 
                           for region in regions}
        
        # Collect results
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                log_groups = future.result()
                all_log_groups.extend(log_groups)
                print(f"✅ Checked {region}: {len(log_groups)} log groups")
            except Exception as e:
                print(f"❌ Failed to check {region}: {str(e)}")
    
    # Separate log groups by retention status
    for log_group in all_log_groups:
        if log_group['retentionInDays'] is None:
            no_retention_groups.append(log_group)
        else:
            with_retention_groups.append(log_group)
    
    print("\n" + "=" * 80)
    print(f"📊 SUMMARY:")
    print(f"Total log groups found: {len(all_log_groups)}")
    print(f"Log groups WITHOUT retention: {len(no_retention_groups)}")
    print(f"Log groups WITH retention: {len(with_retention_groups)}")
    
    # Highlight log groups without retention
    if no_retention_groups:
        print("\n" + "🚨" * 20)
        print("⚠️  LOG GROUPS WITHOUT RETENTION POLICY (NEVER EXPIRE)")
        print("🚨" * 20)
        
        # Group by region for better organization
        by_region = defaultdict(list)
        for group in no_retention_groups:
            by_region[group['region']].append(group)
        
        for region in sorted(by_region.keys()):
            print(f"\n📍 Region: {region}")
            print("-" * 60)
            
            for group in sorted(by_region[region], key=lambda x: x['logGroupName']):
                stored_size = format_bytes(group['storedBytes'])
                print(f"  • {group['logGroupName']}")
                print(f"    Size: {stored_size}")
                print()
    
    # List log groups with retention
    if with_retention_groups:
        print("\n" + "✅" * 20)
        print("✅ LOG GROUPS WITH RETENTION POLICY")
        print("✅" * 20)
        
        # Group by region
        by_region = defaultdict(list)
        for group in with_retention_groups:
            by_region[group['region']].append(group)
        
        for region in sorted(by_region.keys()):
            print(f"\n📍 Region: {region}")
            print("-" * 60)
            
            for group in sorted(by_region[region], key=lambda x: x['logGroupName']):
                stored_size = format_bytes(group['storedBytes'])
                retention_days = group['retentionInDays']
                print(f"  • {group['logGroupName']}")
                print(f"    Retention: {retention_days} days | Size: {stored_size}")
                print()
    
    # Export to JSON file
    output_file = 'cloudwatch_log_retention_report.json'
    report_data = {
        'summary': {
            'total_log_groups': len(all_log_groups),
            'no_retention_count': len(no_retention_groups),
            'with_retention_count': len(with_retention_groups),
            'regions_checked': len(regions)
        },
        'log_groups_without_retention': no_retention_groups,
        'log_groups_with_retention': with_retention_groups
    }
    
    with open(output_file, 'w') as f:
        json.dump(report_data, f, indent=2, default=str)
    
    print(f"\n💾 Report saved to: {output_file}")
    
    # Show potential cost savings message
    if no_retention_groups:
        total_size_no_retention = sum(group['storedBytes'] for group in no_retention_groups)
        print(f"\n💰 COST OPTIMIZATION OPPORTUNITY:")
        print(f"Total data in log groups with no retention: {format_bytes(total_size_no_retention)}")
        print("Consider setting appropriate retention policies to reduce storage costs.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Script interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)