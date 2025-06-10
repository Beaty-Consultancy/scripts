import boto3
import json
import time
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from io import StringIO
import sys

# Thread-safe output collector
output_lock = threading.Lock()
region_outputs = {}

class OutputCapture:
    def __init__(self, region):
        self.region = region
        self.buffer = StringIO()
        
    def write(self, text):
        self.buffer.write(text)
        
    def flush(self):
        pass
        
    def get_output(self):
        return self.buffer.getvalue()

def get_aws_regions():
    """Get all AWS regions"""
    try:
        ec2 = boto3.client('ec2', region_name='eu-west-2')
        regions = ec2.describe_regions()
        return [region['RegionName'] for region in regions['Regions']]
    except Exception as e:
        print(f"Error getting regions: {e}")
        return ['eu-west-2']  # Fallback to default region

def get_running_instances(region='us-east-1') -> List[Dict[str, Any]]:
    """Get all running EC2 instances in the specified region."""
    ec2 = boto3.client('ec2', region_name=region)
    
    try:
        response = ec2.describe_instances(
            Filters=[
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
        )
        
        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_info = {
                    'instance_id': instance['InstanceId'],
                    'instance_type': instance['InstanceType'],
                    'platform': instance.get('Platform', 'linux'),  # 'windows' if Windows, otherwise assume Linux
                    'launch_time': instance['LaunchTime'],
                    'region': region,  # Add region info
                    'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                }
                instances.append(instance_info)
        
        return instances
    except Exception as e:
        return []

def check_disk_usage_via_ssm(instance_id, platform='linux', region='us-east-1', output_buffer=None):
    """Check disk usage for a specific instance via SSM."""
    ssm = boto3.client('ssm', region_name=region)
    ec2 = boto3.client('ec2', region_name=region)
    
    def print_to_buffer(text):
        if output_buffer:
            output_buffer.write(text + '\n')
        else:
            print(text)
    
    # Get provisioned storage first
    try:
        volumes_response = ec2.describe_volumes(
            Filters=[{'Name': 'attachment.instance-id', 'Values': [instance_id]}]
        )
    except Exception as e:
        print_to_buffer(f"Error getting volumes for {instance_id}: {str(e)}")
        return False
    
    provisioned_storage = {}
    total_provisioned = 0
    
    print_to_buffer(f"\n{'='*60}")
    print_to_buffer(f"Instance ID: {instance_id} (Platform: {platform})")
    print_to_buffer(f"{'='*60}")
    
    # Display provisioned storage
    print_to_buffer("PROVISIONED STORAGE:")
    for volume in volumes_response['Volumes']:
        device = volume['Attachments'][0]['Device'] if volume['Attachments'] else 'Unknown'
        size_gb = volume['Size']
        volume_type = volume['VolumeType']
        provisioned_storage[device] = size_gb
        total_provisioned += size_gb
        
        print_to_buffer(f"  Volume: {volume['VolumeId']}")
        print_to_buffer(f"  Device: {device}")
        print_to_buffer(f"  Size: {size_gb} GB")
        print_to_buffer(f"  Type: {volume_type}")
        print_to_buffer("")
    
    print_to_buffer(f"Total Provisioned: {total_provisioned} GB")
    print_to_buffer("-" * 40)
    
    # Check if SSM agent is available
    try:
        ssm.describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
        )
    except Exception as e:
        print_to_buffer(f"SSM Agent not available or not responding for {instance_id}: {str(e)}")
        return False
    
    # Get actual disk usage based on platform
    if platform.lower() == 'windows':
        return _check_windows_disk_usage(ssm, instance_id, output_buffer)
    else:
        return _check_linux_disk_usage(ssm, instance_id, output_buffer)

def _check_linux_disk_usage(ssm, instance_id, output_buffer=None):
    """Check disk usage for Linux instances."""
    def print_to_buffer(text):
        if output_buffer:
            output_buffer.write(text + '\n')
        else:
            print(text)
    
    linux_command = """
    df -BG | grep -E '^/dev/' | while read filesystem size used available percent mountpoint; do
        echo "FILESYSTEM:$filesystem|SIZE:$size|USED:$used|AVAILABLE:$available|PERCENT:$percent|MOUNTPOINT:$mountpoint"
    done
    """
    
    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': [linux_command]},
            TimeoutSeconds=60
        )
        
        command_id = response['Command']['CommandId']
        
        # Wait for command to complete
        max_attempts = 12
        for attempt in range(max_attempts):
            time.sleep(5)
            
            try:
                output = ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id
                )
                
                if output['Status'] in ['Success', 'Failed']:
                    break
            except ssm.exceptions.InvocationDoesNotExist:
                continue
        
        if output['Status'] == 'Success':
            lines = output['StandardOutputContent'].strip().split('\n')
            
            print_to_buffer("ACTUAL DISK USAGE (Linux):")
            total_used = 0
            total_available = 0
            
            for line in lines:
                if 'FILESYSTEM:' in line and line.strip():
                    parts = line.split('|')
                    if len(parts) >= 6:
                        filesystem = parts[0].split(':')[1]
                        size = parts[1].split(':')[1].replace('G', '')
                        used = parts[2].split(':')[1].replace('G', '')
                        available = parts[3].split(':')[1].replace('G', '')
                        percent = parts[4].split(':')[1]
                        mountpoint = parts[5].split(':')[1]
                        
                        try:
                            used_gb = int(used)
                            avail_gb = int(available)
                            size_gb = int(size)
                            
                            total_used += used_gb
                            total_available += avail_gb
                            
                            print_to_buffer(f"  Device: {filesystem}")
                            print_to_buffer(f"  Mount Point: {mountpoint}")
                            print_to_buffer(f"  Total: {size_gb} GB")
                            print_to_buffer(f"  Used: {used_gb} GB ({percent})")
                            print_to_buffer(f"  Available: {avail_gb} GB")
                            
                            # Warning if usage is high
                            usage_percent = int(percent.replace('%', ''))
                            if usage_percent > 90:
                                print_to_buffer(f"  🚨 CRITICAL: {usage_percent}% usage!")
                            elif usage_percent > 80:
                                print_to_buffer(f"  ⚠️  WARNING: {usage_percent}% usage")
                            
                            print_to_buffer("")
                        except ValueError:
                            continue
            
            print_to_buffer(f"Total Used Across All Filesystems: {total_used} GB")
            print_to_buffer(f"Total Available Across All Filesystems: {total_available} GB")
            return True
        else:
            print_to_buffer(f"Linux command failed: {output.get('StandardErrorContent', 'Unknown error')}")
            return False
            
    except Exception as e:
        print_to_buffer(f"Error executing Linux SSM command: {str(e)}")
        return False

def _check_windows_disk_usage(ssm, instance_id, output_buffer=None):
    """Check disk usage for Windows instances."""
    def print_to_buffer(text):
        if output_buffer:
            output_buffer.write(text + '\n')
        else:
            print(text)
    
    windows_command = """
    Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | ForEach-Object {
        $SizeGB = [math]::Round($_.Size / 1GB, 2)
        $FreeSpaceGB = [math]::Round($_.FreeSpace / 1GB, 2)
        $UsedSpaceGB = [math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)
        $PercentFree = [math]::Round(($_.FreeSpace / $_.Size) * 100, 2)
        $PercentUsed = [math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 2)
        
        Write-Output "DRIVE:$($_.DeviceID)|SIZE:$($SizeGB)GB|USED:$($UsedSpaceGB)GB|FREE:$($FreeSpaceGB)GB|PERCENT_USED:$($PercentUsed)%|PERCENT_FREE:$($PercentFree)%|LABEL:$($_.VolumeName)"
    }
    """
    
    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={'commands': [windows_command]},
            TimeoutSeconds=60
        )
        
        command_id = response['Command']['CommandId']
        
        # Wait for command to complete
        max_attempts = 12
        for attempt in range(max_attempts):
            time.sleep(5)
            
            try:
                output = ssm.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id
                )
                
                if output['Status'] in ['Success', 'Failed']:
                    break
            except ssm.exceptions.InvocationDoesNotExist:
                continue
        
        if output['Status'] == 'Success':
            lines = output['StandardOutputContent'].strip().split('\n')
            
            print_to_buffer("ACTUAL DISK USAGE (Windows):")
            total_used = 0
            total_free = 0
            
            for line in lines:
                if 'DRIVE:' in line and line.strip():
                    parts = line.split('|')
                    if len(parts) >= 6:
                        drive = parts[0].split(':')[1]
                        size = parts[1].split(':')[1].replace('GB', '')
                        used = parts[2].split(':')[1].replace('GB', '')
                        free = parts[3].split(':')[1].replace('GB', '')
                        percent_used = parts[4].split(':')[1].replace('%', '')
                        percent_free = parts[5].split(':')[1].replace('%', '')
                        label = parts[6].split(':')[1] if len(parts) > 6 else ''
                        
                        try:
                            used_gb = float(used)
                            free_gb = float(free)
                            size_gb = float(size)
                            usage_percent = float(percent_used)
                            
                            total_used += used_gb
                            total_free += free_gb
                            
                            print_to_buffer(f"  Drive: {drive}")
                            if label:
                                print_to_buffer(f"  Label: {label}")
                            print_to_buffer(f"  Total: {size_gb:.2f} GB")
                            print_to_buffer(f"  Used: {used_gb:.2f} GB ({usage_percent:.1f}%)")
                            print_to_buffer(f"  Free: {free_gb:.2f} GB")
                            
                            # Warning if usage is high
                            if usage_percent > 90:
                                print_to_buffer(f"  🚨 CRITICAL: {usage_percent:.1f}% usage!")
                            elif usage_percent > 80:
                                print_to_buffer(f"  ⚠️  WARNING: {usage_percent:.1f}% usage")
                            
                            print_to_buffer("")
                        except ValueError:
                            continue
            
            print_to_buffer(f"Total Used Across All Drives: {total_used:.2f} GB")
            print_to_buffer(f"Total Free Across All Drives: {total_free:.2f} GB")
            return True
        else:
            print_to_buffer(f"Windows command failed: {output.get('StandardErrorContent', 'Unknown error')}")
            return False
            
    except Exception as e:
        print_to_buffer(f"Error executing Windows SSM command: {str(e)}")
        return False

def check_region_instances(region):
    """Check instances in a specific region and return summary with captured output"""
    output_capture = OutputCapture(region)
    
    # Capture region header
    output_capture.write(f"🌍 Checking region: {region}\n")
    output_capture.write("-" * 50 + "\n")
    
    instances = get_running_instances(region)
    
    if not instances:
        output_capture.write(f"   No running instances found in {region}\n")
        return {
            'region': region,
            'total_instances': 0,
            'successful_checks': 0,
            'failed_checks': 0,
            'instances': [],
            'output': output_capture.get_output()
        }
    
    output_capture.write(f"   Found {len(instances)} running instances in {region}\n")
    
    successful_checks = 0
    failed_checks = 0
    checked_instances = []
    
    for instance in instances:
        try:
            name = instance['tags'].get('Name', 'No Name')
            output_capture.write(f"   Checking: {instance['instance_id']} ({name})\n")
            
            success = check_disk_usage_via_ssm(
                instance['instance_id'], 
                instance['platform'], 
                region,
                output_capture
            )
            
            checked_instances.append({
                'instance_id': instance['instance_id'],
                'name': name,
                'instance_type': instance['instance_type'],
                'platform': instance['platform'],
                'check_success': success
            })
            
            if success:
                successful_checks += 1
            else:
                failed_checks += 1
                
        except Exception as e:
            output_capture.write(f"   Error checking instance {instance['instance_id']}: {str(e)}\n")
            failed_checks += 1
            checked_instances.append({
                'instance_id': instance['instance_id'],
                'name': instance['tags'].get('Name', 'No Name'),
                'instance_type': instance['instance_type'],
                'platform': instance['platform'],
                'check_success': False,
                'error': str(e)
            })
        
        # Small delay between instances to avoid rate limiting
        time.sleep(1)
    
    output_capture.write(f"   ✅ {region} completed: {successful_checks} successful, {failed_checks} failed\n")
    
    region_summary = {
        'region': region,
        'total_instances': len(instances),
        'successful_checks': successful_checks,
        'failed_checks': failed_checks,
        'instances': checked_instances,
        'output': output_capture.get_output()
    }
    
    return region_summary

def check_all_regions_instances(max_workers=5):
    """Check storage for all running instances across all AWS regions."""
    print("🚀 Starting global EC2 storage capacity check across all AWS regions")
    print("=" * 80)
    
    # Get all AWS regions
    regions = get_aws_regions()
    print(f"📍 Found {len(regions)} AWS regions to check")
    print(f"🔧 Using {max_workers} concurrent workers")
    print()
    
    # Use ThreadPoolExecutor to check regions concurrently
    region_summaries = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit tasks for each region
        future_to_region = {executor.submit(check_region_instances, region): region for region in regions}
        
        # Collect results as they complete
        completed_regions = []
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                summary = future.result()
                region_summaries.append(summary)
                completed_regions.append(region)
                
                # Show progress
                print(f"✅ Completed: {region} ({len(completed_regions)}/{len(regions)})")
                
            except Exception as e:
                print(f"❌ Error processing region {region}: {str(e)}")
                region_summaries.append({
                    'region': region,
                    'total_instances': 0,
                    'successful_checks': 0,
                    'failed_checks': 0,
                    'instances': [],
                    'error': str(e),
                    'output': f"❌ Error processing region {region}: {str(e)}\n"
                })
    
    # Sort regions by name for consistent output
    region_summaries.sort(key=lambda x: x['region'])
    
    # Print detailed results for each region
    print("\n" + "=" * 80)
    print("📋 DETAILED REGION RESULTS")
    print("=" * 80)
    
    for summary in region_summaries:
        if summary['total_instances'] > 0:  # Only show regions with instances
            print(summary['output'])
    
    # Generate comprehensive summary
    print_global_summary(region_summaries)
    return region_summaries

def print_global_summary(region_summaries):
    """Print a comprehensive summary of all regions checked."""
    print(f"\n{'='*80}")
    print("🌐 GLOBAL SUMMARY - EC2 Storage Capacity Check")
    print(f"{'='*80}")
    
    total_instances = sum(summary['total_instances'] for summary in region_summaries)
    total_successful = sum(summary['successful_checks'] for summary in region_summaries)
    total_failed = sum(summary['failed_checks'] for summary in region_summaries)
    regions_with_instances = sum(1 for summary in region_summaries if summary['total_instances'] > 0)
    
    print(f"📊 Overall Statistics:")
    print(f"   Total Regions Checked: {len(region_summaries)}")
    print(f"   Regions with Instances: {regions_with_instances}")
    print(f"   Total EC2 Instances: {total_instances}")
    print(f"   Successful Checks: {total_successful}")
    print(f"   Failed Checks: {total_failed}")
    print(f"   Success Rate: {(total_successful/max(total_instances, 1)*100):.1f}%")
    
    print(f"\n📍 Per-Region Breakdown:")
    print(f"{'Region':<20} {'Instances':<10} {'Success':<8} {'Failed':<8} {'Status'}")
    print("-" * 60)
    
    for summary in sorted(region_summaries, key=lambda x: x['total_instances'], reverse=True):
        region = summary['region']
        total = summary['total_instances']
        success = summary['successful_checks']
        failed = summary['failed_checks']
        
        if total == 0:
            status = "No instances"
        elif failed == 0:
            status = "✅ All good"
        elif success == 0:
            status = "❌ All failed"
        else:
            status = "⚠️ Mixed"
        
        print(f"{region:<20} {total:<10} {success:<8} {failed:<8} {status}")
    
    # Show regions with issues
    problem_regions = [s for s in region_summaries if s['failed_checks'] > 0 or 'error' in s]
    if problem_regions:
        print(f"\n⚠️ Regions with Issues:")
        for summary in problem_regions:
            region = summary['region']
            if 'error' in summary:
                print(f"   {region}: Region check failed - {summary['error']}")
            elif summary['failed_checks'] > 0:
                print(f"   {region}: {summary['failed_checks']} instances failed storage check")
                # Show failed instances
                failed_instances = [inst for inst in summary['instances'] if not inst['check_success']]
                for inst in failed_instances[:3]:  # Show first 3 failed instances
                    error_msg = inst.get('error', 'SSM check failed')
                    print(f"     - {inst['instance_id']} ({inst['name']}): {error_msg}")
                if len(failed_instances) > 3:
                    print(f"     ... and {len(failed_instances) - 3} more")
    
    print(f"\n{'='*80}")

def check_all_instances_storage(region='us-east-1'):
    """Check storage for all running instances in the region."""
    print(f"Checking storage for all running instances in region: {region}")
    print("=" * 80)
    
    # Get all running instances
    instances = get_running_instances(region)
    
    if not instances:
        print("No running instances found or error retrieving instances.")
        return
    
    print(f"Found {len(instances)} running instances:")
    for i, instance in enumerate(instances, 1):
        name = instance['tags'].get('Name', 'No Name')
        print(f"{i}. {instance['instance_id']} ({instance['instance_type']}) - {name} - {instance['platform']}")
    
    print("\nStarting storage capacity checks...")
    
    successful_checks = 0
    failed_checks = 0
    
    for instance in instances:
        try:
            success = check_disk_usage_via_ssm(
                instance['instance_id'], 
                instance['platform'], 
                region
            )
            if success:
                successful_checks += 1
            else:
                failed_checks += 1
        except Exception as e:
            print(f"Error checking instance {instance['instance_id']}: {str(e)}")
            failed_checks += 1
        
        # Small delay between instances to avoid rate limiting
        time.sleep(2)
    
    print(f"\n{'='*80}")
    print("SUMMARY:")
    print(f"Total instances checked: {len(instances)}")
    print(f"Successful checks: {successful_checks}")
    print(f"Failed checks: {failed_checks}")
    print(f"{'='*80}")

def check_specific_instance_storage(instance_id, region='us-east-1'):
    """Check storage for a specific instance."""
    ec2 = boto3.client('ec2', region_name=region)
    
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        platform = instance.get('Platform', 'linux')
        
        return check_disk_usage_via_ssm(instance_id, platform, region)
    except Exception as e:
        print(f"Error getting instance details for {instance_id}: {str(e)}")
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='EC2 Storage Capacity Checker')
    parser.add_argument('--mode', choices=['single-region', 'all-regions', 'specific-instance'], 
                       default='single-region', help='Checking mode')
    parser.add_argument('--region', default='eu-west-2', help='AWS region (for single-region mode)')
    parser.add_argument('--instance-id', help='Specific instance ID to check')
    parser.add_argument('--max-workers', type=int, default=5, 
                       help='Maximum concurrent workers for all-regions mode')
    
    args = parser.parse_args()
    
    if args.mode == 'all-regions':
        print("🌐 Checking all AWS regions...")
        check_all_regions_instances(args.max_workers)
    elif args.mode == 'specific-instance':
        if not args.instance_id:
            print("❌ Error: --instance-id is required for specific-instance mode")
            exit(1)
        print(f"🎯 Checking specific instance: {args.instance_id}")
        check_specific_instance_storage(args.instance_id, args.region)
    else:  # single-region
        print(f"🌍 Checking single region: {args.region}")
        check_all_instances_storage(args.region)