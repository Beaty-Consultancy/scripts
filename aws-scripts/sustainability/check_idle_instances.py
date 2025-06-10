#!/usr/bin/env python3
# filepath: /Users/syedmuhammadahmed/Downloads/repos/aws-scripts/check_idle_instances.py

import boto3
import json
import re
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError, ProfileNotFound
import sys

def get_aws_regions():
    """Get all AWS regions"""
    try:
        ec2 = boto3.client('ec2', region_name='eu-west-2')
        regions = ec2.describe_regions()
        return [region['RegionName'] for region in regions['Regions']]
    except Exception as e:
        print(f"Error getting regions: {e}")
        return []

def parse_stop_time(state_transition_reason):
    """Parse stop time from StateTransitionReason with multiple patterns"""
    if not state_transition_reason:
        return None
    
    try:
        # Multiple patterns to catch different timestamp formats
        patterns = [
            r'\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)',  # (2023-05-29 14:30:45 GMT)
            r'\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\+00:00\)',  # (2023-05-29 14:30:45+00:00)
            r'\((\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\)',  # ISO format
            r'\((\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\)',  # ISO format without milliseconds
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT',  # Without parentheses
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)',  # ISO without parentheses
        ]
        
        for pattern in patterns:
            match = re.search(pattern, state_transition_reason)
            if match:
                time_str = match.group(1)
                
                # Try different parsing formats
                try:
                    if 'T' in time_str:
                        if time_str.endswith('Z'):
                            if '.' in time_str:
                                # ISO with milliseconds
                                return datetime.strptime(time_str, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
                            else:
                                # ISO without milliseconds
                                return datetime.strptime(time_str, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                    else:
                        # Standard format
                        return datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
    except Exception as e:
        print(f"Debug: Error parsing timestamp '{state_transition_reason}': {e}")
    
    return None

def check_idle_instances():
    """Check for instances that have been stopped for more than 1 week"""
    print("🔍 Checking for AWS EC2 instances that have been stopped for more than 1 week...")
    print("=" * 70)
    
    # Calculate cutoff date (1 week ago)
    one_week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    print(f"Cutoff date: {one_week_ago.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    
    idle_instances = []  # Instances stopped for more than 1 week
    recent_stopped_instances = []  # Instances stopped for less than 1 week
    total_instances_checked = 0
    total_running_instances = 0
    total_stopped_instances = 0
    
    regions = get_aws_regions()
    if not regions:
        print("❌ Could not retrieve AWS regions")
        return
    
    for region in regions:
        try:
            ec2 = boto3.client('ec2', region_name=region)
            
            # Get all instances (excluding terminated)
            response = ec2.describe_instances(
                Filters=[
                    {
                        'Name': 'instance-state-name',
                        'Values': ['pending', 'running', 'shutting-down', 'stopping', 'stopped']
                    }
                ]
            )
            
            region_idle_instances = []
            region_recent_stopped = []
            region_total_instances = 0
            region_running_instances = 0
            region_stopped_instances = 0
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    region_total_instances += 1
                    total_instances_checked += 1
                    
                    launch_time = instance['LaunchTime']
                    state = instance['State']['Name']
                    state_transition_reason = instance.get('StateTransitionReason', '')
                    
                    # Count instances by state
                    if state == 'running':
                        total_running_instances += 1
                        region_running_instances += 1
                    elif state == 'stopped':
                        total_stopped_instances += 1
                        region_stopped_instances += 1
                    
                    # Process all stopped instances
                    if state == 'stopped':
                        stop_time = parse_stop_time(state_transition_reason)
                        
                        stopped_since = None
                        stop_reason = ""
                        
                        if stop_time:
                            stopped_since = stop_time
                            stop_reason = f"Stopped since {stop_time.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                        else:
                            # Fallback: if we can't parse stop time, use launch time
                            print(f"Debug: Could not parse stop time for {instance['InstanceId']}: '{state_transition_reason}'")
                            stopped_since = launch_time
                            stop_reason = f"Launched {launch_time.strftime('%Y-%m-%d %H:%M:%S UTC')} (stop time unknown)"
                        
                        instance_name = 'N/A'
                        
                        # Get instance name from tags
                        if 'Tags' in instance:
                            for tag in instance['Tags']:
                                if tag['Key'] == 'Name':
                                    instance_name = tag['Value']
                                    break
                        
                        stopped_instance = {
                            'InstanceId': instance['InstanceId'],
                            'InstanceType': instance['InstanceType'],
                            'LaunchTime': launch_time,
                            'State': state,
                            'Name': instance_name,
                            'Region': region,
                            'StoppedSince': stopped_since,
                            'StopReason': stop_reason,
                            'StateTransitionReason': state_transition_reason
                        }
                        
                        # Categorize based on stop duration
                        if stopped_since <= one_week_ago:
                            # Stopped for more than 1 week
                            region_idle_instances.append(stopped_instance)
                            idle_instances.append(stopped_instance)
                        else:
                            # Stopped for less than 1 week
                            region_recent_stopped.append(stopped_instance)
                            recent_stopped_instances.append(stopped_instance)
            
            if region_total_instances > 0:
                print(f"📍 Region: {region} - Total: {region_total_instances} instances")
                print(f"   • Running: {region_running_instances}")
                print(f"   • Stopped: {region_stopped_instances}")
                print(f"   • Stopped > 1 week: {len(region_idle_instances)}")
                print(f"   • Stopped < 1 week: {len(region_recent_stopped)}")
                
                # Show instances stopped for more than 1 week
                if region_idle_instances:
                    print("\n   🔴 Instances stopped for MORE than 1 week:")
                    print("   " + "-" * 47)
                    for instance in region_idle_instances:
                        days_stopped = (datetime.now(timezone.utc) - instance['StoppedSince']).days
                        
                        print(f"   🖥️  Instance ID: {instance['InstanceId']}")
                        print(f"      Name: {instance['Name']}")
                        print(f"      Type: {instance['InstanceType']}")
                        print(f"      {instance['StopReason']}")
                        print(f"      Days Stopped: {days_stopped}")
                        print(f"      State Transition: {instance['StateTransitionReason']}")
                        print()
                
                # Show instances stopped for less than 1 week
                if region_recent_stopped:
                    print("   🟡 Instances stopped for LESS than 1 week:")
                    print("   " + "-" * 47)
                    for instance in region_recent_stopped:
                        days_stopped = (datetime.now(timezone.utc) - instance['StoppedSince']).days
                        
                        print(f"   🖥️  Instance ID: {instance['InstanceId']}")
                        print(f"      Name: {instance['Name']}")
                        print(f"      Type: {instance['InstanceType']}")
                        print(f"      {instance['StopReason']}")
                        print(f"      Days Stopped: {days_stopped}")
                        print(f"      State Transition: {instance['StateTransitionReason']}")
                        print()
                
                if not region_idle_instances and not region_recent_stopped:
                    print("   ✅ No stopped instances in this region")
                print()
        
        except ClientError as e:
            if e.response['Error']['Code'] == 'UnauthorizedOperation':
                print(f"⚠️  No access to region {region}")
            else:
                print(f"❌ Error checking region {region}: {e}")
        except Exception as e:
            print(f"❌ Unexpected error in region {region}: {e}")
    
    # Summary
    print("=" * 70)
    print(f"🔍 Total instances checked: {total_instances_checked}")
    print(f"🟢 Total running instances: {total_running_instances}")
    print(f"🔴 Total stopped instances: {total_stopped_instances}")
    print(f"⏰ Stopped for more than 1 week: {len(idle_instances)}")
    print(f"🕐 Stopped for less than 1 week: {len(recent_stopped_instances)}")
    
    if idle_instances:
        print(f"\n📊 Found {len(idle_instances)} instances stopped for more than 1 week")
        print("\n💡 Recommendations for long-stopped instances:")
        print("   • Review if these stopped instances are still needed")
        print("   • Terminate instances that are no longer required")
        print("   • Consider creating AMIs before terminating if you might need them later")
        print("   • Check for associated EBS volumes that might still incur costs")
        print("   • Use AWS Cost Explorer to analyze storage costs")
        
        print(f"\n💰 Cost Impact:")
        print(f"   • {len(idle_instances)} stopped instances may have associated EBS storage costs")
        print(f"   • Review EBS volumes, snapshots, and other resources tied to these instances")
        
        # Group by region for better overview
        regions_summary = {}
        for instance in idle_instances:
            region = instance['Region']
            if region not in regions_summary:
                regions_summary[region] = 0
            regions_summary[region] += 1
        
        print(f"\n📈 Long-stopped instances breakdown by region:")
        for region, count in sorted(regions_summary.items()):
            print(f"   • {region}: {count} instances")
    
    if recent_stopped_instances:
        print(f"\n📊 Found {len(recent_stopped_instances)} instances stopped for less than 1 week")
        print("💡 These instances were recently stopped and may be intentionally paused")
        
        # Group recent stopped by region
        recent_regions_summary = {}
        for instance in recent_stopped_instances:
            region = instance['Region']
            if region not in recent_regions_summary:
                recent_regions_summary[region] = 0
            recent_regions_summary[region] += 1
        
        print(f"\n📈 Recently-stopped instances breakdown by region:")
        for region, count in sorted(recent_regions_summary.items()):
            print(f"   • {region}: {count} instances")
    
    if not idle_instances and not recent_stopped_instances:
        print("✅ No stopped instances found")

def main():
    try:
        # Check if AWS credentials are configured
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        print(f"🔐 Using AWS Account: {identity['Account']}")
        print(f"👤 IAM User/Role: {identity['Arn']}")
        print()
        
        check_idle_instances()
        
    except ProfileNotFound:
        print("❌ AWS credentials not found. Please run 'aws configure' or set environment variables.")
        sys.exit(1)
    except ClientError as e:
        print(f"❌ AWS API Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()