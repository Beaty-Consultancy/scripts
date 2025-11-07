#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Sustainability Pillar
EC2 Storage Capacity Analysis

This script analyzes EC2 instances across all AWS regions to identify
storage capacity utilization and optimization opportunities using SSM.
"""

import boto3
import json
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError
import sys

# Constants
DEFAULT_NAME = 'No Name'


def get_available_regions():
    """
    Get all AWS regions where EC2 is available
    
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


def get_running_instances(region_name: str) -> List[Dict[str, Any]]:
    """
    Get all running EC2 instances for a specific region
    
    Args:
        region_name: AWS region name
        
    Returns:
        list: List of running EC2 instance information
    """
    try:
        ec2_client = boto3.client('ec2', region_name=region_name)
        response = ec2_client.describe_instances(
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
                    'platform': instance.get('Platform', 'linux'),
                    'launch_time': instance['LaunchTime'],
                    'region': region_name,
                    'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                }
                instances.append(instance_info)
        
        return instances
    except ClientError:
        return []
    except Exception:
        return []


def get_instance_volumes(region_name: str, instance_id: str) -> List[Dict[str, Any]]:
    """
    Get all volumes attached to a specific instance
    
    Args:
        region_name: AWS region name
        instance_id: EC2 instance ID
        
    Returns:
        list: List of volume information
    """
    try:
        ec2_client = boto3.client('ec2', region_name=region_name)
        response = ec2_client.describe_volumes(
            Filters=[{'Name': 'attachment.instance-id', 'Values': [instance_id]}]
        )
        
        volumes = []
        for volume in response['Volumes']:
            volume_info = {
                'volume_id': volume['VolumeId'],
                'size_gb': volume['Size'],
                'volume_type': volume['VolumeType'],
                'device': volume['Attachments'][0]['Device'] if volume['Attachments'] else 'Unknown',
                'encrypted': volume.get('Encrypted', False)
            }
            volumes.append(volume_info)
        
        return volumes
    except Exception:
        return []


def execute_ssm_command(region_name: str, instance_id: str, document_name: str, 
                       commands: List[str], timeout: int = 60) -> Dict[str, Any]:
    """
    Execute SSM command on an instance
    
    Args:
        region_name: AWS region name
        instance_id: EC2 instance ID
        document_name: SSM document name
        commands: List of commands to execute
        timeout: Command timeout in seconds
        
    Returns:
        dict: Command execution results
    """
    try:
        ssm_client = boto3.client('ssm', region_name=region_name)
        
        # Check if SSM agent is available
        try:
            ssm_client.describe_instance_information(
                Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
            )
        except Exception:
            return {'success': False, 'error': 'SSM Agent not available or not responding'}
        
        # Send command
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName=document_name,
            Parameters={'commands': commands},
            TimeoutSeconds=timeout
        )
        
        command_id = response['Command']['CommandId']
        
        # Wait for command to complete
        max_attempts = 12
        output = None
        for _ in range(max_attempts):
            time.sleep(5)
            
            try:
                output = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id
                )
                
                if output['Status'] in ['Success', 'Failed']:
                    break
            except ssm_client.exceptions.InvocationDoesNotExist:
                continue
        
        if output and output['Status'] == 'Success':
            return {
                'success': True, 
                'stdout': output['StandardOutputContent'],
                'stderr': output.get('StandardErrorContent', '')
            }
        elif output:
            return {
                'success': False, 
                'error': output.get('StandardErrorContent', 'Command failed')
            }
        else:
            return {'success': False, 'error': 'Command execution timeout'}
            
    except Exception as e:
        return {'success': False, 'error': str(e)}


def parse_linux_disk_usage(output: str) -> List[Dict[str, Any]]:
    """
    Parse Linux df command output
    
    Args:
        output: Raw command output
        
    Returns:
        list: List of filesystem usage data
    """
    filesystems = []
    lines = output.strip().split('\n')
    
    for line in lines:
        if 'FILESYSTEM:' in line and line.strip():
            parts = line.split('|')
            if len(parts) >= 6:
                try:
                    filesystem = parts[0].split(':')[1]
                    size = int(parts[1].split(':')[1].replace('G', ''))
                    used = int(parts[2].split(':')[1].replace('G', ''))
                    available = int(parts[3].split(':')[1].replace('G', ''))
                    percent = parts[4].split(':')[1].replace('%', '')
                    mountpoint = parts[5].split(':')[1]
                    
                    usage_percent = int(percent)
                    
                    filesystem_data = {
                        'filesystem': filesystem,
                        'mountpoint': mountpoint,
                        'size_gb': size,
                        'used_gb': used,
                        'available_gb': available,
                        'usage_percent': usage_percent,
                        'high_usage': usage_percent > 80,
                        'critical_usage': usage_percent > 90
                    }
                    filesystems.append(filesystem_data)
                except (ValueError, IndexError):
                    continue
    
    return filesystems


def parse_windows_disk_usage(output: str) -> List[Dict[str, Any]]:
    """
    Parse Windows PowerShell disk usage output
    
    Args:
        output: Raw command output
        
    Returns:
        list: List of drive usage data
    """
    drives = []
    lines = output.strip().split('\n')
    
    for line in lines:
        if 'DRIVE:' in line and line.strip():
            parts = line.split('|')
            if len(parts) >= 6:
                try:
                    drive = parts[0].split(':')[1]
                    size = float(parts[1].split(':')[1].replace('GB', ''))
                    used = float(parts[2].split(':')[1].replace('GB', ''))
                    free = float(parts[3].split(':')[1].replace('GB', ''))
                    percent_used = float(parts[4].split(':')[1].replace('%', ''))
                    label = parts[6].split(':')[1] if len(parts) > 6 else ''
                    
                    drive_data = {
                        'drive': drive,
                        'label': label,
                        'size_gb': round(size, 2),
                        'used_gb': round(used, 2),
                        'free_gb': round(free, 2),
                        'usage_percent': round(percent_used, 1),
                        'high_usage': percent_used > 80,
                        'critical_usage': percent_used > 90
                    }
                    drives.append(drive_data)
                except (ValueError, IndexError):
                    continue
    
    return drives


def analyze_instance_storage(region_name: str, instance: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze storage usage for a single EC2 instance
    
    Args:
        region_name: AWS region name
        instance: Instance information
        
    Returns:
        dict: Instance storage analysis data
    """
    instance_id = instance['instance_id']
    platform = instance['platform']
    
    # Get provisioned volumes
    volumes = get_instance_volumes(region_name, instance_id)
    total_provisioned_gb = sum(vol['size_gb'] for vol in volumes)
    
    # Prepare SSM commands based on platform
    if platform.lower() == 'windows':
        document_name = "AWS-RunPowerShellScript"
        commands = ['''
        Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | ForEach-Object {
            $SizeGB = [math]::Round($_.Size / 1GB, 2)
            $FreeSpaceGB = [math]::Round($_.FreeSpace / 1GB, 2)
            $UsedSpaceGB = [math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)
            $PercentUsed = [math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 2)
            $PercentFree = [math]::Round(($_.FreeSpace / $_.Size) * 100, 2)
            
            Write-Output "DRIVE:$($_.DeviceID)|SIZE:$($SizeGB)GB|USED:$($UsedSpaceGB)GB|FREE:$($FreeSpaceGB)GB|PERCENT_USED:$($PercentUsed)%|PERCENT_FREE:$($PercentFree)%|LABEL:$($_.VolumeName)"
        }
        ''']
    else:
        document_name = "AWS-RunShellScript"
        commands = ['''
        df -BG | grep -E '^/dev/' | while read filesystem size used available percent mountpoint; do
            echo "FILESYSTEM:$filesystem|SIZE:$size|USED:$used|AVAILABLE:$available|PERCENT:$percent|MOUNTPOINT:$mountpoint"
        done
        ''']
    
    # Execute SSM command
    ssm_result = execute_ssm_command(region_name, instance_id, document_name, commands)
    
    # Analyze results
    if not ssm_result['success']:
        # Instance failed SSM check
        result = {
            'instance_id': instance_id,
            'name': instance['tags'].get('Name', DEFAULT_NAME),
            'instance_type': instance['instance_type'],
            'platform': platform,
            'region': region_name,
            'launch_time': instance['launch_time'].isoformat(),
            'volumes': volumes,
            'total_provisioned_gb': total_provisioned_gb,
            'ssm_available': False,
            'error': ssm_result['error'],
            'storage_data': [],
            'total_used_gb': 0,
            'total_available_gb': 0,
            'overall_usage_percent': 0,
            'non_compliant': True,
            'non_compliant_reasons': [f"SSM unavailable: {ssm_result['error']}"]
        }
        return result
    
    # Parse disk usage based on platform
    if platform.lower() == 'windows':
        storage_data = parse_windows_disk_usage(ssm_result['stdout'])
        total_used_gb = sum(drive['used_gb'] for drive in storage_data)
        total_available_gb = sum(drive['free_gb'] for drive in storage_data)
    else:
        storage_data = parse_linux_disk_usage(ssm_result['stdout'])
        total_used_gb = sum(fs['used_gb'] for fs in storage_data)
        total_available_gb = sum(fs['available_gb'] for fs in storage_data)
    
    # Calculate overall usage percentage
    total_actual_gb = total_used_gb + total_available_gb
    overall_usage_percent = (total_used_gb / total_actual_gb * 100) if total_actual_gb > 0 else 0
    
    # Determine non-compliance issues
    non_compliant_reasons = []
    
    # Check for high usage filesystems/drives
    high_usage_items = [item for item in storage_data if item.get('high_usage', False)]
    critical_usage_items = [item for item in storage_data if item.get('critical_usage', False)]
    
    if critical_usage_items:
        non_compliant_reasons.append(f"{len(critical_usage_items)} storage volume(s) with critical usage (>90%)")
    elif high_usage_items:
        non_compliant_reasons.append(f"{len(high_usage_items)} storage volume(s) with high usage (>80%)")
    
    # Check for over-provisioned storage (actual usage < 50% of provisioned)
    if total_provisioned_gb > 0 and total_actual_gb > 0:
        utilization_ratio = total_actual_gb / total_provisioned_gb
        if utilization_ratio < 0.5:
            non_compliant_reasons.append(f"Low storage utilization: only {utilization_ratio*100:.1f}% of provisioned storage is allocated")
    
    result = {
        'instance_id': instance_id,
        'name': instance['tags'].get('Name', DEFAULT_NAME),
        'instance_type': instance['instance_type'],
        'platform': platform,
        'region': region_name,
        'launch_time': instance['launch_time'].isoformat(),
        'volumes': volumes,
        'total_provisioned_gb': total_provisioned_gb,
        'ssm_available': True,
        'storage_data': storage_data,
        'total_used_gb': round(total_used_gb, 2),
        'total_available_gb': round(total_available_gb, 2),
        'total_actual_gb': round(total_actual_gb, 2),
        'overall_usage_percent': round(overall_usage_percent, 1),
        'storage_utilization_ratio': round((total_actual_gb / total_provisioned_gb * 100), 1) if total_provisioned_gb > 0 else 0,
        'non_compliant': len(non_compliant_reasons) > 0,
        'non_compliant_reasons': non_compliant_reasons
    }
    
    return result


def check_ec2_storage_for_region(region_name: str) -> Dict[str, Any]:
    """
    Check EC2 storage capacity for a specific region
    
    Args:
        region_name: AWS region name
        
    Returns:
        dict: Region analysis data
    """
    try:
        # Get running instances
        instances = get_running_instances(region_name)
        
        region_results = []
        
        # Analyze each instance
        for instance in instances:
            try:
                analysis = analyze_instance_storage(region_name, instance)
                region_results.append(analysis)
            except Exception as e:
                error_item = {
                    "instance_id": instance.get('instance_id', 'Unknown'),
                    "name": instance.get('tags', {}).get('Name', DEFAULT_NAME),
                    "error": str(e),
                    "region": region_name,
                    "non_compliant": True,
                    "non_compliant_reasons": [f"Analysis failed: {str(e)}"]
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


def check_ec2_storage_all_regions(max_workers: int = 5) -> Dict[str, Any]:
    """
    Check EC2 storage capacity across all AWS regions
    
    Args:
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
                executor.submit(check_ec2_storage_for_region, region): region 
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
            if 'error' in item and 'instance_id' in item:
                error_items.append(item)
            elif item.get('non_compliant', False):
                non_compliant_items.append(item)
            else:
                compliant_items.append(item)
        
        # Calculate statistics
        total_instances = len(all_results)
        non_compliant_count = len(non_compliant_items)
        compliant_count = len(compliant_items)
        error_count = len(error_items)
        
        # SSM availability stats
        ssm_available = len([item for item in all_results if item.get('ssm_available', False)])
        
        # High usage instances
        high_usage_instances = len([item for item in all_results 
                                  if 'overall_usage_percent' in item and item['overall_usage_percent'] > 80])
        
        # Calculate total provisioned vs used storage
        total_provisioned = sum(item.get('total_provisioned_gb', 0) for item in all_results)
        total_used = sum(item.get('total_used_gb', 0) for item in all_results)
        
        return {
            'total_regions_checked': len(regions),
            'total_instances': total_instances,
            'compliant_instances': compliant_count,
            'non_compliant_instances': non_compliant_count,
            'error_instances': error_count,
            'ssm_available_instances': ssm_available,
            'high_usage_instances': high_usage_instances,
            'total_provisioned_storage_gb': total_provisioned,
            'total_used_storage_gb': round(total_used, 2),
            'global_storage_utilization_percent': round((total_used / total_provisioned * 100), 1) if total_provisioned > 0 else 0,
            'all_results': all_results,
            'non_compliant_items': non_compliant_items,
            'error_items': error_items,
            'error_regions': error_regions
        }
        
    except Exception as e:
        raise RuntimeError(f"Failed to check EC2 storage across regions: {str(e)}") from e


def determine_ec2_storage_status(stats: Dict[str, Any]) -> tuple:
    """
    Determine overall status based on EC2 storage analysis statistics
    
    Args:
        stats: Dictionary containing analysis statistics
        
    Returns:
        tuple: (status, message)
    """
    total_instances = stats['total_instances']
    non_compliant_count = stats['non_compliant_instances']
    error_count = stats['error_instances']
    
    if error_count > 0 and total_instances == 0:
        return ('Error', f'Failed to analyze EC2 storage: {error_count} regions had errors')
    elif total_instances == 0:
        return ('Pass', 'No running EC2 instances found in any region')
    elif non_compliant_count == 0:
        return ('Pass', f'All {total_instances} EC2 instances have optimal storage configuration')
    elif non_compliant_count == total_instances:
        return ('Fail', f'All {total_instances} EC2 instances have storage optimization opportunities')
    else:
        return ('Warning', f'{non_compliant_count} out of {total_instances} EC2 instances have storage optimization opportunities')


def check_ec2_storage(profile_name: Optional[str] = None, max_workers: int = 5) -> Dict[str, Any]:
    """
    Main function to check EC2 storage capacity across all regions
    
    Args:
        profile_name: AWS profile name (optional)
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
            # Perform the EC2 storage check
            result = check_ec2_storage_all_regions(max_workers)
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        status, message = determine_ec2_storage_status(result)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'ec2_storage_capacity',
            'total_regions_checked': result['total_regions_checked'],
            'total_instances': result['total_instances'],
            'compliant_instances': result['compliant_instances'],
            'non_compliant_instances': result['non_compliant_instances'],
            'error_instances': result['error_instances'],
            'ssm_available_instances': result['ssm_available_instances'],
            'high_usage_instances': result['high_usage_instances'],
            'total_provisioned_storage_gb': result['total_provisioned_storage_gb'],
            'total_used_storage_gb': result['total_used_storage_gb'],
            'global_storage_utilization_percent': result['global_storage_utilization_percent'],
            'non_compliant_items': result['non_compliant_items']
        }
        
        return final_result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found or invalid',
            'check_type': 'ec2_storage_capacity',
            'non_compliant_items': []
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': 'Insufficient permissions to check EC2 storage',
                'check_type': 'ec2_storage_capacity',
                'non_compliant_items': []
            }
        else:
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': f'AWS API error: {error_code}',
                'check_type': 'ec2_storage_capacity',
                'non_compliant_items': []
            }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error during EC2 storage check: {str(e)}',
            'check_type': 'ec2_storage_capacity',
            'non_compliant_items': []
        }


# Console output functions for backwards compatibility
def print_instance_details(instance_info: Dict[str, Any], index: int) -> None:
    """Print detailed information about an instance"""
    print(f"  {index}. Instance: {instance_info['instance_id']} ({instance_info['name']})")
    print(f"     Type: {instance_info['instance_type']}")
    print(f"     Platform: {instance_info['platform']}")
    print(f"     Region: {instance_info['region']}")
    
    if instance_info.get('ssm_available', False):
        print(f"     Provisioned: {instance_info['total_provisioned_gb']} GB")
        print(f"     Used: {instance_info['total_used_gb']} GB")
        print(f"     Available: {instance_info['total_available_gb']} GB")
        print(f"     Usage: {instance_info['overall_usage_percent']}%")
        print(f"     Utilization: {instance_info['storage_utilization_ratio']}% of provisioned")
        
        # Show high usage storage
        storage_data = instance_info.get('storage_data', [])
        critical_items = [item for item in storage_data if item.get('critical_usage', False)]
        high_items = [item for item in storage_data if item.get('high_usage', False) and not item.get('critical_usage', False)]
        
        if critical_items:
            print(f"     🚨 Critical: {len(critical_items)} volume(s) >90% usage")
        elif high_items:
            print(f"     ⚠️  Warning: {len(high_items)} volume(s) >80% usage")
    else:
        print(f"     ❌ SSM unavailable: {instance_info.get('error', 'Unknown error')}")
    
    if instance_info.get('non_compliant_reasons'):
        print(f"     Issues: {', '.join(instance_info['non_compliant_reasons'])}")


def print_basic_summary(result: Dict[str, Any]) -> None:
    """Print basic summary information"""
    print("EC2 Storage Capacity Analysis Summary")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Regions Checked: {result.get('total_regions_checked', 'N/A')}")
    print(f"Total Instances: {result.get('total_instances', 'N/A')}")
    print(f"Compliant: {result.get('compliant_instances', 'N/A')}")
    print(f"Non-Compliant: {result.get('non_compliant_instances', 'N/A')}")
    print(f"SSM Available: {result.get('ssm_available_instances', 'N/A')}")
    print(f"High Usage: {result.get('high_usage_instances', 'N/A')} instances")
    print(f"Total Provisioned: {result.get('total_provisioned_storage_gb', 'N/A')} GB")
    print(f"Total Used: {result.get('total_used_storage_gb', 'N/A')} GB")
    print(f"Global Utilization: {result.get('global_storage_utilization_percent', 'N/A')}%")


def print_non_compliant_instances(instances: List[Dict[str, Any]]) -> None:
    """Print details of non-compliant instances"""
    if instances:
        print(f"\nInstances with Storage Optimization Opportunities ({len(instances)}):")
        for i, instance in enumerate(instances, 1):
            print_instance_details(instance, i)


def print_summary_output(result: Dict[str, Any]) -> None:
    """Print human-readable summary output"""
    print_basic_summary(result)
    
    non_compliant_items = result.get('non_compliant_items', [])
    print_non_compliant_instances(non_compliant_items)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check EC2 storage capacity optimization opportunities")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    parser.add_argument('--max-workers', type=int, default=5,
                       help='Maximum number of concurrent workers (default: 5)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_ec2_storage(
        profile_name=args.profile,
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
