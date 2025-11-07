#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Performance Efficiency Pillar
EC2 Supported Operating System Check

This script checks EC2 instances across all AWS regions to verify they are
running supported operating systems using SSM to query OS information.
"""

import boto3
import json
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError
import sys
from typing import Dict, List, Any, Tuple, Optional

# Constants
DEFAULT_NAME = 'No Name'
SSM_TIMEOUT = 30
MAX_COMMAND_ATTEMPTS = 6
COMMAND_WAIT_TIME = 5

# OS Release file patterns
VERSION_ID_PATTERN = 'VERSION_ID='
ID_PATTERN = 'ID='
NAME_PATTERN = 'NAME='

# Supported Operating Systems
SUPPORTED_LINUX_OS = [
    'Amazon Linux', 'CentOS', 'Red Hat Enterprise Linux',
    'SUSE Linux Enterprise Server', 'Ubuntu', 'Debian',
    'Oracle Linux', 'Rocky Linux', 'AlmaLinux'
]

SUPPORTED_WINDOWS_VERSIONS = [
    'Windows Server 2016', 'Windows Server 2019', 'Windows Server 2022',
    'Windows 10', 'Windows 11', 'Windows Server 2025'
]

# Supported Linux distribution IDs (for OS family checking)
SUPPORTED_LINUX_IDS = [
    'amazon', 'ubuntu', 'rhel', 'centos', 'sles', 
    'debian', 'rocky', 'almalinux', 'fedora'
]

# Supported Linux versions (specific version requirements)
SUPPORTED_LINUX_VERSIONS = {
    'ubuntu': ['24.04', '22.04', '20.04'],
    'amazon': ['2023', '2'],  # Amazon Linux 2023, 2
    'rhel': ['9', '8', '10'],  # RHEL 9.x, 8.x, 10.x
    'centos': ['7', '8'],  # CentOS 7.x, 8.x
    'rocky': ['9', '8', '10'],  # Rocky Linux 9.x, 8.x, 10.x
    'almalinux': ['9', '8', '10'],  # AlmaLinux 9.x, 8.x, 10.x
    'debian': ['12', '11'],  # Debian 12, 11
    'sles': ['15'],  # SUSE Linux Enterprise Server 15.x
    'fedora': ['41', '42']  # Fedora 41, 42
}


class SSMCommandError(Exception):
    """Custom exception for SSM command errors"""
    pass


def get_instance_name(instance: Dict[str, Any]) -> str:
    """
    Get instance name from tags
    
    Args:
        instance: EC2 instance data
        
    Returns:
        str: Instance name or default value
    """
    return instance.get('tags', {}).get('Name', DEFAULT_NAME)


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


def check_ssm_availability(region_name: str, instance_id: str) -> bool:
    """
    Check if SSM agent is available and responding on an instance
    
    Args:
        region_name: AWS region name
        instance_id: EC2 instance ID
        
    Returns:
        bool: True if SSM is available, False otherwise
    """
    try:
        ssm_client = boto3.client('ssm', region_name=region_name)
        response = ssm_client.describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
        )
        return len(response['InstanceInformationList']) > 0
    except Exception:
        return False


def execute_ssm_command(region_name: str, instance_id: str, commands: List[str]) -> Dict[str, Any]:
    """
    Execute SSM command on an instance
    
    Args:
        region_name: AWS region name
        instance_id: EC2 instance ID
        commands: List of shell commands to execute
        
    Returns:
        dict: Command execution results
    """
    try:
        ssm_client = boto3.client('ssm', region_name=region_name)
        
        # Send command
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': commands},
            TimeoutSeconds=30
        )
        
        command_id = response['Command']['CommandId']
        
        # Wait for command to complete
        max_attempts = 6
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


def parse_windows_system_info(command_output: str) -> Dict[str, Any]:
    """
    Parse Windows system information from command output
    
    Args:
        command_output: Raw command output from Windows
        
    Returns:
        dict: Parsed Windows OS information
    """
    os_info = {
        'os_name': 'Unknown',
        'os_version': 'Unknown',
        'os_family': 'windows',
        'supported': False
    }
    
    lines = command_output.strip().split('\n')
    for line in lines:
        if 'Caption' in line:
            os_info['os_name'] = line.split(':', 1)[-1].strip()
        elif 'Version' in line:
            os_info['os_version'] = line.split(':', 1)[-1].strip()
    
    # Check if Windows version is supported
    os_info['supported'] = any(supported in os_info['os_name'] for supported in SUPPORTED_WINDOWS_VERSIONS)
    return os_info


def parse_linux_system_info(command_output: str) -> Dict[str, Any]:
    """
    Parse Linux system information from command output
    
    Args:
        command_output: Raw command output from Linux
        
    Returns:
        dict: Parsed Linux OS information
    """
    os_info = {
        'os_name': 'Unknown',
        'os_version': 'Unknown',
        'os_family': 'linux',
        'supported': False
    }
    
    lines = command_output.strip().split('\n')
    os_id = ''
    version_id = ''
    
    for line in lines:
        if line.startswith(NAME_PATTERN):
            os_info['os_name'] = line.split('=', 1)[1].strip('"')
        elif line.startswith('VERSION='):
            os_info['os_version'] = line.split('=', 1)[1].strip('"')
        elif line.startswith(VERSION_ID_PATTERN):
            version_id = line.split('=', 1)[1].strip('"')
        elif line.startswith(ID_PATTERN):
            os_id = line.split('=', 1)[1].strip('"')
            os_info['os_family'] = os_id
    
    # Check if Linux distribution and version are supported
    if os_id and version_id:
        os_info['supported'] = check_linux_version_support(os_id, version_id)
    else:
        # Fallback to basic distribution checking if version info is missing
        os_info['supported'] = any(supported in os_info['os_family'].lower() for supported in SUPPORTED_LINUX_IDS)
    
    return os_info


def parse_os_information(command_output: str, platform: str) -> Dict[str, Any]:
    """
    Parse OS information from command output
    
    Args:
        command_output: Raw command output
        platform: Instance platform (linux/windows)
        
    Returns:
        dict: Parsed OS information
    """
    if platform.lower() == 'windows':
        return parse_windows_system_info(command_output)
    else:
        return parse_linux_system_info(command_output)


def parse_linux_os_release(command_output: str) -> Tuple[str, str]:
    """
    Parse /etc/os-release content to extract OS name and version
    
    Args:
        command_output: Output from cat /etc/os-release command
        
    Returns:
        Tuple of (os_name, os_version)
    """
    os_name = 'unknown'
    os_version = 'unknown'
    
    for line in command_output.split('\n'):
        line = line.strip()
        if line.startswith(NAME_PATTERN):
            os_name = line.split('=', 1)[1].strip('"').strip("'")
        elif line.startswith(VERSION_ID_PATTERN):
            os_version = line.split('=', 1)[1].strip('"').strip("'")
    
    return os_name, os_version


def parse_windows_os_info(command_output: str) -> Tuple[str, str]:
    """
    Parse Windows registry output to extract OS name and version
    
    Args:
        command_output: Output from Windows registry query command
        
    Returns:
        Tuple of (os_name, os_version)
    """
    os_name = 'unknown'
    os_version = 'unknown'
    
    for line in command_output.split('\n'):
        line = line.strip()
        if 'ProductName' in line and 'REG_SZ' in line:
            parts = line.split('REG_SZ')
            if len(parts) > 1:
                os_name = parts[1].strip()
        elif 'CurrentVersion' in line and 'REG_SZ' in line:
            parts = line.split('REG_SZ')
            if len(parts) > 1:
                os_version = parts[1].strip()
    
    return os_name, os_version


def check_os_support(os_name: str, platform: str) -> bool:
    """
    Check if the detected OS is supported
    
    Args:
        os_name: Operating system name
        platform: Platform type ('Linux' or 'Windows')
        
    Returns:
        bool: True if OS is supported, False otherwise
    """
    if platform == 'Linux':
        return any(supported_os.lower() in os_name.lower() for supported_os in SUPPORTED_LINUX_OS)
    elif platform == 'Windows':
        return any(supported_version in os_name for supported_version in SUPPORTED_WINDOWS_VERSIONS)
    
    return False


def check_linux_version_support(os_id: str, version: str) -> bool:
    """
    Check if a specific Linux distribution version is supported
    
    Args:
        os_id: Linux distribution ID (e.g., 'ubuntu', 'rhel')
        version: Version string (e.g., '22.04', '8.5')
        
    Returns:
        bool: True if the specific version is supported, False otherwise
    """
    if os_id.lower() not in SUPPORTED_LINUX_VERSIONS:
        return False
    
    supported_versions = SUPPORTED_LINUX_VERSIONS[os_id.lower()]
    
    # Check if the version starts with any of the supported major versions
    for supported_version in supported_versions:
        if version.startswith(supported_version):
            return True
    
    return False


def execute_ssm_os_command(ssm_client, instance_id: str, platform: str) -> str:
    """
    Execute SSM command to get OS information
    
    Args:
        ssm_client: SSM client instance
        instance_id: EC2 instance ID
        platform: Platform type ('Linux' or 'Windows')
        
    Returns:
        str: Command output
        
    Raises:
        Exception: If command execution fails
    """
    if platform == 'Linux':
        command = 'cat /etc/os-release'
        document_name = 'AWS-RunShellScript'
    else:  # Windows
        command = 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" /v ProductName /v CurrentVersion'
        document_name = 'AWS-RunPowerShellScript'
    
    try:
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName=document_name,
            Parameters={'commands': [command]},
            TimeoutSeconds=SSM_TIMEOUT
        )
        
        command_id = response['Command']['CommandId']
        
        # Wait for command to complete with retries
        for _ in range(MAX_COMMAND_ATTEMPTS):
            time.sleep(COMMAND_WAIT_TIME)
            
            result = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            
            if result['Status'] in ['Success', 'Failed']:
                if result['Status'] == 'Success':
                    return result['StandardOutputContent']
                else:
                    raise SSMCommandError(f"SSM command failed: {result.get('StandardErrorContent', 'Unknown error')}")
        
        raise SSMCommandError("SSM command timed out")
        
    except Exception as e:
        raise SSMCommandError(f"Failed to execute SSM command: {str(e)}") from e


def create_instance_result(instance: Dict[str, Any], status: str, reason: str, 
                          ssm_status: str = 'unknown', os_name: str = 'unknown', 
                          os_version: str = 'unknown', supported: bool = False, 
                          error: Optional[str] = None) -> Dict[str, Any]:
    """
    Create standardized instance result dictionary
    
    Args:
        instance: EC2 instance data
        status: Status of the check
        reason: Reason for the status
        ssm_status: SSM agent status
        os_name: Operating system name
        os_version: Operating system version
        supported: Whether OS is supported
        error: Error message if any
        
    Returns:
        Dict containing instance check results
    """
    result = {
        'instance_id': instance.get('instance_id', DEFAULT_NAME),
        'name': get_instance_name(instance),
        'instance_type': instance.get('instance_type', DEFAULT_NAME),
        'platform': instance.get('platform', 'unknown'),
        'region': instance.get('region', 'unknown'),
        'launch_time': instance.get('launch_time', '').isoformat() if hasattr(instance.get('launch_time', ''), 'isoformat') else str(instance.get('launch_time', '')),
        'ssm_available': ssm_status == 'available',
        'os_info': {
            'os_name': os_name,
            'os_version': os_version,
            'os_family': instance.get('platform', 'unknown'),
            'supported': supported
        },
        'non_compliant': not supported or status == 'error',
        'non_compliant_reasons': [reason] if not supported or status == 'error' else []
    }
    
    if error:
        result['error'] = error
    
    return result


def get_linux_version_support(command_output: str, os_name: str) -> bool:
    """
    Determine Linux version support from command output
    
    Args:
        command_output: Raw SSM command output
        os_name: Parsed OS name
        
    Returns:
        bool: True if Linux version is supported
    """
    lines = command_output.split('\n')
    os_id = ''
    version_id = ''
    
    for line in lines:
        line = line.strip()
        if line.startswith(ID_PATTERN):
            os_id = line.split('=', 1)[1].strip('"').strip("'")
        elif line.startswith(VERSION_ID_PATTERN):
            version_id = line.split('=', 1)[1].strip('"').strip("'")
    
    # Use version-aware checking for Linux
    if os_id and version_id:
        return check_linux_version_support(os_id, version_id)
    else:
        # Fallback to basic OS name checking
        return check_os_support(os_name, 'Linux')


def analyze_instance_os(region_name: str, instance: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze operating system for a single EC2 instance
    
    Args:
        region_name: AWS region name
        instance: Instance information
        
    Returns:
        dict: Instance OS analysis data
    """
    instance_id = instance['instance_id']
    platform = instance['platform']
    
    # Check SSM availability
    ssm_available = check_ssm_availability(region_name, instance_id)
    
    if not ssm_available:
        return create_instance_result(
            instance, 'non_compliant', 'SSM agent not available',
            ssm_status='unavailable', supported=False
        )
    
    # Get OS information via SSM
    try:
        ssm_client = boto3.client('ssm', region_name=region_name)
        command_output = execute_ssm_os_command(ssm_client, instance_id, platform)
        
        # Parse OS information
        if platform.lower() == 'windows':
            os_name, os_version = parse_windows_os_info(command_output)
            supported = check_os_support(os_name, platform)
        else:
            os_name, os_version = parse_linux_os_release(command_output)
            supported = get_linux_version_support(command_output, os_name)
        
        return create_instance_result(
            instance, 'compliant' if supported else 'non_compliant',
            'Supported OS' if supported else f'Unsupported OS: {os_name}',
            ssm_status='available', os_name=os_name, os_version=os_version,
            supported=supported
        )
        
    except SSMCommandError as e:
        return create_instance_result(
            instance, 'error', 'Failed to get OS information',
            ssm_status='available', error=str(e)
        )
    except Exception as e:
        return create_instance_result(
            instance, 'error', 'Analysis failed',
            ssm_status='unknown', error=str(e)
        )


def check_ec2_os_for_region(region_name: str) -> Dict[str, Any]:
    """
    Check EC2 operating systems for a specific region
    
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
                analysis = analyze_instance_os(region_name, instance)
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


def check_ec2_os_all_regions(max_workers: int = 5) -> Dict[str, Any]:
    """
    Check EC2 operating systems across all AWS regions
    
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
                executor.submit(check_ec2_os_for_region, region): region 
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
        
        # Supported OS instances
        supported_os = len([item for item in all_results 
                           if item.get('os_info', {}).get('supported', False)])
        
        return {
            'total_regions_checked': len(regions),
            'total_instances': total_instances,
            'compliant_instances': compliant_count,
            'non_compliant_instances': non_compliant_count,
            'error_instances': error_count,
            'ssm_available_instances': ssm_available,
            'supported_os_instances': supported_os,
            'all_results': all_results,
            'non_compliant_items': non_compliant_items,
            'error_items': error_items,
            'error_regions': error_regions
        }
        
    except Exception as e:
        raise RuntimeError(f"Failed to check EC2 OS across regions: {str(e)}") from e


def determine_ec2_os_status(stats: Dict[str, Any]) -> tuple:
    """
    Determine overall status based on EC2 OS analysis statistics
    
    Args:
        stats: Dictionary containing analysis statistics
        
    Returns:
        tuple: (status, message)
    """
    total_instances = stats['total_instances']
    non_compliant_count = stats['non_compliant_instances']
    error_count = stats['error_instances']
    
    if error_count > 0 and total_instances == 0:
        return ('Error', f'Failed to analyze EC2 operating systems: {error_count} regions had errors')
    elif total_instances == 0:
        return ('Pass', 'No running EC2 instances found in any region')
    elif non_compliant_count == 0:
        return ('Pass', f'All {total_instances} EC2 instances are running supported operating systems')
    elif non_compliant_count == total_instances:
        return ('Fail', f'All {total_instances} EC2 instances have unsupported operating systems or detection issues')
    else:
        return ('Warning', f'{non_compliant_count} out of {total_instances} EC2 instances have unsupported operating systems or detection issues')


def check_ec2_supported_os(profile_name: Optional[str] = None, max_workers: int = 5) -> Dict[str, Any]:
    """
    Main function to check EC2 supported operating systems across all regions
    
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
            # Perform the EC2 OS check
            result = check_ec2_os_all_regions(max_workers)
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        status, message = determine_ec2_os_status(result)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'ec2_supported_os',
            'total_regions_checked': result['total_regions_checked'],
            'total_instances': result['total_instances'],
            'compliant_instances': result['compliant_instances'],
            'non_compliant_instances': result['non_compliant_instances'],
            'error_instances': result['error_instances'],
            'ssm_available_instances': result['ssm_available_instances'],
            'supported_os_instances': result['supported_os_instances'],
            'non_compliant_items': result['non_compliant_items']
        }
        
        return final_result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found or invalid',
            'check_type': 'ec2_supported_os',
            'non_compliant_items': []
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': 'Insufficient permissions to check EC2 operating systems',
                'check_type': 'ec2_supported_os',
                'non_compliant_items': []
            }
        else:
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': f'AWS API error: {error_code}',
                'check_type': 'ec2_supported_os',
                'non_compliant_items': []
            }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error during EC2 OS check: {str(e)}',
            'check_type': 'ec2_supported_os',
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
        os_info = instance_info.get('os_info', {})
        print(f"     OS: {os_info.get('os_name', 'Unknown')} {os_info.get('os_version', '')}")
        print(f"     OS Family: {os_info.get('os_family', 'Unknown')}")
        print(f"     Supported: {'✅ Yes' if os_info.get('supported', False) else '❌ No'}")
    else:
        print("     ❌ SSM unavailable")
    
    if instance_info.get('non_compliant_reasons'):
        print(f"     Issues: {', '.join(instance_info['non_compliant_reasons'])}")


def print_basic_summary(result: Dict[str, Any]) -> None:
    """Print basic summary information"""
    print("EC2 Supported Operating System Check Summary")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Regions Checked: {result.get('total_regions_checked', 'N/A')}")
    print(f"Total Instances: {result.get('total_instances', 'N/A')}")
    print(f"Compliant: {result.get('compliant_instances', 'N/A')}")
    print(f"Non-Compliant: {result.get('non_compliant_instances', 'N/A')}")
    print(f"SSM Available: {result.get('ssm_available_instances', 'N/A')}")
    print(f"Supported OS: {result.get('supported_os_instances', 'N/A')}")


def print_non_compliant_instances(instances: List[Dict[str, Any]]) -> None:
    """Print details of non-compliant instances"""
    if instances:
        print(f"\nInstances with Unsupported OS or Detection Issues ({len(instances)}):")
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
    
    parser = argparse.ArgumentParser(description="Check EC2 instances for supported operating systems")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    parser.add_argument('--max-workers', type=int, default=5,
                       help='Maximum number of concurrent workers (default: 5)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_ec2_supported_os(
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
