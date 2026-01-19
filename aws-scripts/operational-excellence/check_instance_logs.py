#!/usr/bin/env python3
"""
Instance Log Configuration Checker

Check whether EC2 instances are configured with SSM management and the
CloudWatch Agent, and report configured log groups.
"""

import boto3
import json
import sys
import time
from datetime import datetime, timezone
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
            'eu-west-2', 'us-west-2', 'eu-west-1', 'eu-central-1'
        ]


def get_managed_instance_ids(ssm_client) -> Tuple[List[str], Optional[str]]:
    """Get list of SSM managed instance IDs."""
    try:
        managed_instance_ids = []
        paginator = ssm_client.get_paginator('describe_instance_information')
        for page in paginator.paginate():
            managed_instance_ids.extend(
                instance['InstanceId']
                for instance in page['InstanceInformationList']
            )
        return managed_instance_ids, None
    except ClientError as e:
        return [], e.response['Error']['Code']


def check_cloudwatch_agent_via_ssm(
    ssm_client,
    instance_id: str,
    is_windows: bool,
    timeout_seconds: int = 60,
    poll_interval_seconds: int = 3
) -> Tuple[bool, Optional[str], List[str]]:
    """Use SSM Run Command to check CloudWatch Agent presence/config."""
    try:
        if is_windows:
            command = [
                '$agentExe = "C:\\Program Files\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent.exe"',
                '$ctlPath = "C:\\Program Files\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent-ctl.ps1"',
                '$configJson = "C:\\ProgramData\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent.json"',
                '$configToml = "C:\\ProgramData\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent.toml"',
                'if (Test-Path $agentExe -or Test-Path $ctlPath) {',
                '  $service = Get-Service -Name AmazonCloudWatchAgent -ErrorAction SilentlyContinue',
                '  if ($service) {',
                '    if ($service.Status -eq "Running") { "cwagent_status=running" } else { "cwagent_status=stopped" }',
                '  } else {',
                '    "cwagent_status=unknown"',
                '  }',
                '  $logGroups = @()',
                '  foreach ($path in @($configJson, $configToml)) {',
                '    if (Test-Path $path) {',
                '      $content = Get-Content $path -Raw',
                '      foreach ($m in [regex]::Matches($content, \'"log_group_name"\\s*:\\s*"([^"]+)"\')) { $logGroups += $m.Groups[1].Value }',
                '      foreach ($m in [regex]::Matches($content, \'log_group_name\\s*=\\s*"([^"]+)"\')) { $logGroups += $m.Groups[1].Value }',
                '    }',
                '  }',
                '  $logGroups = $logGroups | Sort-Object -Unique',
                '  if ((Test-Path $configJson) -or (Test-Path $configToml)) { "cwagent_config_present" } else { "cwagent_config_missing" }',
                '  "cwagent_log_groups=" + ($logGroups -join ",")',
                '} else {',
                '  "cwagent_not_found"',
                '}'
            ]

            response = ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName='AWS-RunPowerShellScript',
                Parameters={'commands': command}
            )
        else:
            command = [
                'if [ -x /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl ]; then',
                '  status_output=$(/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a status 2>&1 || true);',
                '  echo "$status_output";',
                '  if echo "$status_output" | grep -qi "running"; then',
                '    echo "cwagent_status=running";',
                '  elif echo "$status_output" | grep -qi "stopped\\|inactive"; then',
                '    echo "cwagent_status=stopped";',
                '  else',
                '    echo "cwagent_status=unknown";',
                '  fi;',
                '  log_groups="";',
                '  if [ -f /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json ]; then',
                '    log_groups="$log_groups $(grep -oE \'"log_group_name"\\s*:\\s*"[^"]+"\' '
                '/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json '
                '| sed -E \'s/.*"log_group_name"\\s*:\\s*"([^"]+)".*/\\1/\')";',
                '  fi;',
                '  if [ -f /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.toml ]; then',
                '    log_groups="$log_groups $(grep -oE \'log_group_name\\s*=\\s*"[^"]+"\' '
                '/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.toml '
                '| sed -E \'s/.*log_group_name\\s*=\\s*"([^"]+)".*/\\1/\')";',
                '  fi;',
                '  log_groups=$(echo "$log_groups" | tr " " "\\n" | sed \'/^$/d\' | sort -u | paste -sd "," -);',
                '  if [ -f /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json ] || '
                '[ -f /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.toml ]; then',
                '    echo "cwagent_config_present";',
                '  else',
                '    echo "cwagent_config_missing";',
                '  fi;',
                '  echo "cwagent_log_groups=$log_groups";',
                'else',
                '  echo "cwagent_not_found";',
                'fi'
            ]

            response = ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName='AWS-RunShellScript',
                Parameters={'commands': [' '.join(command)]}
            )

        command_id = response['Command']['CommandId']

        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            try:
                invocation = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id
                )
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'InvocationDoesNotExist':
                    time.sleep(poll_interval_seconds)
                    continue
                return False, error_code, []

            status = invocation.get('Status', '')
            if status in ['Success', 'Cancelled', 'TimedOut', 'Failed', 'Cancelled']:
                stdout = invocation.get('StandardOutputContent', '')
                stderr = invocation.get('StandardErrorContent', '')

                if status != 'Success':
                    reason = stderr.strip() or f'Run Command status {status}'
                    return False, reason, []

                output = f'{stdout}\n{stderr}'
                output_lower = output.lower()
                log_groups = []
                for line in output.splitlines():
                    if line.startswith('cwagent_log_groups='):
                        raw = line.split('=', 1)[1].strip()
                        if raw:
                            log_groups = [item for item in raw.split(',') if item]
                        break

                status_line = None
                for line in output.splitlines():
                    if line.startswith('cwagent_status='):
                        status_line = line.split('=', 1)[1].strip().lower()
                        break

                if 'cwagent_not_found' in output_lower:
                    return False, 'CloudWatch Agent binary not found', log_groups
                if 'cwagent_config_missing' in output_lower:
                    return False, 'CloudWatch Agent config not found', log_groups
                if status_line == 'running':
                    return True, None, log_groups
                if status_line == 'stopped':
                    return False, 'CloudWatch Agent not running', log_groups
                if 'cwagent_config_present' in output_lower:
                    return True, None, log_groups
                return False, 'Unable to determine CloudWatch Agent status', log_groups

            time.sleep(poll_interval_seconds)

        return False, 'Run Command timed out', []
    except ClientError as e:
        return False, e.response['Error']['Code'], []


def check_instance_logs_in_region(region: str) -> List[Dict[str, Any]]:
    """
    Check instance log configuration in a specific region.
    
    Args:
        region: AWS region to check
        
    Returns:
        List of instances without required configuration
    """
    instance_items = []
    
    try:
        ec2_client = boto3.client('ec2', region_name=region)
        ssm_client = boto3.client('ssm', region_name=region)
        
        # Get running instances
        instances_response = ec2_client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        
        managed_instance_ids, managed_error = get_managed_instance_ids(ssm_client)
        if managed_error:
            instance_items.append({
                'region': region,
                'error': f'Failed to list SSM managed instances: {managed_error}',
                'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
            })
            return instance_items

        managed_instance_ids = set(managed_instance_ids)

        for reservation in instances_response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_type = instance.get('InstanceType', 'unknown')
                platform = instance.get('Platform', '')
                platform_details = instance.get('PlatformDetails', '')
                is_windows = (
                    (platform and platform.lower() == 'windows') or
                    (platform_details and 'windows' in platform_details.lower())
                )
                
                if instance_id not in managed_instance_ids:
                    instance_items.append({
                        'instance_id': instance_id,
                        'instance_type': instance_type,
                        'region': region,
                        'platform': 'windows' if is_windows else 'linux',
                        'log_groups': [],
                        'status': 'non_compliant',
                        'reason': 'Not managed by SSM',
                        'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
                    })
                    continue

                agent_ok, agent_reason, log_groups = check_cloudwatch_agent_via_ssm(
                    ssm_client, instance_id, is_windows
                )

                instance_item = {
                    'instance_id': instance_id,
                    'instance_type': instance_type,
                    'region': region,
                    'platform': 'windows' if is_windows else 'linux',
                    'log_groups': log_groups,
                    'status': 'compliant' if agent_ok else 'non_compliant',
                    'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
                }

                if not agent_ok:
                    instance_item['reason'] = agent_reason or 'CloudWatch Agent not detected via SSM Run Command'

                instance_items.append(instance_item)
    
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code not in ['UnauthorizedOperation', 'AccessDenied']:
            instance_items.append({
                'region': region,
                'error': f'Failed to check region {region}: {error_code}',
                'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
            })
    
    return instance_items


def check_instance_logs_all_regions(max_workers: int = 5) -> Dict[str, Any]:
    """
    Check instance log configuration across all regions.
    
    Args:
        max_workers: Maximum number of concurrent workers
        
    Returns:
        Dictionary containing aggregated results
    """
    regions = get_enabled_regions()
    all_instance_items = []
    total_regions_checked = 0
    error_count = 0
    non_compliant_items = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit tasks for all regions
        future_to_region = {
            executor.submit(check_instance_logs_in_region, region): region 
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
                    all_instance_items.extend(region_results)
                    non_compliant_items.extend(
                        item for item in region_results if item.get('status') == 'non_compliant'
                    )
                
            except Exception as e:
                error_count += 1
                all_instance_items.append({
                    'region': region,
                    'error': f'Failed to process region {region}: {str(e)}',
                    'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
                })
    
    # Filter out error entries for statistics
    valid_instances = [item for item in all_instance_items if 'error' not in item]
    
    return {
        'total_regions_checked': total_regions_checked,
        'instances_without_logs': len(non_compliant_items),
        'error_count': error_count,
        'instance_items': all_instance_items,
        'non_compliant_items': non_compliant_items
    }


def determine_instance_logs_status(stats: Dict[str, Any]) -> Tuple[str, str]:
    """
    Determine the overall status based on instance configuration check results.
    
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
        return 'Pass', 'All instances are configured with SSM and CloudWatch Agent'
    else:
        return 'Fail', f'Found {instances_without_logs} instances without required configuration'


def check_instance_logs(profile_name: Optional[str] = None, max_workers: int = 5) -> Dict[str, Any]:
    """
    Main function to check instance log configuration across all regions
    
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
            # Perform the instance logs check
            result = check_instance_logs_all_regions(max_workers)
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
            'total_regions_checked': result['total_regions_checked'],
            'instances_without_logs': result['instances_without_logs'],
            'error_count': result['error_count'],
            'non_compliant_items': result['non_compliant_items'],
            'instance_items': result['instance_items']
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
    
    parser = argparse.ArgumentParser(
        description="Check if EC2 instances are configured with SSM and CloudWatch Agent, and list log groups"
    )
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--max-workers', type=int, default=5,
                       help='Maximum number of concurrent workers (default: 5)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_instance_logs(
        profile_name=args.profile,
        max_workers=args.max_workers
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
