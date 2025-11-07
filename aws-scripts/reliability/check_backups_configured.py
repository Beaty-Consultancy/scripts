#!/usr/bin/env python3
"""
AWS Backup Configuration Check Script

This script checks if AWS Backup is properly configured by examining:
- Backup vaults and their protected resources
- Total number of vaults and protected resources
- Resource breakdown by type

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime
from collections import defaultdict

# Constants
MIN_PROTECTED_RESOURCES = 1
MIN_BACKUP_VAULTS = 1


def get_resource_name(tags, resource_id):
    """Extract resource name from tags or use resource ID as fallback"""
    if tags:
        for tag in tags:
            if tag.get('Key', '').lower() == 'name':
                return tag.get('Value', resource_id)
    return resource_id


def create_vault_info(vault_name, vault_arn, region_name, vault, tags, display_name, has_policy, has_notifications, sns_topic_arn, backup_vault_events):
    """Create vault information dictionary"""
    return {
        'vaultName': vault_name,
        'displayName': display_name,
        'vaultArn': vault_arn,
        'region': region_name,
        'creationDate': vault.get('CreationDate', '').isoformat() if vault.get('CreationDate') else '',
        'encryptionKeyArn': vault.get('EncryptionKeyArn', ''),
        'numberOfRecoveryPoints': vault.get('NumberOfRecoveryPoints', 0),
        'locked': vault.get('Locked', False),
        'hasPolicy': has_policy,
        'hasNotifications': has_notifications,
        'snsTopicArn': sns_topic_arn,
        'backupVaultEvents': backup_vault_events,
        'tags': tags
    }


def create_basic_vault_info(vault_name, vault_arn, region_name, vault, error_message):
    """Create basic vault information dictionary with error"""
    return {
        'vaultName': vault_name,
        'displayName': vault_name,
        'vaultArn': vault_arn,
        'region': region_name,
        'creationDate': vault.get('CreationDate', '').isoformat() if vault.get('CreationDate') else '',
        'encryptionKeyArn': vault.get('EncryptionKeyArn', ''),
        'numberOfRecoveryPoints': vault.get('NumberOfRecoveryPoints', 0),
        'locked': vault.get('Locked', False),
        'hasPolicy': False,
        'hasNotifications': False,
        'snsTopicArn': '',
        'backupVaultEvents': [],
        'tags': {},
        'error': error_message
    }


def get_vault_policy_and_notifications(backup_client, vault_name):
    """Get vault policy and notification settings"""
    # Get vault access policy
    try:
        backup_client.get_backup_vault_access_policy(BackupVaultName=vault_name)
        has_policy = True
    except ClientError:
        has_policy = False
    
    # Get vault notifications
    try:
        notifications_response = backup_client.get_backup_vault_notifications(BackupVaultName=vault_name)
        has_notifications = True
        sns_topic_arn = notifications_response.get('SNSTopicArn', '')
        backup_vault_events = notifications_response.get('BackupVaultEvents', [])
    except ClientError:
        has_notifications = False
        sns_topic_arn = ''
        backup_vault_events = []
    
    return has_policy, has_notifications, sns_topic_arn, backup_vault_events


def get_backup_vaults(session, region_name):
    """Get all backup vaults in a region"""
    try:
        backup_client = session.client('backup', region_name=region_name)
        
        vaults = []
        
        # List all backup vaults
        paginator = backup_client.get_paginator('list_backup_vaults')
        for page in paginator.paginate():
            for vault in page.get('BackupVaultList', []):
                vault_name = vault['BackupVaultName']
                vault_arn = vault['BackupVaultArn']
                
                try:
                    # Get vault tags
                    tags_response = backup_client.list_tags(ResourceArn=vault_arn)
                    tags = tags_response.get('Tags', {})
                    display_name = get_resource_name([{'Key': k, 'Value': v} for k, v in tags.items()], vault_name)
                    
                    # Get vault policy and notifications
                    has_policy, has_notifications, sns_topic_arn, backup_vault_events = get_vault_policy_and_notifications(backup_client, vault_name)
                    
                    vaults.append(create_vault_info(
                        vault_name, vault_arn, region_name, vault, tags, display_name,
                        has_policy, has_notifications, sns_topic_arn, backup_vault_events
                    ))
                except Exception as e:
                    # Add basic vault info if detailed info fails
                    vaults.append(create_basic_vault_info(
                        vault_name, vault_arn, region_name, vault, f'Failed to get vault details: {str(e)}'
                    ))
        
        return vaults
        
    except ClientError as e:
        return {'error': f'Backup Vaults error: {e.response["Error"]["Code"]}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


def extract_plan_names_from_recovery_points(recovery_points):
    """Extract unique backup plan names from recovery points"""
    plan_names_set = set()
    for point in recovery_points:
        backup_plan_arn = point.get('BackupPlanArn', '')
        if backup_plan_arn:
            # Extract plan name from ARN (format: arn:aws:backup:region:account:backup-plan:plan-id/plan-name)
            try:
                plan_name = backup_plan_arn.split('/')[-1] if '/' in backup_plan_arn else backup_plan_arn.split(':')[-1]
                plan_names_set.add(plan_name)
            except Exception:
                pass
    return list(plan_names_set)


def get_latest_recovery_point_date(recovery_points):
    """Get the latest recovery point creation date"""
    if recovery_points:
        # Sort by creation date and get the latest
        sorted_points = sorted(recovery_points, key=lambda x: x.get('CreationDate', ''), reverse=True)
        return sorted_points[0].get('CreationDate', '').isoformat() if sorted_points[0].get('CreationDate') else ''
    return ''


def get_resource_backup_info(backup_client, resource_arn):
    """Get backup plans and recovery points for a resource"""
    # Initialize variables
    backup_plan_count = 0
    plan_names = []
    recovery_point_count = 0
    latest_recovery_point = ''
    
    # Get recovery points for this resource
    try:
        recovery_response = backup_client.list_recovery_points_by_resource(ResourceArn=resource_arn)
        recovery_points = recovery_response.get('RecoveryPoints', [])
        recovery_point_count = len(recovery_points)
        
        if recovery_points:
            latest_recovery_point = get_latest_recovery_point_date(recovery_points)
            plan_names = extract_plan_names_from_recovery_points(recovery_points)
            backup_plan_count = len(plan_names)
    except (ClientError, Exception):
        pass
    
    return backup_plan_count, plan_names, recovery_point_count, latest_recovery_point


def create_protected_resource_info(resource_arn, resource_type, region_name, resource, backup_plan_count, plan_names, recovery_point_count, latest_recovery_point):
    """Create protected resource information dictionary"""
    resource_id = resource_arn.split('/')[-1] if '/' in resource_arn else resource_arn.split(':')[-1]
    
    return {
        'resourceArn': resource_arn,
        'resourceId': resource_id,
        'resourceType': resource_type,
        'region': region_name,
        'lastBackupTime': resource.get('LastBackupTime', '').isoformat() if resource.get('LastBackupTime') else '',
        'backupPlanCount': backup_plan_count,
        'backupPlanNames': plan_names,
        'recoveryPointCount': recovery_point_count,
        'latestRecoveryPoint': latest_recovery_point
    }


def create_basic_protected_resource_info(resource_arn, resource_type, region_name, resource, error_message):
    """Create basic protected resource information dictionary with error"""
    resource_id = resource_arn.split('/')[-1] if '/' in resource_arn else resource_arn.split(':')[-1]
    
    return {
        'resourceArn': resource_arn,
        'resourceId': resource_id,
        'resourceType': resource_type,
        'region': region_name,
        'lastBackupTime': resource.get('LastBackupTime', '').isoformat() if resource.get('LastBackupTime') else '',
        'backupPlanCount': 0,
        'backupPlanNames': [],
        'recoveryPointCount': 0,
        'latestRecoveryPoint': '',
        'error': error_message
    }


def get_protected_resources(session, region_name):
    """Get all protected resources in a region"""
    try:
        backup_client = session.client('backup', region_name=region_name)
        
        protected_resources = []
        resource_counts = defaultdict(int)
        
        # List all protected resources
        paginator = backup_client.get_paginator('list_protected_resources')
        for page in paginator.paginate():
            for resource in page.get('Results', []):
                resource_arn = resource['ResourceArn']
                resource_type = resource['ResourceType']
                
                try:
                    # Get backup information for this resource
                    backup_plan_count, plan_names, recovery_point_count, latest_recovery_point = get_resource_backup_info(backup_client, resource_arn)
                    
                    protected_resources.append(create_protected_resource_info(
                        resource_arn, resource_type, region_name, resource,
                        backup_plan_count, plan_names, recovery_point_count, latest_recovery_point
                    ))
                    
                    # Count by resource type
                    resource_counts[resource_type] += 1
                    
                except Exception as e:
                    # Add basic resource info if detailed info fails
                    protected_resources.append(create_basic_protected_resource_info(
                        resource_arn, resource_type, region_name, resource, f'Failed to get resource details: {str(e)}'
                    ))
                    resource_counts[resource_type] += 1
        
        return {
            'protected_resources': protected_resources,
            'resource_counts': dict(resource_counts)
        }
        
    except ClientError as e:
        return {'error': f'Protected Resources error: {e.response["Error"]["Code"]}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


def get_plan_details_and_selections(backup_client, plan_id):
    """Get backup plan details and selections"""
    try:
        # Get plan details
        plan_response = backup_client.get_backup_plan(BackupPlanId=plan_id)
        plan_details = plan_response.get('BackupPlan', {})
        rules = plan_details.get('Rules', [])
    except ClientError:
        rules = []
    
    # Get plan selections (resources covered by this plan)
    try:
        selections_response = backup_client.list_backup_selections(BackupPlanId=plan_id)
        selections = selections_response.get('BackupSelectionsList', [])
        selection_count = len(selections)
    except ClientError:
        selection_count = 0
    
    return rules, selection_count


def create_backup_plan_info(plan_id, plan_arn, plan_name, region_name, plan, rules, selection_count):
    """Create backup plan information dictionary"""
    return {
        'planId': plan_id,
        'planArn': plan_arn,
        'planName': plan_name,
        'region': region_name,
        'creationDate': plan.get('CreationDate', '').isoformat() if plan.get('CreationDate') else '',
        'lastExecutionDate': plan.get('LastExecutionDate', '').isoformat() if plan.get('LastExecutionDate') else '',
        'versionId': plan.get('VersionId', ''),
        'selectionCount': selection_count,
        'rules': rules
    }


def create_basic_backup_plan_info(plan_id, plan_arn, plan_name, region_name, plan, error_message):
    """Create basic backup plan information dictionary with error"""
    return {
        'planId': plan_id,
        'planArn': plan_arn,
        'planName': plan_name,
        'region': region_name,
        'creationDate': plan.get('CreationDate', '').isoformat() if plan.get('CreationDate') else '',
        'lastExecutionDate': plan.get('LastExecutionDate', '').isoformat() if plan.get('LastExecutionDate') else '',
        'versionId': plan.get('VersionId', ''),
        'selectionCount': 0,
        'rules': [],
        'error': error_message
    }


def get_backup_plans(session, region_name):
    """Get all backup plans in a region"""
    try:
        backup_client = session.client('backup', region_name=region_name)
        
        backup_plans = []
        
        # List all backup plans
        paginator = backup_client.get_paginator('list_backup_plans')
        for page in paginator.paginate():
            for plan in page.get('BackupPlansList', []):
                plan_id = plan['BackupPlanId']
                plan_arn = plan['BackupPlanArn']
                plan_name = plan['BackupPlanName']
                
                try:
                    # Get plan details and selections
                    rules, selection_count = get_plan_details_and_selections(backup_client, plan_id)
                    
                    backup_plans.append(create_backup_plan_info(
                        plan_id, plan_arn, plan_name, region_name, plan, rules, selection_count
                    ))
                except Exception as e:
                    # Add basic plan info if detailed info fails
                    backup_plans.append(create_basic_backup_plan_info(
                        plan_id, plan_arn, plan_name, region_name, plan, f'Failed to get plan details: {str(e)}'
                    ))
        
        return backup_plans
        
    except ClientError as e:
        return {'error': f'Backup Plans error: {e.response["Error"]["Code"]}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


def check_region_backup_configuration(session, region_name):
    """Check backup configuration in a specific region"""
    region_results = {
        'region': region_name,
        'backup_vaults': [],
        'protected_resources': [],
        'backup_plans': [],
        'resource_counts': {},
        'errors': []
    }
    
    # Check backup vaults
    vaults_result = get_backup_vaults(session, region_name)
    if isinstance(vaults_result, dict) and 'error' in vaults_result:
        region_results['errors'].append(f"Backup Vaults: {vaults_result['error']}")
    else:
        region_results['backup_vaults'] = vaults_result
    
    # Check protected resources
    resources_result = get_protected_resources(session, region_name)
    if isinstance(resources_result, dict) and 'error' in resources_result:
        region_results['errors'].append(f"Protected Resources: {resources_result['error']}")
    else:
        region_results['protected_resources'] = resources_result.get('protected_resources', [])
        region_results['resource_counts'] = resources_result.get('resource_counts', {})
    
    # Check backup plans
    plans_result = get_backup_plans(session, region_name)
    if isinstance(plans_result, dict) and 'error' in plans_result:
        region_results['errors'].append(f"Backup Plans: {plans_result['error']}")
    else:
        region_results['backup_plans'] = plans_result
    
    return region_results


def get_all_regions(session):
    """Get all available AWS regions"""
    try:
        ec2_client = session.client('ec2', region_name='us-east-1')
        regions_response = ec2_client.describe_regions()
        return [region['RegionName'] for region in regions_response['Regions']]
    except Exception:
        # Fallback to common regions if API call fails
        return [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1',
            'ap-northeast-2', 'ap-south-1', 'ca-central-1',
            'sa-east-1'
        ]


def analyze_backup_configuration(all_region_results):
    """Analyze the backup configuration across all regions"""
    total_vaults = 0
    total_protected_resources = 0
    total_backup_plans = 0
    total_recovery_points = 0
    regions_with_vaults = 0
    regions_with_protected_resources = 0
    regions_with_backup_plans = 0
    all_resource_counts = defaultdict(int)
    
    for region_result in all_region_results:
        vaults = region_result.get('backup_vaults', [])
        resources = region_result.get('protected_resources', [])
        plans = region_result.get('backup_plans', [])
        resource_counts = region_result.get('resource_counts', {})
        
        if vaults:
            regions_with_vaults += 1
            total_vaults += len(vaults)
            total_recovery_points += sum(vault.get('numberOfRecoveryPoints', 0) for vault in vaults)
        
        if resources:
            regions_with_protected_resources += 1
            total_protected_resources += len(resources)
        
        if plans:
            regions_with_backup_plans += 1
            total_backup_plans += len(plans)
        
        # Aggregate resource counts
        for resource_type, count in resource_counts.items():
            all_resource_counts[resource_type] += count
    
    # Determine overall status
    has_backup_configuration = total_vaults >= MIN_BACKUP_VAULTS and total_protected_resources >= MIN_PROTECTED_RESOURCES
    has_active_backups = total_recovery_points > 0 and total_backup_plans > 0
    
    if has_active_backups:
        status = 'Success'
        message = f"AWS Backup is properly configured with {total_vaults} vaults protecting {total_protected_resources} resources across {regions_with_vaults} regions."
    elif has_backup_configuration:
        status = 'Warning'
        message = f"AWS Backup components found but may not be fully active: {total_vaults} vaults, {total_protected_resources} protected resources, {total_backup_plans} backup plans."
    else:
        status = 'Warning'
        message = "No AWS Backup configuration detected. Consider setting up backup vaults and backup plans to protect your resources."
    
    return {
        'status': status,
        'message': message,
        'analysis': {
            'total_vaults': total_vaults,
            'total_protected_resources': total_protected_resources,
            'total_backup_plans': total_backup_plans,
            'total_recovery_points': total_recovery_points,
            'regions_with_vaults': regions_with_vaults,
            'regions_with_protected_resources': regions_with_protected_resources,
            'regions_with_backup_plans': regions_with_backup_plans,
            'resource_counts_by_type': dict(all_resource_counts),
            'has_backup_configuration': has_backup_configuration,
            'has_active_backups': has_active_backups
        }
    }


def create_error_result(status, message, error_type, error_message):
    """Create error result dictionary"""
    return {
        'status': status,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'regions_checked': '0',
        'total_vaults': '0',
        'total_protected_resources': '0',
        'backup_configured': False,
        'details': {
            'error_type': error_type,
            'error_message': error_message,
            'region_results': [],
            'recommendations': []
        }
    }


def process_regions(session, regions_to_check):
    """Process all regions and collect results"""
    all_region_results = []
    
    for region in regions_to_check:
        try:
            region_result = check_region_backup_configuration(session, region)
            all_region_results.append(region_result)
        except Exception as e:
            # Add error info for this region
            all_region_results.append({
                'region': region,
                'backup_vaults': [],
                'protected_resources': [],
                'backup_plans': [],
                'resource_counts': {},
                'errors': [f'Region check failed: {str(e)}']
            })
    
    return all_region_results


def check_backups_configured(profile_name=None, region_name=None):
    """
    Check AWS Backup configuration across all regions or specific region
    
    Args:
        profile_name (str): AWS profile name (optional)
        region_name (str): AWS region name (optional, if not provided checks all regions)
        
    Returns:
        dict: Structured result for dashboard compatibility
    """
    
    try:
        # Initialize session with profile
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
        else:
            session = boto3.Session()
        
        # Determine which regions to check
        if region_name:
            regions_to_check = [region_name]
        else:
            regions_to_check = get_all_regions(session)
        
        # Check each region
        all_region_results = process_regions(session, regions_to_check)
        regions_checked = len(regions_to_check)
        
        # Analyze results
        analysis = analyze_backup_configuration(all_region_results)
        
        # Generate recommendations
        recommendations = []
        if analysis['analysis']['total_vaults'] == 0:
            recommendations.append("Create backup vaults to store backup recovery points")
        if analysis['analysis']['total_backup_plans'] == 0:
            recommendations.append("Create backup plans to define backup schedules and retention policies")
        if analysis['analysis']['total_protected_resources'] == 0:
            recommendations.append("Configure backup selections to protect critical resources")
        if analysis['analysis']['total_recovery_points'] == 0 and analysis['analysis']['total_vaults'] > 0:
            recommendations.append("Ensure backup jobs are running successfully to create recovery points")
        if analysis['analysis']['has_backup_configuration']:
            recommendations.append("Test backup and restore procedures to ensure data can be recovered")
            recommendations.append("Review backup retention policies to ensure they meet compliance requirements")
        
        return {
            'status': analysis['status'],
            'message': analysis['message'],
            'timestamp': datetime.now().isoformat(),
            'regions_checked': str(regions_checked),
            'total_vaults': str(analysis['analysis']['total_vaults']),
            'total_protected_resources': str(analysis['analysis']['total_protected_resources']),
            'backup_configured': analysis['analysis']['has_active_backups'],
            'details': {
                'region_results': all_region_results,
                'analysis': analysis['analysis'],
                'resource_breakdown': analysis['analysis']['resource_counts_by_type'],
                'thresholds': {
                    'min_protected_resources': MIN_PROTECTED_RESOURCES,
                    'min_backup_vaults': MIN_BACKUP_VAULTS
                },
                'recommendations': recommendations
            }
        }
        
    except NoCredentialsError:
        return create_error_result(
            'Error',
            'AWS credentials not found. Please configure your credentials.',
            'NoCredentialsError',
            'AWS credentials not found'
        )
    
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        return create_error_result(
            'Error',
            f'AWS API error: {error_message}',
            error_code,
            error_message
        )
    
    except Exception as e:
        return create_error_result(
            'Error',
            f'Unexpected error: {str(e)}',
            'UnexpectedError',
            str(e)
        )


def print_vault_details(vault, index):
    """Print detailed information for a backup vault"""
    print(f"  {index}. {vault['displayName']} ({vault['vaultName']})")
    print(f"     Region: {vault['region']}")
    print(f"     Recovery Points: {vault['numberOfRecoveryPoints']}")
    print(f"     Locked: {'Yes' if vault['locked'] else 'No'}")
    print(f"     Has Policy: {'Yes' if vault['hasPolicy'] else 'No'}")
    print(f"     Has Notifications: {'Yes' if vault['hasNotifications'] else 'No'}")
    
    if vault['creationDate']:
        print(f"     Created: {vault['creationDate']}")
    
    if vault['encryptionKeyArn']:
        print(f"     Encryption Key: {vault['encryptionKeyArn']}")
    
    if vault.get('error'):
        print(f"     Error: {vault['error']}")
    
    print()


def print_resource_summary(resource_counts):
    """Print resource breakdown summary"""
    if resource_counts:
        print("  Resource Breakdown:")
        for resource_type, count in sorted(resource_counts.items()):
            print(f"    - {resource_type}: {count}")
    else:
        print("  No protected resources found")


def print_region_details(region_result):
    """Print details for a specific region"""
    region = region_result['region']
    vaults = region_result.get('backup_vaults', [])
    resources = region_result.get('protected_resources', [])
    plans = region_result.get('backup_plans', [])
    resource_counts = region_result.get('resource_counts', {})
    errors = region_result.get('errors', [])
    
    print(f"\n  Region: {region}")
    print(f"    Backup Vaults: {len(vaults)}")
    print(f"    Protected Resources: {len(resources)}")
    print(f"    Backup Plans: {len(plans)}")
    
    if errors:
        print(f"    Errors: {', '.join(errors)}")
    
    if resource_counts:
        print_resource_summary(resource_counts)
    
    if vaults:
        print("\n    Backup Vault Details:")
        for i, vault in enumerate(vaults, 1):
            print_vault_details(vault, i)


def print_summary_output(result):
    """Print summary output for backup configuration check"""
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Regions Checked: {result['regions_checked']}")
    print(f"Total Backup Vaults: {result['total_vaults']}")
    print(f"Total Protected Resources: {result['total_protected_resources']}")
    print(f"Backup Configured: {result['backup_configured']}")
    
    if result['details']['region_results']:
        print("\nThresholds:")
        thresholds = result['details']['thresholds']
        print(f"  - Minimum Backup Vaults: {thresholds['min_backup_vaults']}")
        print(f"  - Minimum Protected Resources: {thresholds['min_protected_resources']}")
        
        # Print overall resource breakdown
        if result['details']['resource_breakdown']:
            print("\nOverall Resource Breakdown:")
            for resource_type, count in sorted(result['details']['resource_breakdown'].items()):
                print(f"  - {resource_type}: {count}")
        
        print("\nRegion-by-Region Results:")
        for region_result in result['details']['region_results']:
            print_region_details(region_result)
    
    if result['details']['recommendations']:
        print("Recommendations:")
        for recommendation in result['details']['recommendations']:
            print(f"  - {recommendation}")


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check AWS Backup configuration')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--region', help='AWS region name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_backups_configured(
        profile_name=args.profile,
        region_name=args.region
    )
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        print_summary_output(result)


if __name__ == "__main__":
    main()
