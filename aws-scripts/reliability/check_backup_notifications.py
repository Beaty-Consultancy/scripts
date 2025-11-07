#!/usr/bin/env python3
"""
AWS Backup Notifications Check Script

This script checks if backup alerts are properly configured by examining:
- EventBridge rules for backup failure events
- SNS topics for backup alerts

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime

# Constants
BACKUP_FAILED_RULE_PATTERN = "backup-failed"
BACKUP_ALERTS_TOPIC_PATTERN = "Backup-Alerts"
ERROR_UNABLE_TO_RETRIEVE = "Unable to retrieve"


def get_resource_name(tags, resource_id):
    """Extract resource name from tags or use resource ID as fallback"""
    if tags:
        for tag in tags:
            if tag.get('Key', '').lower() == 'name':
                return tag.get('Value', resource_id)
    return resource_id


def create_eventbridge_rule_info(rule_name, rule_arn, region_name, rule, rule_details, targets):
    """Create eventbridge rule information dictionary"""
    return {
        'ruleName': rule_name,
        'ruleArn': rule_arn,
        'region': region_name,
        'state': rule.get('State', 'UNKNOWN'),
        'description': rule.get('Description', ''),
        'eventPattern': rule_details.get('EventPattern', ''),
        'scheduleExpression': rule_details.get('ScheduleExpression', ''),
        'targetCount': len(targets),
        'targets': [
            {
                'id': target.get('Id', ''),
                'arn': target.get('Arn', ''),
                'type': 'SNS' if 'sns' in target.get('Arn', '').lower() else 'Other'
            }
            for target in targets
        ]
    }


def create_basic_eventbridge_rule_info(rule_name, rule_arn, region_name, rule):
    """Create basic eventbridge rule information dictionary"""
    return {
        'ruleName': rule_name,
        'ruleArn': rule_arn,
        'region': region_name,
        'state': rule.get('State', 'UNKNOWN'),
        'description': rule.get('Description', ''),
        'eventPattern': ERROR_UNABLE_TO_RETRIEVE,
        'scheduleExpression': '',
        'targetCount': 0,
        'targets': []
    }


def check_eventbridge_backup_rules(session, region_name):
    """Check for EventBridge rules related to backup failures"""
    try:
        events_client = session.client('events', region_name=region_name)
        
        backup_rules = []
        
        # List all EventBridge rules
        paginator = events_client.get_paginator('list_rules')
        for page in paginator.paginate():
            for rule in page.get('Rules', []):
                rule_name = rule['Name']
                rule_arn = rule['Arn']
                
                # Check if rule name contains backup-failed pattern
                if BACKUP_FAILED_RULE_PATTERN.lower() in rule_name.lower():
                    try:
                        # Get rule details including event pattern
                        rule_details = events_client.describe_rule(Name=rule_name)
                        
                        # Get targets for this rule
                        targets_response = events_client.list_targets_by_rule(Rule=rule_name)
                        targets = targets_response.get('Targets', [])
                        
                        backup_rules.append(create_eventbridge_rule_info(
                            rule_name, rule_arn, region_name, rule, rule_details, targets
                        ))
                    except ClientError:
                        # If we can't get rule details, add basic info
                        backup_rules.append(create_basic_eventbridge_rule_info(
                            rule_name, rule_arn, region_name, rule
                        ))
                        
        return backup_rules
        
    except ClientError as e:
        return {'error': f'EventBridge error: {e.response["Error"]["Code"]}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


def create_sns_topic_info(topic_name, topic_arn, region_name, topic_attrs, subscriptions, display_name, tags):
    """Create SNS topic information dictionary"""
    return {
        'topicName': topic_name,
        'displayName': display_name,
        'topicArn': topic_arn,
        'region': region_name,
        'subscriptionCount': len(subscriptions),
        'subscriptions': [
            {
                'protocol': sub.get('Protocol', ''),
                'endpoint': sub.get('Endpoint', ''),
                'confirmationWasAuthenticated': sub.get('ConfirmationWasAuthenticated', False)
            }
            for sub in subscriptions
        ],
        'policy': topic_attrs.get('Policy', ''),
        'deliveryPolicy': topic_attrs.get('DeliveryPolicy', ''),
        'tags': tags
    }


def create_basic_sns_topic_info(topic_name, topic_arn, region_name):
    """Create basic SNS topic information dictionary"""
    return {
        'topicName': topic_name,
        'displayName': topic_name,
        'topicArn': topic_arn,
        'region': region_name,
        'subscriptionCount': 0,
        'subscriptions': [],
        'policy': ERROR_UNABLE_TO_RETRIEVE,
        'deliveryPolicy': '',
        'tags': []
    }


def check_sns_backup_topics(session, region_name):
    """Check for SNS topics related to backup alerts"""
    try:
        sns_client = session.client('sns', region_name=region_name)
        
        backup_topics = []
        
        # List all SNS topics
        paginator = sns_client.get_paginator('list_topics')
        for page in paginator.paginate():
            for topic in page.get('Topics', []):
                topic_arn = topic['TopicArn']
                topic_name = topic_arn.split(':')[-1]  # Extract topic name from ARN
                
                # Check if topic name contains backup alerts pattern
                if BACKUP_ALERTS_TOPIC_PATTERN.lower() in topic_name.lower():
                    try:
                        # Get topic attributes
                        attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)
                        topic_attrs = attributes.get('Attributes', {})
                        
                        # Get subscriptions for this topic
                        subscriptions_response = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
                        subscriptions = subscriptions_response.get('Subscriptions', [])
                        
                        # Get topic tags
                        try:
                            tags_response = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
                            tags = tags_response.get('Tags', [])
                            display_name = get_resource_name(tags, topic_name)
                        except Exception:
                            display_name = topic_name
                            tags = []
                        
                        backup_topics.append(create_sns_topic_info(
                            topic_name, topic_arn, region_name, topic_attrs, subscriptions, display_name, tags
                        ))
                    except ClientError:
                        # If we can't get topic details, add basic info
                        backup_topics.append(create_basic_sns_topic_info(
                            topic_name, topic_arn, region_name
                        ))
                        
        return backup_topics
        
    except ClientError as e:
        return {'error': f'SNS error: {e.response["Error"]["Code"]}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


def check_region_backup_notifications(session, region_name):
    """Check backup notification configuration in a specific region"""
    region_results = {
        'region': region_name,
        'eventbridge_rules': [],
        'sns_topics': [],
        'errors': []
    }
    
    # Check EventBridge rules
    eventbridge_result = check_eventbridge_backup_rules(session, region_name)
    if isinstance(eventbridge_result, dict) and 'error' in eventbridge_result:
        region_results['errors'].append(f"EventBridge: {eventbridge_result['error']}")
    else:
        region_results['eventbridge_rules'] = eventbridge_result
    
    # Check SNS topics
    sns_result = check_sns_backup_topics(session, region_name)
    if isinstance(sns_result, dict) and 'error' in sns_result:
        region_results['errors'].append(f"SNS: {sns_result['error']}")
    else:
        region_results['sns_topics'] = sns_result
    
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


def analyze_backup_notification_setup(all_region_results):
    """Analyze the backup notification setup across all regions"""
    total_eventbridge_rules = 0
    total_sns_topics = 0
    total_active_rules = 0
    total_subscribed_topics = 0
    regions_with_rules = 0
    regions_with_topics = 0
    
    for region_result in all_region_results:
        rules = region_result.get('eventbridge_rules', [])
        topics = region_result.get('sns_topics', [])
        
        if rules:
            regions_with_rules += 1
            total_eventbridge_rules += len(rules)
            total_active_rules += len([r for r in rules if r.get('state') == 'ENABLED'])
        
        if topics:
            regions_with_topics += 1
            total_sns_topics += len(topics)
            total_subscribed_topics += len([t for t in topics if t.get('subscriptionCount', 0) > 0])
    
    # Determine overall status
    has_backup_notifications = total_eventbridge_rules > 0 and total_sns_topics > 0
    has_active_setup = total_active_rules > 0 and total_subscribed_topics > 0
    
    if has_active_setup:
        status = 'Success'
        message = f"Backup notifications are properly configured with {total_active_rules} active EventBridge rules and {total_subscribed_topics} subscribed SNS topics across {regions_with_rules} regions."
    elif has_backup_notifications:
        status = 'Warning'
        message = f"Backup notification components found but may not be fully configured: {total_eventbridge_rules} EventBridge rules ({total_active_rules} active) and {total_sns_topics} SNS topics ({total_subscribed_topics} with subscriptions)."
    else:
        status = 'Warning'
        message = "No backup notification setup detected. Consider configuring EventBridge rules and SNS topics for backup failure alerts."
    
    return {
        'status': status,
        'message': message,
        'analysis': {
            'total_eventbridge_rules': total_eventbridge_rules,
            'total_active_rules': total_active_rules,
            'total_sns_topics': total_sns_topics,
            'total_subscribed_topics': total_subscribed_topics,
            'regions_with_rules': regions_with_rules,
            'regions_with_topics': regions_with_topics,
            'has_backup_notifications': has_backup_notifications,
            'has_active_setup': has_active_setup
        }
    }


def create_error_result(status, message, error_type, error_message):
    """Create error result dictionary"""
    return {
        'status': status,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'regions_checked': '0',
        'total_eventbridge_rules': '0',
        'total_sns_topics': '0',
        'backup_notifications_configured': False,
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
            region_result = check_region_backup_notifications(session, region)
            all_region_results.append(region_result)
        except Exception as e:
            # Add error info for this region
            all_region_results.append({
                'region': region,
                'eventbridge_rules': [],
                'sns_topics': [],
                'errors': [f'Region check failed: {str(e)}']
            })
    
    return all_region_results


def check_backup_notifications(profile_name=None, region_name=None):
    """
    Check AWS backup notification configuration across all regions or specific region
    
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
        analysis = analyze_backup_notification_setup(all_region_results)
        
        # Generate recommendations
        recommendations = []
        if analysis['analysis']['total_eventbridge_rules'] == 0:
            recommendations.append("Create EventBridge rules to monitor backup failure events")
        if analysis['analysis']['total_sns_topics'] == 0:
            recommendations.append("Create SNS topics for backup alert notifications")
        if analysis['analysis']['total_active_rules'] == 0 and analysis['analysis']['total_eventbridge_rules'] > 0:
            recommendations.append("Enable EventBridge rules for backup monitoring")
        if analysis['analysis']['total_subscribed_topics'] == 0 and analysis['analysis']['total_sns_topics'] > 0:
            recommendations.append("Add subscriptions to SNS topics for alert delivery")
        if analysis['analysis']['has_backup_notifications']:
            recommendations.append("Test backup notification system to ensure alerts are working properly")
        
        return {
            'status': analysis['status'],
            'message': analysis['message'],
            'timestamp': datetime.now().isoformat(),
            'regions_checked': str(regions_checked),
            'total_eventbridge_rules': str(analysis['analysis']['total_eventbridge_rules']),
            'total_sns_topics': str(analysis['analysis']['total_sns_topics']),
            'backup_notifications_configured': analysis['analysis']['has_active_setup'],
            'details': {
                'region_results': all_region_results,
                'analysis': analysis['analysis'],
                'search_patterns': {
                    'eventbridge_rule_pattern': BACKUP_FAILED_RULE_PATTERN,
                    'sns_topic_pattern': BACKUP_ALERTS_TOPIC_PATTERN
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


def print_eventbridge_rule_details(rule, index):
    """Print detailed information for an EventBridge rule"""
    print(f"  {index}. {rule['ruleName']}")
    print(f"     State: {rule['state']}")
    print(f"     Region: {rule['region']}")
    print(f"     Description: {rule['description'] if rule['description'] else 'No description'}")
    print(f"     Target Count: {rule['targetCount']}")
    
    if rule['targets']:
        print("     Targets:")
        for target in rule['targets']:
            print(f"       - {target['type']}: {target['arn']}")
    
    if rule['eventPattern'] and rule['eventPattern'] != ERROR_UNABLE_TO_RETRIEVE:
        print(f"     Event Pattern: {rule['eventPattern'][:100]}{'...' if len(rule['eventPattern']) > 100 else ''}")
    
    print()


def print_sns_topic_details(topic, index):
    """Print detailed information for an SNS topic"""
    print(f"  {index}. {topic['displayName']} ({topic['topicName']})")
    print(f"     Region: {topic['region']}")
    print(f"     Subscription Count: {topic['subscriptionCount']}")
    
    if topic['subscriptions']:
        print("     Subscriptions:")
        for sub in topic['subscriptions']:
            authenticated = "✓" if sub['confirmationWasAuthenticated'] else "✗"
            print(f"       - {sub['protocol'].upper()}: {sub['endpoint']} [{authenticated}]")
    
    print()


def print_region_details(region_result):
    """Print details for a specific region"""
    region = region_result['region']
    rules = region_result.get('eventbridge_rules', [])
    topics = region_result.get('sns_topics', [])
    errors = region_result.get('errors', [])
    
    print(f"\n  Region: {region}")
    print(f"    EventBridge Rules: {len(rules)}")
    print(f"    SNS Topics: {len(topics)}")
    
    if errors:
        print(f"    Errors: {', '.join(errors)}")
    
    if rules:
        print("\n    EventBridge Rules Details:")
        for i, rule in enumerate(rules, 1):
            print_eventbridge_rule_details(rule, i)
    
    if topics:
        print("\n    SNS Topics Details:")
        for i, topic in enumerate(topics, 1):
            print_sns_topic_details(topic, i)


def print_summary_output(result):
    """Print summary output for backup notifications check"""
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Regions Checked: {result['regions_checked']}")
    print(f"Total EventBridge Rules: {result['total_eventbridge_rules']}")
    print(f"Total SNS Topics: {result['total_sns_topics']}")
    print(f"Backup Notifications Configured: {result['backup_notifications_configured']}")
    
    if result['details']['region_results']:
        print("\nSearch Patterns:")
        patterns = result['details']['search_patterns']
        print(f"  - EventBridge Rule Pattern: '{patterns['eventbridge_rule_pattern']}'")
        print(f"  - SNS Topic Pattern: '{patterns['sns_topic_pattern']}'")
        
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
    
    parser = argparse.ArgumentParser(description='Check AWS backup notification configuration')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--region', help='AWS region name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_backup_notifications(
        profile_name=args.profile,
        region_name=args.region
    )
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        print_summary_output(result)


if __name__ == "__main__":
    main()
