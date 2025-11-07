#!/usr/bin/env python3
"""
Cost Anomaly Detection Check Script

This script checks if AWS Cost Anomaly Detection monitors are configured
and provides details about their status and configuration.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime


def check_cost_anomaly_enabled(profile_name=None):
    """
    Check if Cost Anomaly Detection monitors are configured
    
    Args:
        profile_name (str): AWS profile name (optional)
        
    Returns:
        dict: Structured result for dashboard compatibility
    """
    
    try:
        # Initialize session with profile
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
        else:
            session = boto3.Session()
        
        # Cost Explorer client (Cost Anomaly Detection is part of Cost Explorer)
        ce_client = session.client('ce')
        
        # Get cost anomaly detectors (monitors)
        response = ce_client.get_anomaly_monitors()
        
        detectors = response.get('AnomalyMonitors', [])
        
        # Process the detectors
        monitor_details = []
        active_monitors = 0
        total_monitors = len(detectors)
        
        for detector in detectors:
            # Handle date formatting - check if it's a datetime object or string
            creation_date = detector.get('CreationDate', '')
            if hasattr(creation_date, 'strftime'):
                creation_date = creation_date.strftime('%Y-%m-%d')
            elif creation_date:
                creation_date = str(creation_date)[:10]  # Take first 10 chars if it's a string
            else:
                creation_date = 'Unknown'
            
            last_updated = detector.get('LastUpdatedDate', '')
            if hasattr(last_updated, 'strftime'):
                last_updated = last_updated.strftime('%Y-%m-%d')
            elif last_updated:
                last_updated = str(last_updated)[:10]  # Take first 10 chars if it's a string
            else:
                last_updated = 'Unknown'
            
            detector_info = {
                'name': detector.get('MonitorName', 'Unknown'),
                'arn': detector.get('MonitorArn', ''),
                'monitor_type': detector.get('MonitorType', 'Unknown'),
                'dimension_key': detector.get('DimensionKey', 'N/A'),
                'creation_date': creation_date,
                'last_updated': last_updated,
                'monitor_specification': detector.get('MonitorSpecification', {}),
                'status': 'Active'  # AWS API doesn't provide explicit status, assume active if returned
            }
            
            monitor_details.append(detector_info)
            active_monitors += 1
        
        # Get anomaly subscriptions for notifications
        subscriptions_response = ce_client.get_anomaly_subscriptions()
        subscriptions = subscriptions_response.get('AnomalySubscriptions', [])
        
        subscription_details = []
        for subscription in subscriptions:
            sub_info = {
                'name': subscription.get('SubscriptionName', 'Unknown'),
                'arn': subscription.get('SubscriptionArn', ''),
                'frequency': subscription.get('Frequency', 'Unknown'),
                'threshold': subscription.get('ThresholdExpression', {}),
                'subscribers': subscription.get('Subscribers', [])
            }
            subscription_details.append(sub_info)
        
        # Determine overall status
        if total_monitors == 0:
            status = 'Not Configured'
            message = 'No Cost Anomaly Detection monitors found. Cost anomaly detection is not enabled.'
        elif active_monitors == 0:
            status = 'Inactive'
            message = 'Cost Anomaly Detection monitors exist but none are active.'
        else:
            status = 'Active'
            message = f'{active_monitors} Cost Anomaly Detection monitor(s) are active and monitoring your costs.'
        
        # Create structured result
        result = {
            'status': status,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'details': {
                'total_monitors': total_monitors,
                'active_monitors': active_monitors,
                'monitors': monitor_details,
                'subscriptions': subscription_details
            }
        }
        
        return result
        
    except NoCredentialsError:
        return {
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'timestamp': datetime.now().isoformat(),
            'details': {
                'error_type': 'NoCredentialsError',
                'total_monitors': 0,
                'active_monitors': 0,
                'monitors': [],
                'subscriptions': []
            }
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        return {
            'status': 'Error',
            'message': f'AWS API Error: {error_message}',
            'timestamp': datetime.now().isoformat(),
            'details': {
                'error_type': 'ClientError',
                'error_code': error_code,
                'error_message': error_message,
                'total_monitors': 0,
                'active_monitors': 0,
                'monitors': [],
                'subscriptions': []
            }
        }
        
    except Exception as e:
        return {
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'details': {
                'error_type': 'UnexpectedError',
                'error_message': str(e),
                'total_monitors': 0,
                'active_monitors': 0,
                'monitors': [],
                'subscriptions': []
            }
        }


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check AWS Cost Anomaly Detection configuration')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_cost_anomaly_enabled(args.profile)
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        # Summary output
        print(f"Status: {result['status']}")
        print(f"Message: {result['message']}")
        print(f"Total Monitors: {result['details']['total_monitors']}")
        print(f"Active Monitors: {result['details']['active_monitors']}")
        
        if result['details']['monitors']:
            print("\nMonitors:")
            for i, monitor in enumerate(result['details']['monitors'], 1):
                print(f"  {i}. {monitor['name']} ({monitor['monitor_type']})")
        
        if result['details']['subscriptions']:
            print("\nSubscriptions:")
            for i, sub in enumerate(result['details']['subscriptions'], 1):
                print(f"  {i}. {sub['name']} ({sub['frequency']})")


if __name__ == "__main__":
    main()
