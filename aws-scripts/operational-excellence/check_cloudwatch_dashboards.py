#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Operational Excellence Pillar
CloudWatch Dashboards Check

This script checks the presence and configuration of CloudWatch dashboards.
"""

import boto3
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError
import sys

# Constants
CLOUDWATCH_DASHBOARD = 'CloudWatch Dashboard'

def get_account_id() -> str:
    """Get the current AWS account ID"""
    try:
        sts = boto3.client('sts')
        return sts.get_caller_identity()['Account']
    except Exception:
        return 'unknown'


def check_cloudwatch_dashboards_single_region(region_name: str = 'eu-west-2') -> List[Dict[str, Any]]:
    """
    Check CloudWatch dashboards in a single region (dashboards are global)
    
    Args:
        region_name: AWS region name to use for the API call
        
    Returns:
        list: List of dashboard information
    """
    dashboard_info = []
    
    try:
        cloudwatch_client = boto3.client('cloudwatch', region_name=region_name)
        
        # Get all dashboards
        all_dashboards = []
        next_token = None
        
        while True:
            if next_token:
                response = cloudwatch_client.list_dashboards(NextToken=next_token)
            else:
                response = cloudwatch_client.list_dashboards()
            
            dashboards = response.get('DashboardEntries', [])
            all_dashboards.extend(dashboards)
            
            next_token = response.get('NextToken')
            if not next_token:
                break
        
        # Process each dashboard
        for dashboard in all_dashboards:
            try:
                dashboard_response = cloudwatch_client.get_dashboard(
                    DashboardName=dashboard['DashboardName']
                )
                
                dashboard_body = json.loads(dashboard_response['DashboardBody'])
                widget_count = len(dashboard_body.get('widgets', []))
                
                dashboard_info.append({
                    'resource_type': CLOUDWATCH_DASHBOARD,
                    'resource_id': dashboard['DashboardName'],
                    'resource_name': dashboard['DashboardName'],
                    'region': region_name,
                    'size': dashboard.get('Size', 0),
                    'widget_count': widget_count,
                    'last_modified': dashboard['LastModified'].isoformat() if dashboard.get('LastModified') else 'Unknown',
                    'dashboard_arn': f"arn:aws:cloudwatch:{region_name}:{get_account_id()}:dashboard/{dashboard['DashboardName']}",
                    'status': 'Active'
                })
                
            except Exception as e:
                dashboard_info.append({
                    'resource_type': CLOUDWATCH_DASHBOARD,
                    'resource_id': dashboard['DashboardName'],
                    'resource_name': dashboard['DashboardName'],
                    'region': region_name,
                    'size': dashboard.get('Size', 0),
                    'widget_count': 'Unknown',
                    'last_modified': dashboard['LastModified'].isoformat() if dashboard.get('LastModified') else 'Unknown',
                    'dashboard_arn': f"arn:aws:cloudwatch:{region_name}:{get_account_id()}:dashboard/{dashboard['DashboardName']}",
                    'status': 'Error',
                    'error': str(e),
                    'reason': 'Failed to get dashboard details'
                })
    
    except Exception as e:
        # Return error info
        dashboard_info.append({
            'resource_type': CLOUDWATCH_DASHBOARD,
            'resource_id': 'unknown',
            'resource_name': 'unknown',
            'region': region_name,
            'error': str(e),
            'reason': 'Failed to check dashboards'
        })
    
    return dashboard_info


def determine_cloudwatch_dashboards_status(dashboard_count: int, error_count: int) -> tuple:
    """
    Determine overall status based on CloudWatch dashboards analysis statistics
    
    Args:
        dashboard_count: Number of dashboards found
        error_count: Number of errors encountered
        
    Returns:
        tuple: (status, message)
    """
    if error_count > 0 and dashboard_count == 0:
        return ('Error', f'Failed to check CloudWatch dashboards: {error_count} errors encountered')
    elif dashboard_count == 0:
        return ('Fail', 'No CloudWatch dashboards found')
    else:
        return ('Pass', f'Found {dashboard_count} CloudWatch dashboards')


def check_cloudwatch_dashboards(profile_name: Optional[str] = None, region: str = 'eu-west-2') -> Dict[str, Any]:
    """
    Main function to check CloudWatch dashboards
    
    Args:
        profile_name: AWS profile name (optional)
        region: AWS region to use for API calls (default: eu-west-2)
        
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
            # Perform the CloudWatch dashboards check
            dashboard_results = check_cloudwatch_dashboards_single_region(region)
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Filter out error entries for statistics
        valid_results = [item for item in dashboard_results if 'error' not in item]
        error_results = [item for item in dashboard_results if 'error' in item]
        
        # Calculate statistics
        total_dashboards = len(valid_results)
        active_dashboards = len([item for item in valid_results if item.get('status') == 'Active'])
        error_dashboards = len([item for item in valid_results if item.get('status') == 'Error'])
        error_count = len(error_results)
        
        # Determine overall status
        status, message = determine_cloudwatch_dashboards_status(total_dashboards, error_count)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'cloudwatch_dashboards',
            'region_checked': region,
            'total_dashboards_found': total_dashboards,
            'active_dashboards': active_dashboards,
            'error_dashboards': error_dashboards,
            'error_count': error_count,
        }
        
        # Add appropriate data field based on status
        if status == 'Pass':
            # For successful checks, put dashboards in 'dashboards' field
            final_result['dashboards'] = valid_results
            final_result['non_compliant_items'] = []  # No issues found
        else:
            # For failed checks, put issues in 'non_compliant_items' field
            final_result['non_compliant_items'] = valid_results + error_results
            final_result['dashboards'] = []
        
        return final_result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found or invalid',
            'check_type': 'cloudwatch_dashboards',
            'non_compliant_items': []
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': 'Insufficient permissions to check CloudWatch dashboards',
                'check_type': 'cloudwatch_dashboards',
                'non_compliant_items': []
            }
        else:
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': f'AWS API error: {error_code}',
                'check_type': 'cloudwatch_dashboards',
                'non_compliant_items': []
            }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error during CloudWatch dashboards check: {str(e)}',
            'check_type': 'cloudwatch_dashboards',
            'non_compliant_items': []
        }

def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check CloudWatch dashboards")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--region', help='AWS region (default: eu-west-2)', default='eu-west-2')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_cloudwatch_dashboards(
        profile_name=args.profile,
        region=args.region
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
