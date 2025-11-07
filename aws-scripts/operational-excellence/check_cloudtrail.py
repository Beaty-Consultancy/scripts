#!/usr/bin/env python3
"""
CloudTrail Management Events Check Script

This script checks if CloudTrail is enabled with management events by examining:
- Active CloudTrail trails in the account
- Event selectors configuration for management events
- Multi-region and global service events coverage

Returns structured data for dashboard compatibility.
"""

import boto3
import json
import sys
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime


def check_trail_selectors(cloudtrail_client, trail_arn):
    """Check event selectors for a specific trail"""
    try:
        selectors_response = cloudtrail_client.get_event_selectors(TrailName=trail_arn)
        event_selectors = selectors_response.get('EventSelectors', [])
        advanced_selectors = selectors_response.get('AdvancedEventSelectors', [])
        
        has_management_events = False
        management_selectors = []
        
        # Check traditional event selectors
        for selector in event_selectors:
            if selector.get('IncludeManagementEvents', False):
                has_management_events = True
                management_selectors.append({
                    'type': 'traditional',
                    'readWriteType': selector.get('ReadWriteType', 'All'),
                    'includeManagementEvents': True
                })
        
        # Check advanced event selectors
        for selector in advanced_selectors:
            field_selectors = selector.get('FieldSelectors', [])
            for field in field_selectors:
                if (field.get('Field') == 'eventCategory' and 
                    'Management' in field.get('Equals', [])):
                    has_management_events = True
                    management_selectors.append({
                        'type': 'advanced',
                        'name': selector.get('Name', ''),
                        'eventCategory': 'Management'
                    })
                    break
        
        return has_management_events, management_selectors
        
    except ClientError:
        return False, []


def get_trail_status(cloudtrail_client, trail_arn):
    """Get logging status for a trail"""
    try:
        status_response = cloudtrail_client.get_trail_status(Name=trail_arn)
        return status_response.get('IsLogging', False)
    except Exception:
        return False


def process_trail(cloudtrail_client, trail):
    """Process a single trail and return its details"""
    trail_name = trail.get('Name', 'Unknown')
    trail_arn = trail.get('TrailARN', '')
    
    # Get logging status
    is_logging = get_trail_status(cloudtrail_client, trail_arn)
    
    # Check management events
    has_management_events, management_selectors = check_trail_selectors(cloudtrail_client, trail_arn)
    
    return {
        'trailName': trail_name,
        'trailArn': trail_arn,
        'homeRegion': trail.get('HomeRegion', 'N/A'),
        'isMultiRegionTrail': trail.get('IsMultiRegionTrail', False),
        'includeGlobalServiceEvents': trail.get('IncludeGlobalServiceEvents', False),
        's3BucketName': trail.get('S3BucketName', 'N/A'),
        'cloudWatchLogsLogGroup': trail.get('CloudWatchLogsLogGroupArn', ''),
        'kmsKeyId': trail.get('KmsKeyId', ''),
        'logFileValidationEnabled': trail.get('LogFileValidationEnabled', False),
        'isLogging': is_logging,
        'hasManagementEvents': has_management_events,
        'managementSelectors': management_selectors
    }


def determine_status(total_trails, active_trails, management_trails, multi_region_trails, global_service_trails):
    """Determine overall CloudTrail status"""
    if management_trails == 0:
        if active_trails == 0:
            return 'Warning', f'Found {total_trails} CloudTrail trails but none are actively logging or configured for management events. Enable logging and management events.'
        else:
            return 'Warning', f'Found {total_trails} CloudTrail trails ({active_trails} active) but none are configured for management events. Enable management event logging.'
    elif management_trails > 0 and multi_region_trails > 0 and global_service_trails > 0:
        return 'Success', f'CloudTrail is properly configured with {management_trails} trails capturing management events across multiple regions and global services.'
    else:
        missing_features = []
        if multi_region_trails == 0:
            missing_features.append('multi-region coverage')
        if global_service_trails == 0:
            missing_features.append('global service events')
        
        if missing_features:
            return 'Warning', f'CloudTrail has {management_trails} trails with management events but missing: {", ".join(missing_features)}.'
        else:
            return 'Warning', f'CloudTrail configuration needs improvement. Found {total_trails} trails, {active_trails} active, {management_trails} with management events.'


def create_no_trails_result(check_region):
    """Create result when no trails are found"""
    return {
        'status': 'Warning',
        'message': 'No CloudTrail trails found. Enable CloudTrail with management events for audit logging.',
        'timestamp': datetime.now().isoformat(),
        'check_region': check_region,
        'total_trails': 0,
        'active_trails': 0,
        'trails_with_management_events': 0,
        'trails': []
    }


def create_error_result(error_type, message, check_region):
    """Create error result"""
    return {
        'status': 'Error',
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'check_region': check_region,
        'total_trails': 0,
        'active_trails': 0,
        'trails_with_management_events': 0,
        'trails': [],
        'error': error_type
    }


def check_cloudtrail_management_events(profile_name=None, region_name=None):
    """
    Check and list CloudTrail trails with management events enabled.
    
    Args:
        profile_name: AWS profile name to use (optional)
        region_name: AWS region to check from (optional, defaults to eu-west-2)
    
    Returns:
        dict: Results in JSON format for dashboard compatibility
    """
    check_region = region_name if region_name else 'eu-west-2'
    
    try:
        session = boto3.Session(profile_name=profile_name)
        cloudtrail_client = session.client('cloudtrail', region_name=check_region)
        
        # Get all trails
        response = cloudtrail_client.describe_trails()
        trails = response.get('trailList', [])
        
        if not trails:
            return create_no_trails_result(check_region)
        
        # Process all trails
        trail_results = []
        active_trails = 0
        management_trails = 0
        
        for trail in trails:
            try:
                trail_data = process_trail(cloudtrail_client, trail)
                trail_results.append(trail_data)
                
                if trail_data['isLogging']:
                    active_trails += 1
                if trail_data['hasManagementEvents']:
                    management_trails += 1
                    
            except Exception as e:
                # Add error trail data
                trail_results.append({
                    'trailName': trail.get('Name', 'Unknown'),
                    'trailArn': trail.get('TrailARN', ''),
                    'homeRegion': trail.get('HomeRegion', 'N/A'),
                    'isMultiRegionTrail': trail.get('IsMultiRegionTrail', False),
                    'includeGlobalServiceEvents': trail.get('IncludeGlobalServiceEvents', False),
                    's3BucketName': trail.get('S3BucketName', 'N/A'),
                    'isLogging': False,
                    'hasManagementEvents': False,
                    'managementSelectors': [],
                    'error': f'Failed to check trail: {str(e)}'
                })
        
        # Calculate statistics
        total_trails = len(trails)
        multi_region_trails = len([t for t in trails if t.get('IsMultiRegionTrail', False)])
        global_service_trails = len([t for t in trails if t.get('IncludeGlobalServiceEvents', False)])
        
        # Determine overall status
        status, message = determine_status(total_trails, active_trails, management_trails, 
                                         multi_region_trails, global_service_trails)
        
        return {
            'status': status,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'check_region': check_region,
            'total_trails': total_trails,
            'active_trails': active_trails,
            'trails_with_management_events': management_trails,
            'trails': trail_results
        }
        
    except NoCredentialsError:
        return create_error_result('NoCredentialsError', 
                                 'AWS credentials not found. Please configure your credentials.',
                                 check_region)
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        if error_code == 'AccessDenied':
            message = "Access denied. Please check your IAM permissions for CloudTrail."
        else:
            message = f"AWS API error: {e.response.get('Error', {}).get('Message', str(e))}"
        
        return create_error_result(error_code, message, check_region)
    except Exception as e:
        return create_error_result('UnexpectedError', f'Unexpected error: {str(e)}', check_region)


def print_trail_info(trail, index):
    """Print information for a single trail"""
    print(f"\n{index}. Trail Name: {trail['trailName']}")
    print(f"   Home Region: {trail['homeRegion']}")
    print(f"   Multi-Region: {trail['isMultiRegionTrail']}")
    print(f"   Global Services: {trail['includeGlobalServiceEvents']}")
    print(f"   Logging: {trail['isLogging']}")
    print(f"   Management Events: {trail['hasManagementEvents']}")
    print(f"   S3 Bucket: {trail['s3BucketName']}")
    
    if trail.get('cloudWatchLogsLogGroup'):
        print(f"   CloudWatch Logs: {trail['cloudWatchLogsLogGroup']}")
    if trail.get('kmsKeyId'):
        print("   KMS Encryption: ✓")
    if trail.get('error'):
        print(f"   Error: {trail['error']}")
    elif trail['managementSelectors']:
        print(f"   Management Selectors: {len(trail['managementSelectors'])}")
        for j, selector in enumerate(trail['managementSelectors'], 1):
            print(f"     {j}. Type: {selector.get('type', 'unknown')}")


def print_summary_output(result):
    """Print human-readable summary output"""
    print("\nCloudTrail Management Events Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Check Region: {result['check_region']}")
    print(f"Total Trails: {result['total_trails']}")
    print(f"Active Trails: {result['active_trails']}")
    print(f"Trails with Management Events: {result['trails_with_management_events']}")
    
    trails = result.get('trails', [])
    if trails:
        print("\nTrail Details:")
        for i, trail in enumerate(trails, 1):
            print_trail_info(trail, i)
    
    if result['trails_with_management_events'] > 0:
        management_trail_names = [t['trailName'] for t in trails if t.get('hasManagementEvents', False)]
        print("\nTrails with Management Events:")
        for trail_name in management_trail_names:
            print(f"  - {trail_name}")
    else:
        print("\nNo trails found with management events enabled.")
        print("Consider enabling management events on at least one trail for security auditing.")


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check CloudTrail management events")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--region', help='AWS region to check from (default: eu-west-2)')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_cloudtrail_management_events(
        profile_name=args.profile,
        region_name=args.region
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
