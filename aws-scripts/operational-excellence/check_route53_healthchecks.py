#!/usr/bin/env python3
"""
Route 53 HealthChecks Checker

Script to check Route 53 health checks in an AWS account.
"""

import boto3
import json
import sys
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from botocore.exceptions import ClientError, NoCredentialsError


def check_route53_healthchecks_status() -> List[Dict[str, Any]]:
    """
    Check Route 53 health checks status.
    
    Returns:
        List of health checks with their details
    """
    health_check_items = []
    
    try:
        route53_client = boto3.client('route53')
        
        # Get all health checks
        response = route53_client.list_health_checks()
        health_checks = response.get('HealthChecks', [])
        
        for hc in health_checks:
            config = hc.get('HealthCheckConfig', {})
            health_check_items.append({
                'health_check_id': hc.get('Id', 'Unknown'),
                'type': config.get('Type', 'Unknown'),
                'fqdn': config.get('FullyQualifiedDomainName', 'N/A'),
                'port': config.get('Port', 'N/A'),
                'path': config.get('ResourcePath', 'N/A'),
                'disabled': config.get('Disabled', False),
                'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
            })
    
    except ClientError as e:
        error_code = e.response['Error']['Code']
        health_check_items.append({
            'error': f'Failed to retrieve Route 53 health checks: {error_code}',
            'last_checked': datetime.now(timezone.utc).isoformat() + 'Z'
        })
    
    return health_check_items


def determine_route53_healthchecks_status(health_check_count: int, error_count: int) -> Tuple[str, str]:
    """
    Determine the overall status based on Route 53 health checks.
    
    Args:
        health_check_count: Number of health checks found
        error_count: Number of errors encountered
        
    Returns:
        Tuple of (status, message)
    """
    if error_count > 0:
        return 'Error', 'Failed to retrieve Route 53 health checks'
    
    if health_check_count == 0:
        return 'Warning', 'No Route 53 health checks found'
    else:
        return 'Pass', f'Found {health_check_count} Route 53 health checks'


def check_route53_health_checks(profile_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Main function to check Route 53 health checks
    
    Args:
        profile_name: AWS profile name (optional)
        
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
            # Perform the Route 53 health checks check
            health_check_results = check_route53_healthchecks_status()
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Filter out error entries for statistics
        valid_results = [item for item in health_check_results if 'error' not in item]
        error_results = [item for item in health_check_results if 'error' in item]
        
        # Calculate statistics
        total_health_checks = len(valid_results)
        error_count = len(error_results)
        
        # Determine overall status
        status, message = determine_route53_healthchecks_status(total_health_checks, error_count)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'route53_healthchecks',
            'total_health_checks_found': total_health_checks,
            'error_count': error_count,
            'non_compliant_items': health_check_results
        }
        
        return final_result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found or invalid',
            'check_type': 'route53_healthchecks',
            'non_compliant_items': []
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': 'Insufficient permissions to check Route 53 health checks',
                'check_type': 'route53_healthchecks',
                'non_compliant_items': []
            }
        else:
            return {
                'timestamp': timestamp,
                'status': 'Error',
                'message': f'AWS API error: {error_code}',
                'check_type': 'route53_healthchecks',
                'non_compliant_items': []
            }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error during Route 53 health checks check: {str(e)}',
            'check_type': 'route53_healthchecks',
            'non_compliant_items': []
        }


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check Route 53 health checks")
    parser.add_argument('--profile', help='AWS profile name to use')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_route53_health_checks(profile_name=args.profile)
    
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