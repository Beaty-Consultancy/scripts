#!/usr/bin/env python3
"""
AWS Reserved Instance Utilization Check Script

This script fetches AWS Reserved Instance utilization data using the boto3 Cost Explorer client.
It identifies underutilized reservations to help optimize costs.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError, OperationNotPageableError
from datetime import datetime, timedelta, timezone


def format_time_remaining(delta):
    """Return a short human string for the remaining timedelta."""
    if delta.total_seconds() <= 0:
        return 'Expired'
    days = delta.days
    hours, remainder = divmod(delta.seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def iterate_items(client, operation_name, result_key, **kwargs):
    """
    Yield items for an operation, gracefully falling back if pagination is unsupported.
    """
    try:
        paginator = client.get_paginator(operation_name)
        for page in paginator.paginate(**kwargs):
            for item in page.get(result_key, []):
                yield item
        return
    except (OperationNotPageableError, AttributeError):
        pass
    
    response = getattr(client, operation_name)(**kwargs)
    for item in response.get(result_key, []):
        yield item


def get_reservation_expirations(session, service_filter=None):
    """
    Collect active reservation expirations for EC2 and/or RDS.
    
    Returns:
        list[dict]: Reservation expiration details
    """
    now = datetime.now(timezone.utc)
    expirations = []
    
    # Determine which services to check
    services = [service_filter.lower()] if service_filter else ['ec2', 'rds']
    
    # Fetch regions once; fall back to us-east-1 if the call fails
    try:
        ec2_client = session.client('ec2', region_name='us-east-1')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    except ClientError:
        regions = ['us-east-1']
    
    for region in regions:
        if 'ec2' in services:
            try:
                ec2 = session.client('ec2', region_name=region)
                for ri in iterate_items(ec2, 'describe_reserved_instances', 'ReservedInstances'):
                    if ri.get('State') != 'active':
                        continue
                    
                    end_time = ri.get('End')
                    if not end_time and ri.get('Start') and ri.get('Duration'):
                        end_time = ri['Start'] + timedelta(seconds=ri['Duration'])
                    
                    time_remaining = end_time - now if end_time else None
                    seconds_remaining = max(time_remaining.total_seconds(), 0) if time_remaining else None
                    
                    expirations.append({
                        'service': 'EC2',
                        'id': ri.get('ReservedInstancesId', 'unknown'),
                        'region': region,
                        'instanceType': ri.get('InstanceType', 'unknown'),
                        'instanceCount': ri.get('InstanceCount', 0),
                        'scope': ri.get('Scope', 'Availability Zone'),
                        'expiresOn': end_time.isoformat() if end_time else 'Unknown',
                        'daysRemaining': round(seconds_remaining / 86400, 2) if seconds_remaining is not None else None,
                        'timeRemaining': format_time_remaining(timedelta(seconds=seconds_remaining)) if seconds_remaining is not None else 'Unknown'
                    })
            except ClientError:
                # Skip regions we cannot query
                pass
        
        if 'rds' in services:
            try:
                rds = session.client('rds', region_name=region)
                for ri in iterate_items(rds, 'describe_reserved_db_instances', 'ReservedDBInstances'):
                    if ri.get('State') != 'active':
                        continue
                    
                    start_time = ri.get('StartTime')
                    duration = ri.get('Duration', 0)
                    end_time = start_time + timedelta(seconds=duration) if start_time else None
                    time_remaining = end_time - now if end_time else None
                    seconds_remaining = max(time_remaining.total_seconds(), 0) if time_remaining else None
                    
                    expirations.append({
                        'service': 'RDS',
                        'id': ri.get('ReservedDBInstanceId', 'unknown'),
                        'region': region,
                        'instanceType': ri.get('DBInstanceClass', 'unknown'),
                        'instanceCount': ri.get('DBInstanceCount', 0),
                        'productDescription': ri.get('ProductDescription', 'unknown'),
                        'expiresOn': end_time.isoformat() if end_time else 'Unknown',
                        'daysRemaining': round(seconds_remaining / 86400, 2) if seconds_remaining is not None else None,
                        'timeRemaining': format_time_remaining(timedelta(seconds=seconds_remaining)) if seconds_remaining is not None else 'Unknown'
                    })
            except ClientError:
                # Skip regions we cannot query
                pass
    
    return expirations


def check_reservations_utilization(profile_name=None, time_period_months=1, service_filter=None, region_filter=None):
    """
    Check Reserved Instance utilization across AWS services
    
    Args:
        profile_name (str): AWS profile name (optional)
        time_period_months (int): Number of months to analyze (default: 1)
        service_filter (str): Filter by service ('ec2' or 'rds')
        region_filter (str): Filter by region (not used in this simple version)
        
    Returns:
        dict: Structured result for dashboard compatibility
    """
    
    try:
        # Initialize session with profile
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
        else:
            session = boto3.Session()
        
        # Initialize Cost Explorer client
        ce_client = session.client('ce', region_name='us-east-1')  # CE is only available in us-east-1
        
        # Collect reservation expiry information alongside utilization
        expiration_details = get_reservation_expirations(session, service_filter=service_filter)
        
        # Calculate time period (default: last month)
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=30 * time_period_months)
        
        # Build request parameters - same as AWS CLI command
        request_params = {
            'TimePeriod': {
                'Start': start_date.strftime('%Y-%m-%d'),
                'End': end_date.strftime('%Y-%m-%d')
            },
            'Granularity': 'MONTHLY'
        }
        
        # Add service filter if specified
        if service_filter:
            service_map = {
                'ec2': 'Amazon Elastic Compute Cloud - Compute',
                'rds': 'Amazon Relational Database Service'
            }
            if service_filter.lower() in service_map:
                request_params['Filter'] = {
                    'Dimensions': {
                        'Key': 'SERVICE',
                        'Values': [service_map[service_filter.lower()]]
                    }
                }
        
        # For RDS, also try without the filter to see if we get any data
        if service_filter and service_filter.lower() == 'rds':
            # First try with the filter
            try:
                response = ce_client.get_reservation_utilization(**request_params)
                # If no data, try without filter to see if RDS reservations exist under different name
                if not response.get('UtilizationsByTime') and all(
                    float(v) == 0 for v in response.get('Total', {}).values() if isinstance(v, str) and v.replace('.', '').isdigit()
                ):
                    # Try without filter
                    request_params_no_filter = {
                        'TimePeriod': request_params['TimePeriod'],
                        'Granularity': request_params['Granularity'],
                        'GroupBy': [{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
                    }
                    response = ce_client.get_reservation_utilization(**request_params_no_filter)
            except Exception:
                # If anything fails, continue with the original request
                pass
        
        # Call Cost Explorer API
        response = ce_client.get_reservation_utilization(**request_params)
        
        reservations = []
        warnings = []
        
        # Add warnings for soon-to-expire reservations
        for expiration in expiration_details:
            days_remaining = expiration.get('daysRemaining')
            if days_remaining is not None and days_remaining <= 30:
                warnings.append(
                    f"{expiration.get('service')} reservation {expiration.get('id')} in "
                    f"{expiration.get('region')} expires in {expiration.get('timeRemaining')}"
                )
        
        # Check if we have any actual reservation data
        has_reservation_data = False
        total_data = response.get('Total', {})
        
        # Check if there's any meaningful data in the Total section
        if total_data and (
            float(total_data.get('PurchasedHours', '0')) > 0 or
            float(total_data.get('TotalActualHours', '0')) > 0 or
            float(total_data.get('AmortizedUpfrontFee', '0')) > 0 or
            float(total_data.get('AmortizedRecurringFee', '0')) > 0
        ):
            has_reservation_data = True
        
        # Process utilization data from UtilizationsByTime (time periods)
        for time_period in response.get('UtilizationsByTime', []):
            total_utilization = time_period.get('Total', {})
            if total_utilization:
                utilization_percentage = total_utilization.get('UtilizationPercentage', '0')
                purchased_hours = total_utilization.get('PurchasedHours', '0')
                total_actual_hours = total_utilization.get('TotalActualHours', '0')
                unused_hours = total_utilization.get('UnusedHours', '0')
                net_ri_savings = total_utilization.get('NetRISavings', '0')
                amortized_upfront_fee = total_utilization.get('AmortizedUpfrontFee', '0')
                
                # Create reservation entry matching your requested format
                service_name = 'RDS' if service_filter and service_filter.lower() == 'rds' else 'EC2'
                reservation = {
                    'resource': service_name,
                    'utilizationPercentage': utilization_percentage,
                    'purchasedHours': purchased_hours,
                    'actualHours': total_actual_hours,
                    'unusedHours': unused_hours,
                    'netRiSavings': f"${float(net_ri_savings):.2f}",
                    'amortizedUpfrontFee': f"${float(amortized_upfront_fee):.2f}"
                }
                
                reservations.append(reservation)
                
                # Add warning for low utilization
                if float(utilization_percentage) < 80:
                    warnings.append(f"Low utilization ({utilization_percentage}%) detected")
        
        # If no time period data, check the overall Total
        if not reservations:
            total_data = response.get('Total', {})
            if total_data:
                utilization_percentage = total_data.get('UtilizationPercentage', '0')
                purchased_hours = total_data.get('PurchasedHours', '0')
                total_actual_hours = total_data.get('TotalActualHours', '0')
                unused_hours = total_data.get('UnusedHours', '0')
                net_ri_savings = total_data.get('NetRISavings', '0')
                amortized_upfront_fee = total_data.get('AmortizedUpfrontFee', '0')
                
                service_name = 'RDS' if service_filter and service_filter.lower() == 'rds' else 'EC2'
                reservation = {
                    'resource': service_name,
                    'utilizationPercentage': utilization_percentage,
                    'purchasedHours': purchased_hours,
                    'actualHours': total_actual_hours,
                    'unusedHours': unused_hours,
                    'netRiSavings': f"${float(net_ri_savings):.2f}",
                    'amortizedUpfrontFee': f"${float(amortized_upfront_fee):.2f}"
                }
                
                reservations.append(reservation)
                
                if float(utilization_percentage) < 80:
                    warnings.append(f"Low utilization ({utilization_percentage}%) detected")
        
        # Generate result counts
        active_reservation_count = len(expiration_details)
        utilization_entries = len(reservations)
        total_reservations = active_reservation_count or utilization_entries
        
        if total_reservations == 0:
            # Check if this is due to no reservations existing vs. no data in time period
            service_name = service_filter.upper() if service_filter else 'EC2/RDS'
            if not has_reservation_data:
                message = f'No {service_name} reservations found in your account for the specified time period.'
            else:
                message = f'No {service_name} reservations found for the specified criteria.'
            
            return {
                'status': 'Success',
                'message': message,
                'timestamp': datetime.now().isoformat(),
                'total_reservations': '0',
                'details': {
                    'reservations': [],
                    'warnings': warnings,
                    'reservationExpirations': [],
                    'activeReservationCount': 0,
                    'utilizationEntryCount': 0
                }
            }
        
        return {
            'status': 'Success',
            'message': f'{total_reservations} reservation{"s" if total_reservations != 1 else ""} found.',
            'timestamp': datetime.now().isoformat(),
            'total_reservations': str(total_reservations),
            'details': {
                'reservations': reservations,
                'warnings': warnings,
                'reservationExpirations': expiration_details,
                'activeReservationCount': active_reservation_count,
                'utilizationEntryCount': utilization_entries
            }
        }
        
    except NoCredentialsError:
        return {
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'timestamp': datetime.now().isoformat(),
            'total_reservations': '0',
            'details': {
                'error_type': 'NoCredentialsError',
                'error_message': 'AWS credentials not found',
                'reservations': [],
                'warnings': [],
                'reservationExpirations': []
            }
        }
    
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        return {
            'status': 'Error',
            'message': f'AWS API error: {error_message}',
            'timestamp': datetime.now().isoformat(),
            'total_reservations': '0',
            'details': {
                'error_type': error_code,
                'error_message': error_message,
                'reservations': [],
                'warnings': [],
                'reservationExpirations': []
            }
        }
    
    except Exception as e:
        return {
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'total_reservations': '0',
            'details': {
                'error_type': 'UnexpectedError',
                'error_message': str(e),
                'reservations': [],
                'warnings': [],
                'reservationExpirations': []
            }
        }


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check AWS Reserved Instance utilization')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--months', type=int, default=1, 
                       help='Number of months to analyze (default: 1)')
    parser.add_argument('--service', choices=['ec2', 'rds'], default=None,
                       help='Filter by service (ec2 or rds)')
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_reservations_utilization(
        profile_name=args.profile,
        time_period_months=args.months,
        service_filter=args.service
    )
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        # Summary output
        print(f"Status: {result['status']}")
        print(f"Message: {result['message']}")
        print(f"Total Reservations: {result['total_reservations']}")
        print(f"Utilization Periods Returned: {len(result['details'].get('reservations', []))}")
        
        if result['details']['reservations']:
            print("\nReservation Utilization:")
            for i, reservation in enumerate(result['details']['reservations'], 1):
                print(f"  {i}. {reservation['resource']} - {reservation['utilizationPercentage']}% utilization")
                print(f"     Purchased: {reservation['purchasedHours']} hours")
                print(f"     Used: {reservation['actualHours']} hours")
                print(f"     Unused: {reservation['unusedHours']} hours")
                print(f"     Savings: {reservation['netRiSavings']}")
                print(f"     Upfront Fee: {reservation['amortizedUpfrontFee']}")
                print()
        
        expirations = result['details'].get('reservationExpirations', [])
        if expirations:
            print("\nActive Reservation Expirations:")
            for i, expiration in enumerate(expirations, 1):
                print(
                    f"  {i}. {expiration.get('service')} {expiration.get('id')} "
                    f"({expiration.get('instanceType')}) in {expiration.get('region')} "
                    f"expires on {expiration.get('expiresOn')} "
                    f"({expiration.get('timeRemaining')})"
                )
        
        if result['details']['warnings']:
            print("Warnings:")
            for warning in result['details']['warnings']:
                print(f"  - {warning}")


if __name__ == "__main__":
    main()
