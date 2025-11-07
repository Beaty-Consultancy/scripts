#!/usr/bin/env python3
"""
AWS Reserved Instance Utilization Check Script

This script fetches AWS Reserved Instance utilization data using the boto3 Cost Explorer client.
It identifies underutilized reservations to help optimize costs.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timedelta


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
        
        # Generate result
        total_reservations = len(reservations)
        
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
                    'warnings': warnings
                }
            }
        
        return {
            'status': 'Success',
            'message': f'{total_reservations} reservation{"s" if total_reservations != 1 else ""} found.',
            'timestamp': datetime.now().isoformat(),
            'total_reservations': str(total_reservations),
            'details': {
                'reservations': reservations,
                'warnings': warnings
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
                'warnings': []
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
                'warnings': []
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
                'warnings': []
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
        
        if result['details']['warnings']:
            print("Warnings:")
            for warning in result['details']['warnings']:
                print(f"  - {warning}")


if __name__ == "__main__":
    main()
