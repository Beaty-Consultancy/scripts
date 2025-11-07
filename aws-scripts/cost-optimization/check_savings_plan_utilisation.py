#!/usr/bin/env python3
"""
AWS Savings Plan Utilization Check Script

This script checks AWS Savings Plans and their utilization rates.
It identifies underutilized savings plans to help optimize costs.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timedelta

# Constants
SAVINGS_PLANS_TYPE = 'Savings Plans'
LOW_UTILIZATION_THRESHOLD = 80.0


def create_savings_plan_entry(utilization_data, period_info='Overall'):
    """Create a savings plan entry from utilization data"""
    utilization_percentage = utilization_data.get('UtilizationPercentage', '0')
    total_commitment = utilization_data.get('TotalCommitment', '0')
    used_commitment = utilization_data.get('UsedCommitment', '0')
    unused_commitment = utilization_data.get('UnusedCommitment', '0')
    utilization_percentage_in_units = utilization_data.get('UtilizationPercentageInUnits', '0')
    
    return {
        'type': SAVINGS_PLANS_TYPE,
        'utilizationPercentage': utilization_percentage,
        'utilizationPercentageInUnits': utilization_percentage_in_units,
        'totalCommitment': f"${float(total_commitment):.2f}",
        'usedCommitment': f"${float(used_commitment):.2f}",
        'unusedCommitment': f"${float(unused_commitment):.2f}",
        'period': period_info
    }


def process_time_period_data(time_periods):
    """Process savings plan data from time periods"""
    savings_plans = []
    warnings = []
    
    for time_period in time_periods:
        total_utilization = time_period.get('Total', {})
        if total_utilization:
            savings_plan = create_savings_plan_entry(
                total_utilization, 
                time_period.get('TimePeriod', {})
            )
            savings_plans.append(savings_plan)
            
            # Add warning for low utilization
            utilization_pct = float(savings_plan['utilizationPercentage'])
            if utilization_pct < LOW_UTILIZATION_THRESHOLD:
                warnings.append(f"Low utilization ({savings_plan['utilizationPercentage']}%) detected for {SAVINGS_PLANS_TYPE}")
    
    return savings_plans, warnings


def create_success_response(savings_plans, warnings):
    """Create success response structure"""
    total_savings_plans = len(savings_plans)
    
    if total_savings_plans == 0:
        return {
            'status': 'Success',
            'message': 'No Savings Plans found in your account for the specified time period.',
            'timestamp': datetime.now().isoformat(),
            'total_savings_plans': '0',
            'details': {
                'savings_plans': [],
                'warnings': warnings
            }
        }
    
    return {
        'status': 'Success',
        'message': f'{total_savings_plans} Savings Plan{"s" if total_savings_plans != 1 else ""} found.',
        'timestamp': datetime.now().isoformat(),
        'total_savings_plans': str(total_savings_plans),
        'details': {
            'savings_plans': savings_plans,
            'warnings': warnings
        }
    }


def check_savings_plan_utilization(profile_name=None, time_period_months=1):
    """
    Check AWS Savings Plan utilization
    
    Args:
        profile_name (str): AWS profile name (optional)
        time_period_months (int): Number of months to analyze (default: 1)
        
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
        
        # Build request parameters for Savings Plans utilization
        request_params = {
            'TimePeriod': {
                'Start': start_date.strftime('%Y-%m-%d'),
                'End': end_date.strftime('%Y-%m-%d')
            },
            'Granularity': 'MONTHLY'
        }
        
        # Call Cost Explorer API for Savings Plans utilization
        response = ce_client.get_savings_plans_utilization(**request_params)
        
        # Process utilization data from UtilizationsByTime (time periods)
        time_periods = response.get('SavingsPlansUtilizationsByTime', [])
        savings_plans, warnings = process_time_period_data(time_periods)
        
        # If no time period data, check the overall Total
        if not savings_plans:
            total_data = response.get('Total', {})
            if total_data:
                savings_plan = create_savings_plan_entry(total_data, 'Overall')
                savings_plans.append(savings_plan)
                
                utilization_pct = float(savings_plan['utilizationPercentage'])
                if utilization_pct < LOW_UTILIZATION_THRESHOLD:
                    warnings.append(f"Low utilization ({savings_plan['utilizationPercentage']}%) detected for {SAVINGS_PLANS_TYPE}")
        
        # Generate result
        return create_success_response(savings_plans, warnings)
        
    except NoCredentialsError:
        return {
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'timestamp': datetime.now().isoformat(),
            'total_savings_plans': '0',
            'details': {
                'error_type': 'NoCredentialsError',
                'error_message': 'AWS credentials not found',
                'savings_plans': [],
                'warnings': []
            }
        }
    
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        # Handle specific case where no Savings Plans data is available
        if error_code == 'DataUnavailableException':
            return {
                'status': 'Success',
                'message': 'No Savings Plans found in your account or no usage data available for the specified time period.',
                'timestamp': datetime.now().isoformat(),
                'total_savings_plans': '0',
                'details': {
                    'savings_plans': [],
                    'warnings': ['No Savings Plans data available - you may not have any active Savings Plans in your account']
                }
            }
        
        return {
            'status': 'Error',
            'message': f'AWS API error: {error_message}',
            'timestamp': datetime.now().isoformat(),
            'total_savings_plans': '0',
            'details': {
                'error_type': error_code,
                'error_message': error_message,
                'savings_plans': [],
                'warnings': []
            }
        }
    
    except Exception as e:
        return {
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'total_savings_plans': '0',
            'details': {
                'error_type': 'UnexpectedError',
                'error_message': str(e),
                'savings_plans': [],
                'warnings': []
            }
        }


def print_summary_output(result):
    """Print summary output for savings plans"""
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Savings Plans: {result['total_savings_plans']}")
    
    if result['details']['savings_plans']:
        print("\nSavings Plans Utilization:")
        for i, plan in enumerate(result['details']['savings_plans'], 1):
            print(f"  {i}. {plan['type']} - {plan['utilizationPercentage']}% utilization")
            print(f"     Total Commitment: {plan['totalCommitment']}")
            print(f"     Used Commitment: {plan['usedCommitment']}")
            print(f"     Unused Commitment: {plan['unusedCommitment']}")
            if plan['period'] != 'Overall':
                period_info = plan['period']
                if isinstance(period_info, dict):
                    print(f"     Period: {period_info.get('Start', 'N/A')} to {period_info.get('End', 'N/A')}")
                else:
                    print(f"     Period: {period_info}")
            print()
    
    if result['details']['warnings']:
        print("Warnings:")
        for warning in result['details']['warnings']:
            print(f"  - {warning}")


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check AWS Savings Plan utilization')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--months', type=int, default=1, 
                       help='Number of months to analyze (default: 1)')
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_savings_plan_utilization(
        profile_name=args.profile,
        time_period_months=args.months
    )
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        print_summary_output(result)


if __name__ == "__main__":
    main()
