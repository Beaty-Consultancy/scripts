#!/usr/bin/env python3
"""
IAM Users MFA Check Script

This script checks if all IAM users have Multi-Factor Authentication (MFA) enabled by:
- Generating an IAM credential report
- Analyzing MFA status for all users
- Identifying users without MFA enabled

Returns structured data for dashboard compatibility.
"""

import boto3
import json
import csv
import base64
import os
import tempfile
import time
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime

# Constants
CREDENTIAL_REPORT_FILENAME = "credential-report.csv"
MAX_REPORT_GENERATION_WAIT = 120  # Maximum wait time in seconds
REPORT_GENERATION_POLL_INTERVAL = 5  # Poll interval in seconds


def generate_credential_report(iam_client):
    """Generate IAM credential report and wait for completion"""
    try:
        # Start credential report generation
        response = iam_client.generate_credential_report()
        state = response.get('State', '')
        
        # If report is already complete, return immediately
        if state == 'COMPLETE':
            return True
        
        # Wait for report generation to complete
        start_time = time.time()
        while time.time() - start_time < MAX_REPORT_GENERATION_WAIT:
            try:
                response = iam_client.generate_credential_report()
                state = response.get('State', '')
                
                if state == 'COMPLETE':
                    return True
                elif state == 'INPROGRESS':
                    time.sleep(REPORT_GENERATION_POLL_INTERVAL)
                    continue
                else:
                    return False
                    
            except ClientError as e:
                # If report is already being generated, check status
                if e.response['Error']['Code'] == 'ReportInProgress':
                    time.sleep(REPORT_GENERATION_POLL_INTERVAL)
                    continue
                else:
                    raise e
        
        return False  # Timeout
        
    except Exception as e:
        raise RuntimeError(f"Failed to generate credential report: {str(e)}")


def fix_base64_padding(content):
    """Fix base64 padding if needed"""
    # Add padding if necessary
    missing_padding = len(content) % 4
    if missing_padding:
        content += '=' * (4 - missing_padding)
    return content


def download_credential_report(iam_client, temp_dir):
    """Download credential report and save to temporary file"""
    try:
        response = iam_client.get_credential_report()
        content = response.get('Content', '')
        
        if not content:
            raise ValueError("Empty credential report content")
        
        # Handle case where content is already bytes (from boto3)
        if isinstance(content, bytes):
            decoded_content = content.decode('utf-8')
        else:
            # Fix base64 padding if needed and decode
            content = fix_base64_padding(content)
            decoded_content = base64.b64decode(content).decode('utf-8')
        
        # Save to temporary file
        report_path = os.path.join(temp_dir, CREDENTIAL_REPORT_FILENAME)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(decoded_content)
        
        return report_path
        
    except Exception as e:
        raise RuntimeError(f"Failed to download credential report: {str(e)}")


def parse_credential_report(report_path):
    """Parse credential report CSV and extract user MFA information"""
    users_data = []
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            csv_reader = csv.DictReader(f)
            
            for row in csv_reader:
                user_name = row.get('user', '')
                user_arn = row.get('arn', '')
                mfa_active = row.get('mfa_active', '').lower() == 'true'
                password_enabled = row.get('password_enabled', '').lower() == 'true'
                user_creation_time = row.get('user_creation_time', '')
                password_last_used = row.get('password_last_used', '')
                access_key_1_active = row.get('access_key_1_active', '').lower() == 'true'
                access_key_2_active = row.get('access_key_2_active', '').lower() == 'true'
                
                # Skip root account for user-specific analysis
                is_root = user_name == '<root_account>'
                
                user_data = {
                    'userName': user_name,
                    'userArn': user_arn,
                    'isRoot': is_root,
                    'mfaActive': mfa_active,
                    'passwordEnabled': password_enabled,
                    'userCreationTime': user_creation_time,
                    'passwordLastUsed': password_last_used,
                    'accessKey1Active': access_key_1_active,
                    'accessKey2Active': access_key_2_active,
                    'hasActiveAccessKeys': access_key_1_active or access_key_2_active,
                    'requiresMfa': password_enabled or access_key_1_active or access_key_2_active
                }
                
                users_data.append(user_data)
    
    except Exception as e:
        raise RuntimeError(f"Failed to parse credential report: {str(e)}")
    
    return users_data


def analyze_user_mfa_stats(users_data):
    """Analyze MFA statistics for users"""
    # Separate root and regular users
    root_users = [user for user in users_data if user['isRoot']]
    regular_users = [user for user in users_data if not user['isRoot']]
    
    # Analyze regular users only for main statistics
    users_requiring_mfa = [user for user in regular_users if user['requiresMfa']]
    users_with_mfa = [user for user in users_requiring_mfa if user['mfaActive']]
    users_without_mfa = [user for user in users_requiring_mfa if not user['mfaActive']]
    
    # Root account analysis
    root_mfa_enabled = any(user['mfaActive'] for user in root_users)
    
    return {
        'total_users': len(regular_users),
        'total_users_requiring_mfa': len(users_requiring_mfa),
        'users_with_mfa': len(users_with_mfa),
        'users_without_mfa': len(users_without_mfa),
        'root_mfa_enabled': root_mfa_enabled,
        'users_without_mfa_list': [user['userName'] for user in users_without_mfa],
        'all_users_have_mfa': len(users_without_mfa) == 0 and len(users_requiring_mfa) > 0
    }


def determine_overall_status(mfa_stats):
    """Determine overall status based on MFA compliance"""
    total_requiring_mfa = mfa_stats['total_users_requiring_mfa']
    users_without_mfa = mfa_stats['users_without_mfa']
    root_mfa_enabled = mfa_stats['root_mfa_enabled']
    
    if total_requiring_mfa == 0:
        return {
            'status': 'Success',
            'message': 'No IAM users found that require MFA (no users with passwords or access keys).'
        }
    elif users_without_mfa == 0 and root_mfa_enabled:
        return {
            'status': 'Success',
            'message': f'All {total_requiring_mfa} users requiring MFA have it enabled, and root account has MFA enabled.'
        }
    elif users_without_mfa == 0:
        return {
            'status': 'Warning',
            'message': f'All {total_requiring_mfa} users requiring MFA have it enabled, but root account does not have MFA enabled.'
        }
    elif root_mfa_enabled:
        return {
            'status': 'Warning',
            'message': f'{users_without_mfa} out of {total_requiring_mfa} users requiring MFA do not have it enabled. Root account has MFA enabled.'
        }
    else:
        return {
            'status': 'Warning',
            'message': f'{users_without_mfa} out of {total_requiring_mfa} users requiring MFA do not have it enabled. Root account also lacks MFA.'
        }


def check_all_users_mfa(profile_name=None):
    """
    Check MFA status for all IAM users
    
    Args:
        profile_name (str): AWS profile name (optional)
        
    Returns:
        dict: Structured result for dashboard compatibility
    """
    
    temp_dir = None
    report_path = None
    
    try:
        # Initialize session with profile
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
        else:
            session = boto3.Session()
        
        iam_client = session.client('iam')
        
        # Create temporary directory
        temp_dir = tempfile.mkdtemp()
        
        # Generate credential report
        if not generate_credential_report(iam_client):
            raise RuntimeError("Credential report generation timed out or failed")
        
        # Download credential report
        report_path = download_credential_report(iam_client, temp_dir)
        
        # Parse credential report
        users_data = parse_credential_report(report_path)
        
        # Analyze MFA statistics
        mfa_stats = analyze_user_mfa_stats(users_data)
        
        # Determine overall status
        status_info = determine_overall_status(mfa_stats)
        
        return {
            'status': status_info['status'],
            'message': status_info['message'],
            'timestamp': datetime.now().isoformat(),
            'total_users': str(mfa_stats['total_users']),
            'users_requiring_mfa': str(mfa_stats['total_users_requiring_mfa']),
            'users_with_mfa': str(mfa_stats['users_with_mfa']),
            'users_without_mfa': str(mfa_stats['users_without_mfa']),
            'root_mfa_enabled': mfa_stats['root_mfa_enabled'],
            'all_users_have_mfa': mfa_stats['all_users_have_mfa'],
            'details': {
                'users_data': users_data,
                'users_without_mfa': mfa_stats['users_without_mfa_list'],
                'analysis': mfa_stats
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
    
    finally:
        # Cleanup temporary files
        if report_path and os.path.exists(report_path):
            try:
                os.remove(report_path)
            except Exception:
                pass
        
        if temp_dir and os.path.exists(temp_dir):
            try:
                os.rmdir(temp_dir)
            except Exception:
                pass


def create_error_result(status, message, error_type, error_message):
    """Create error result dictionary"""
    return {
        'status': status,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'total_users': '0',
        'users_requiring_mfa': '0',
        'users_with_mfa': '0',
        'users_without_mfa': '0',
        'root_mfa_enabled': False,
        'all_users_have_mfa': False,
        'details': {
            'error_type': error_type,
            'error_message': error_message,
            'users_data': [],
            'users_without_mfa': []
        }
    }


def print_user_details(user, index):
    """Print detailed information for a user"""
    print(f"  {index}. {user['userName']}")
    print(f"     ARN: {user['userArn']}")
    print(f"     MFA Active: {'✓' if user['mfaActive'] else '✗'}")
    print(f"     Password Enabled: {'✓' if user['passwordEnabled'] else '✗'}")
    print(f"     Active Access Keys: {'✓' if user['hasActiveAccessKeys'] else '✗'}")
    print(f"     Requires MFA: {'✓' if user['requiresMfa'] else '✗'}")
    
    if user['userCreationTime']:
        print(f"     Created: {user['userCreationTime']}")
    
    if user['passwordLastUsed'] and user['passwordLastUsed'] != 'N/A':
        print(f"     Password Last Used: {user['passwordLastUsed']}")
    
    print()


def print_summary_output(result):
    """Print summary output for MFA check"""
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Users: {result['total_users']}")
    print(f"Users Requiring MFA: {result['users_requiring_mfa']}")
    print(f"Users With MFA: {result['users_with_mfa']}")
    print(f"Users Without MFA: {result['users_without_mfa']}")
    print(f"Root MFA Enabled: {result['root_mfa_enabled']}")
    print(f"All Users Have MFA: {result['all_users_have_mfa']}")
    
    if result['details']['users_without_mfa']:
        print("\nUsers Without MFA:")
        for user_name in result['details']['users_without_mfa']:
            print(f"  - {user_name}")
    
    if result['details']['users_data']:
        print("\nAll Users Details:")
        regular_users = [user for user in result['details']['users_data'] if not user['isRoot']]
        root_users = [user for user in result['details']['users_data'] if user['isRoot']]
        
        if regular_users:
            print("\n  Regular Users:")
            for i, user in enumerate(regular_users, 1):
                print_user_details(user, i)
        
        if root_users:
            print("\n  Root Account:")
            for i, user in enumerate(root_users, 1):
                print_user_details(user, i)


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check MFA status for all IAM users')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_all_users_mfa(profile_name=args.profile)
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        print_summary_output(result)


if __name__ == "__main__":
    main()
