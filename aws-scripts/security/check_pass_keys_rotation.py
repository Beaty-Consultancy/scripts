#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Security Pillar
Check IAM User Password and Access Key Rotation

This script checks if IAM users have rotated their passwords and access keys
within the last 90 days to ensure proper credential hygiene.

Rotation Checks:
- User password last changed (if password login enabled)
- Access key age for all active access keys
- Users without recent rotation activity
"""

import boto3
import json
import sys
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError, NoCredentialsError


def get_all_iam_users(iam_client):
    """
    Get all IAM users with pagination support
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        list: List of IAM users
    """
    try:
        users = []
        paginator = iam_client.get_paginator('list_users')
        
        for page in paginator.paginate():
            users.extend(page.get('Users', []))
        
        return users
        
    except ClientError as e:
        raise ClientError(e.response, e.operation_name) from e
    except Exception as e:
        raise RuntimeError(f"Failed to get IAM users: {str(e)}") from e


def get_user_login_profile(iam_client, username):
    """
    Get user login profile to check if password login is enabled
    
    Args:
        iam_client: Boto3 IAM client
        username: IAM username
        
    Returns:
        dict: Login profile information or None if not exists
    """
    try:
        response = iam_client.get_login_profile(UserName=username)
        login_profile = response.get('LoginProfile', {})
        return {
            'has_login_profile': True,
            'password_last_used': login_profile.get('PasswordLastUsed'),
            'create_date': login_profile.get('CreateDate'),
            'password_reset_required': login_profile.get('PasswordResetRequired', False),
            'error': None
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchEntity':
            return {
                'has_login_profile': False,
                'password_last_used': None,
                'create_date': None,
                'password_reset_required': False,
                'error': None
            }
        else:
            return {
                'has_login_profile': None,
                'password_last_used': None,
                'create_date': None,
                'password_reset_required': None,
                'error': str(e)
            }


def get_user_access_keys(iam_client, username):
    """
    Get all access keys for a user
    
    Args:
        iam_client: Boto3 IAM client
        username: IAM username
        
    Returns:
        list: List of access key information
    """
    try:
        response = iam_client.list_access_keys(UserName=username)
        access_keys = response.get('AccessKeyMetadata', [])
        
        key_details = []
        for key in access_keys:
            # Get additional key details
            key_info = {
                'access_key_id': key.get('AccessKeyId', ''),
                'status': key.get('Status', ''),
                'create_date': key.get('CreateDate'),
                'last_used': None,
                'last_used_service': None,
                'last_used_region': None,
                'error': None
            }
            
            # Try to get last used information
            try:
                last_used_response = iam_client.get_access_key_last_used(
                    AccessKeyId=key.get('AccessKeyId', '')
                )
                last_used_info = last_used_response.get('AccessKeyLastUsed', {})
                key_info['last_used'] = last_used_info.get('LastUsedDate')
                key_info['last_used_service'] = last_used_info.get('ServiceName')
                key_info['last_used_region'] = last_used_info.get('Region')
            except ClientError:
                # If we can't get last used info, continue without it
                pass
            
            key_details.append(key_info)
        
        return key_details
        
    except ClientError as e:
        return [{
            'access_key_id': 'Error',
            'status': 'Error',
            'create_date': None,
            'last_used': None,
            'last_used_service': None,
            'last_used_region': None,
            'error': str(e)
        }]


def calculate_days_since_date(date_obj, reference_date=None):
    """
    Calculate days since a given date
    
    Args:
        date_obj: datetime object or None
        reference_date: Reference date (defaults to now)
        
    Returns:
        int: Days since the date, or None if date_obj is None
    """
    if date_obj is None:
        return None
    
    if reference_date is None:
        reference_date = datetime.now(timezone.utc)
    
    # Ensure both dates are timezone-aware
    if date_obj.tzinfo is None:
        date_obj = date_obj.replace(tzinfo=timezone.utc)
    
    delta = reference_date - date_obj
    return delta.days


def analyze_password_rotation(login_profile, rotation_threshold_days):
    """
    Analyze password rotation compliance
    
    Args:
        login_profile: Login profile information
        rotation_threshold_days: Threshold for password rotation
        
    Returns:
        tuple: (needs_rotation, days_old)
    """
    password_needs_rotation = False
    password_days_old = None
    password_last_changed = login_profile.get('create_date')
    
    if login_profile.get('has_login_profile') and password_last_changed:
        password_days_old = calculate_days_since_date(password_last_changed)
        if password_days_old is not None:
            password_needs_rotation = password_days_old > rotation_threshold_days
    
    return password_needs_rotation, password_days_old


def create_key_rotation_entry(key, key_age):
    """
    Create rotation entry for a key that needs rotation
    
    Args:
        key: Access key information
        key_age: Age of the key in days
        
    Returns:
        dict: Key rotation entry
    """
    return {
        'access_key_id': key['access_key_id'],
        'age_days': key_age,
        'create_date': key['create_date'].isoformat() if key['create_date'] else None,
        'last_used': key['last_used'].isoformat() if key['last_used'] else None,
        'last_used_service': key['last_used_service']
    }


def analyze_access_keys_rotation(access_keys, rotation_threshold_days):
    """
    Analyze access keys rotation compliance
    
    Args:
        access_keys: List of access keys
        rotation_threshold_days: Threshold for key rotation
        
    Returns:
        tuple: (keys_needing_rotation, active_keys_count)
    """
    keys_needing_rotation = []
    active_keys_count = 0
    
    for key in access_keys:
        if key['status'] != 'Active' or key.get('error'):
            continue
            
        active_keys_count += 1
        key_age = calculate_days_since_date(key['create_date'])
        
        if key_age and key_age > rotation_threshold_days:
            rotation_entry = create_key_rotation_entry(key, key_age)
            keys_needing_rotation.append(rotation_entry)
    
    return keys_needing_rotation, active_keys_count


def build_access_key_analysis(access_keys, keys_needing_rotation, active_keys_count):
    """
    Build access key analysis structure
    
    Args:
        access_keys: List of all access keys
        keys_needing_rotation: Keys that need rotation
        active_keys_count: Count of active keys
        
    Returns:
        dict: Access key analysis
    """
    return {
        'active_keys_count': active_keys_count,
        'keys_needing_rotation_count': len(keys_needing_rotation),
        'keys_needing_rotation': keys_needing_rotation,
        'all_keys': [{
            'access_key_id': key['access_key_id'],
            'status': key['status'],
            'age_days': calculate_days_since_date(key['create_date']),
            'create_date': key['create_date'].isoformat() if key['create_date'] else None,
            'last_used': key['last_used'].isoformat() if key['last_used'] else None,
            'error': key.get('error')
        } for key in access_keys]
    }


def analyze_user_credentials(iam_client, user, rotation_threshold_days=90):
    """
    Analyze user credentials for rotation compliance
    
    Args:
        iam_client: Boto3 IAM client
        user: IAM user dict
        rotation_threshold_days: Threshold for credential rotation (default 90 days)
        
    Returns:
        dict: Complete user credential analysis
    """
    username = user['UserName']
    user_create_date = user.get('CreateDate')
    password_last_used = user.get('PasswordLastUsed')
    
    # Get login profile (password) information
    login_profile = get_user_login_profile(iam_client, username)
    
    # Get access key information
    access_keys = get_user_access_keys(iam_client, username)
    
    # Analyze password rotation
    password_needs_rotation, password_days_old = analyze_password_rotation(
        login_profile, rotation_threshold_days
    )
    
    # Analyze access key rotation
    keys_needing_rotation, active_keys_count = analyze_access_keys_rotation(
        access_keys, rotation_threshold_days
    )
    
    # Determine overall compliance
    needs_rotation = password_needs_rotation or len(keys_needing_rotation) > 0
    
    # Build password analysis
    password_last_changed = login_profile.get('create_date')
    password_analysis = {
        'has_login_profile': login_profile.get('has_login_profile'),
        'password_needs_rotation': password_needs_rotation,
        'password_days_old': password_days_old,
        'password_last_changed': password_last_changed.isoformat() if password_last_changed else None,
        'password_reset_required': login_profile.get('password_reset_required'),
        'error': login_profile.get('error')
    }
    
    # Build access key analysis
    access_key_analysis = build_access_key_analysis(
        access_keys, keys_needing_rotation, active_keys_count
    )
    
    return {
        'username': username,
        'user_create_date': user_create_date.isoformat() if user_create_date else None,
        'password_last_used': password_last_used.isoformat() if password_last_used else None,
        'needs_rotation': needs_rotation,
        'password_analysis': password_analysis,
        'access_key_analysis': access_key_analysis
    }


def check_iam_credentials_rotation(rotation_threshold_days=90):
    """
    Check IAM user credentials rotation
    
    Args:
        rotation_threshold_days: Threshold for credential rotation (default 90 days)
        
    Returns:
        dict: Complete check results
    """
    try:
        # IAM is a global service
        iam_client = boto3.client('iam', region_name='us-east-1')
        
        # Get all users
        users = get_all_iam_users(iam_client)
        
        # Analyze each user
        user_analyses = []
        users_needing_rotation = []
        error_users = []
        
        for user in users:
            analysis = analyze_user_credentials(iam_client, user, rotation_threshold_days)
            user_analyses.append(analysis)
            
            # Check for errors
            has_errors = (
                analysis['password_analysis'].get('error') or
                any(key.get('error') for key in analysis['access_key_analysis']['all_keys'])
            )
            
            if has_errors:
                error_users.append(analysis)
            elif analysis['needs_rotation']:
                users_needing_rotation.append(analysis)
        
        return {
            'total_users': len(users),
            'compliant_users': len([u for u in user_analyses if not u['needs_rotation'] and 
                                  not u['password_analysis'].get('error') and
                                  not any(key.get('error') for key in u['access_key_analysis']['all_keys'])]),
            'users_needing_rotation': len(users_needing_rotation),
            'error_users': len(error_users),
            'rotation_threshold_days': rotation_threshold_days,
            'users': user_analyses,
            'non_compliant_items': users_needing_rotation,
            'error_items': error_users,
            'error': None
        }
        
    except ClientError as e:
        error_msg = f"AWS API error: {str(e)}"
        return {
            'total_users': 0,
            'compliant_users': 0,
            'users_needing_rotation': 0,
            'error_users': 0,
            'rotation_threshold_days': rotation_threshold_days,
            'users': [],
            'non_compliant_items': [],
            'error_items': [],
            'error': error_msg
        }
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        return {
            'total_users': 0,
            'compliant_users': 0,
            'users_needing_rotation': 0,
            'error_users': 0,
            'rotation_threshold_days': rotation_threshold_days,
            'users': [],
            'non_compliant_items': [],
            'error_items': [],
            'error': error_msg
        }


def determine_rotation_status(stats):
    """Determine overall rotation compliance status and message"""
    total_users = stats['total_users']
    users_needing_rotation = stats['users_needing_rotation']
    error_users = stats['error_users']
    threshold_days = stats['rotation_threshold_days']
    
    if total_users == 0:
        status = 'Success'
        message = 'No IAM users found in the account.'
    elif users_needing_rotation == 0 and error_users == 0:
        status = 'Success'
        message = f'All {total_users} IAM users have rotated credentials within {threshold_days} days.'
    elif users_needing_rotation > 0 and error_users == 0:
        status = 'Warning'
        message = f'Found {users_needing_rotation} IAM users with credentials older than {threshold_days} days out of {total_users} total users.'
    elif users_needing_rotation == 0 and error_users > 0:
        status = 'Warning'
        message = f'Could not determine rotation status for {error_users} IAM users out of {total_users} total users.'
    else:
        status = 'Warning'
        message = f'Found {users_needing_rotation} non-compliant and {error_users} error IAM users out of {total_users} total users.'
    
    return status, message


def check_pass_keys_rotation(profile_name=None, rotation_threshold_days=90):
    """
    Main function to check IAM password and access key rotation
    
    Args:
        profile_name: AWS profile name (optional)
        rotation_threshold_days: Threshold for credential rotation (default 90 days)
        
    Returns:
        dict: Complete check results in JSON format
    """
    timestamp = datetime.now(timezone.utc).isoformat() + 'Z'
    
    try:
        # Create session and IAM client
        session = boto3.Session(profile_name=profile_name)
        
        # Override the default client creation for this specific check
        original_client = boto3.client
        boto3.client = lambda service, **kwargs: session.client(service, **kwargs)
        
        try:
            # Perform the credentials rotation check
            result = check_iam_credentials_rotation(rotation_threshold_days)
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        stats = {
            'total_users': result['total_users'],
            'compliant_users': result['compliant_users'],
            'users_needing_rotation': result['users_needing_rotation'],
            'error_users': result['error_users'],
            'rotation_threshold_days': result['rotation_threshold_days']
        }
        
        status, message = determine_rotation_status(stats)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'iam_credentials_rotation',
            'total_users': result['total_users'],
            'compliant_users': result['compliant_users'],
            'users_needing_rotation': result['users_needing_rotation'],
            'error_users': result['error_users'],
            'rotation_threshold_days': result['rotation_threshold_days'],
            'users': result['users'],
            'non_compliant_items': result['non_compliant_items']
        }
        
        # Add error details if any
        if result['error']:
            final_result['error'] = result['error']
        
        if result['error_items']:
            final_result['error_items'] = result['error_items']
        
        return final_result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'check_type': 'iam_credentials_rotation',
            'total_users': 0,
            'compliant_users': 0,
            'users_needing_rotation': 0,
            'error_users': 0,
            'rotation_threshold_days': rotation_threshold_days,
            'users': [],
            'non_compliant_items': []
        }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'check_type': 'iam_credentials_rotation',
            'total_users': 0,
            'compliant_users': 0,
            'users_needing_rotation': 0,
            'error_users': 0,
            'rotation_threshold_days': rotation_threshold_days,
            'users': [],
            'non_compliant_items': []
        }


def print_password_analysis(pwd_analysis):
    """Print password analysis details"""
    if pwd_analysis['has_login_profile']:
        print("   Password Analysis:")
        print("     Has Console Access: Yes")
        print(f"     Password Age (days): {pwd_analysis.get('password_days_old', 'Unknown')}")
        print(f"     Needs Rotation: {'Yes' if pwd_analysis['password_needs_rotation'] else 'No'}")
        if pwd_analysis['password_reset_required']:
            print("     Password Reset Required: Yes")
    else:
        print("   Password Analysis: No console access")


def print_access_key_analysis(key_analysis):
    """Print access key analysis details"""
    print(f"   Access Keys: {key_analysis['active_keys_count']} active")
    
    if key_analysis['keys_needing_rotation']:
        print(f"   Keys Needing Rotation: {key_analysis['keys_needing_rotation_count']}")
        for key in key_analysis['keys_needing_rotation']:
            print(f"     Key {key['access_key_id']}: {key['age_days']} days old")


def print_user_errors(pwd_analysis, key_analysis):
    """Print user-related errors"""
    errors = []
    if pwd_analysis.get('error'):
        errors.append(f"Password: {pwd_analysis['error']}")
    
    key_errors = [key for key in key_analysis['all_keys'] if key.get('error')]
    if key_errors:
        for key in key_errors:
            errors.append(f"Access Key {key['access_key_id']}: {key['error']}")
    
    if errors:
        print("   Errors:")
        for error in errors:
            print(f"     {error}")


def print_user_details(user, index):
    """Print detailed information about an IAM user"""
    print(f"\n{index}. IAM User Details:")
    print(f"   Username: {user['username']}")
    print(f"   User Created: {user['user_create_date']}")
    print(f"   Password Last Used: {user['password_last_used'] or 'Never'}")
    print(f"   Needs Rotation: {'Yes' if user['needs_rotation'] else 'No'}")
    
    # Password analysis
    pwd_analysis = user['password_analysis']
    print_password_analysis(pwd_analysis)
    
    # Access key analysis
    key_analysis = user['access_key_analysis']
    print_access_key_analysis(key_analysis)
    
    # Print errors if any
    print_user_errors(pwd_analysis, key_analysis)


def print_basic_summary(result):
    """Print basic summary information"""
    print("\nIAM Credentials Rotation Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Users: {result['total_users']}")
    print(f"Compliant Users: {result['compliant_users']}")
    print(f"Users Needing Rotation: {result['users_needing_rotation']}")
    print(f"Error Users: {result['error_users']}")
    print(f"Rotation Threshold: {result['rotation_threshold_days']} days")


def print_non_compliant_users(users):
    """Print details of users needing credential rotation"""
    if users:
        print(f"\nUsers Needing Credential Rotation ({len(users)}):")
        for i, user in enumerate(users, 1):
            print_user_details(user, i)


def print_error_users(users):
    """Print details of users with errors"""
    if users:
        print(f"\nUsers with Errors ({len(users)}):")
        for i, user in enumerate(users, 1):
            print_user_details(user, i)


def print_summary_output(result):
    """Print human-readable summary output"""
    print_basic_summary(result)
    
    non_compliant_users = result.get('non_compliant_items', [])
    print_non_compliant_users(non_compliant_users)
    
    error_users = result.get('error_items', [])
    print_error_users(error_users)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check IAM user password and access key rotation")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    parser.add_argument('--threshold', type=int, default=90,
                       help='Rotation threshold in days (default: 90)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_pass_keys_rotation(
        profile_name=args.profile,
        rotation_threshold_days=args.threshold
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
