#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Security Pillar
Check IAM Account Password Policy

This script checks if strong password policies are in place according to the specified standards.

Required Password Policy Standards:
- Minimum password length: 14 characters
- Require lowercase characters: true
- Require uppercase characters: true
- Require numbers: true
- Require symbols: true
- Allow users to change password: true
"""

import boto3
import json
import sys
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError


# Required password policy standards
REQUIRED_POLICY = {
    'minimum_password_length': 14,
    'require_lowercase_characters': True,
    'require_uppercase_characters': True,
    'require_numbers': True,
    'require_symbols': True,
    'allow_users_to_change_password': True
}


def get_password_policy(iam_client):
    """
    Get the current IAM account password policy
    
    Args:
        iam_client: Boto3 IAM client
        
    Returns:
        dict: Password policy details or None if not found
    """
    try:
        response = iam_client.get_account_password_policy()
        return response.get('PasswordPolicy', {})
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchEntity':
            # No password policy exists
            return None
        else:
            # Other AWS API error
            raise e


def analyze_password_policy(current_policy):
    """
    Analyze the current password policy against required standards
    
    Args:
        current_policy: Current password policy dict or None
        
    Returns:
        dict: Analysis results with compliance status and details
    """
    if current_policy is None:
        return {
            'policy_exists': False,
            'is_compliant': False,
            'non_compliant_settings': ['No password policy exists'],
            'current_settings': {},
            'required_settings': REQUIRED_POLICY
        }
    
    non_compliant_settings = []
    current_settings = {}
    
    # Check minimum password length
    min_length = current_policy.get('MinimumPasswordLength', 0)
    current_settings['minimum_password_length'] = min_length
    if min_length < REQUIRED_POLICY['minimum_password_length']:
        non_compliant_settings.append(
            f"Minimum password length is {min_length}, required: {REQUIRED_POLICY['minimum_password_length']}"
        )
    
    # Check require lowercase characters
    require_lowercase = current_policy.get('RequireLowercaseCharacters', False)
    current_settings['require_lowercase_characters'] = require_lowercase
    if not require_lowercase and REQUIRED_POLICY['require_lowercase_characters']:
        non_compliant_settings.append("Lowercase characters are not required")
    
    # Check require uppercase characters
    require_uppercase = current_policy.get('RequireUppercaseCharacters', False)
    current_settings['require_uppercase_characters'] = require_uppercase
    if not require_uppercase and REQUIRED_POLICY['require_uppercase_characters']:
        non_compliant_settings.append("Uppercase characters are not required")
    
    # Check require numbers
    require_numbers = current_policy.get('RequireNumbers', False)
    current_settings['require_numbers'] = require_numbers
    if not require_numbers and REQUIRED_POLICY['require_numbers']:
        non_compliant_settings.append("Numbers are not required")
    
    # Check require symbols
    require_symbols = current_policy.get('RequireSymbols', False)
    current_settings['require_symbols'] = require_symbols
    if not require_symbols and REQUIRED_POLICY['require_symbols']:
        non_compliant_settings.append("Symbols are not required")
    
    # Check allow users to change password
    allow_change = current_policy.get('AllowUsersToChangePassword', False)
    current_settings['allow_users_to_change_password'] = allow_change
    if not allow_change and REQUIRED_POLICY['allow_users_to_change_password']:
        non_compliant_settings.append("Users are not allowed to change their own passwords")
    
    return {
        'policy_exists': True,
        'is_compliant': len(non_compliant_settings) == 0,
        'non_compliant_settings': non_compliant_settings,
        'current_settings': current_settings,
        'required_settings': REQUIRED_POLICY
    }


def determine_policy_status(analysis):
    """Determine overall password policy status and message"""
    if not analysis['policy_exists']:
        status = 'Warning'
        message = 'No IAM account password policy is configured. A strong password policy is required for security.'
    elif analysis['is_compliant']:
        status = 'Success'
        message = 'IAM account password policy meets all required security standards.'
    else:
        non_compliant_count = len(analysis['non_compliant_settings'])
        status = 'Warning'
        message = f'IAM account password policy has {non_compliant_count} non-compliant settings that need to be addressed.'
    
    return status, message


def check_password_policy(profile_name=None):
    """
    Main function to check IAM account password policy
    
    Args:
        profile_name: AWS profile name (optional)
        
    Returns:
        dict: Complete check results in JSON format
    """
    timestamp = datetime.now(timezone.utc).isoformat() + 'Z'
    
    try:
        # Create session and IAM client
        session = boto3.Session(profile_name=profile_name)
        iam_client = session.client('iam')
        
        # Get current password policy
        current_policy = get_password_policy(iam_client)
        
        # Analyze the policy
        analysis = analyze_password_policy(current_policy)
        
        # Determine overall status
        status, message = determine_policy_status(analysis)
        
        # Build final result
        result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 'iam_password_policy',
            'policy_exists': analysis['policy_exists'],
            'is_compliant': analysis['is_compliant'],
            'current_settings': analysis['current_settings'],
            'required_settings': analysis['required_settings'],
            'non_compliant_settings': analysis['non_compliant_settings']
        }
        
        return result
        
    except NoCredentialsError:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'check_type': 'iam_password_policy',
            'policy_exists': False,
            'is_compliant': False,
            'current_settings': {},
            'required_settings': REQUIRED_POLICY,
            'non_compliant_settings': []
        }
    except ClientError as e:
        error_msg = f"AWS API error: {str(e)}"
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': error_msg,
            'check_type': 'iam_password_policy',
            'policy_exists': False,
            'is_compliant': False,
            'current_settings': {},
            'required_settings': REQUIRED_POLICY,
            'non_compliant_settings': []
        }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'check_type': 'iam_password_policy',
            'policy_exists': False,
            'is_compliant': False,
            'current_settings': {},
            'required_settings': REQUIRED_POLICY,
            'non_compliant_settings': []
        }


def print_policy_comparison(result):
    """Print comparison between current and required settings"""
    print("\nPassword Policy Comparison:")
    print("-" * 50)
    
    current = result['current_settings']
    required = result['required_settings']
    
    print(f"{'Setting':<35} {'Current':<10} {'Required':<10} {'Status'}")
    print("-" * 70)
    
    for key, required_value in required.items():
        current_value = current.get(key, 'Not Set')
        
        # Determine status
        if key == 'minimum_password_length':
            status = "✓" if isinstance(current_value, int) and current_value >= required_value else "✗"
        else:
            status = "✓" if current_value == required_value else "✗"
        
        print(f"{key.replace('_', ' ').title():<35} {str(current_value):<10} {str(required_value):<10} {status}")


def print_non_compliant_issues(result):
    """Print non-compliant settings"""
    if result['non_compliant_settings']:
        print(f"\nNon-Compliant Settings ({len(result['non_compliant_settings'])}):")
        for i, issue in enumerate(result['non_compliant_settings'], 1):
            print(f"  {i}. {issue}")


def print_basic_summary(result):
    """Print basic summary information"""
    print("\nIAM Account Password Policy Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Policy Exists: {result['policy_exists']}")
    print(f"Is Compliant: {result['is_compliant']}")


def print_summary_output(result):
    """Print human-readable summary output"""
    print_basic_summary(result)
    
    if result['policy_exists']:
        print_policy_comparison(result)
    
    print_non_compliant_issues(result)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check IAM Account Password Policy compliance")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_password_policy(profile_name=args.profile)
    
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
