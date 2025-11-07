#!/usr/bin/env python3
"""
AWS Well-Architected Tool - Security Pillar
Check S3 Bucket Public Access Configuration

This script checks if S3 buckets have public access enabled and analyzes
public access at bucket level only.

Public Access Checks:
- Bucket Public Access Block settings
- Bucket ACL public permissions
- Bucket Policy public statements
"""

import boto3
import json
import sys
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError


def get_s3_buckets(s3_client):
    """
    Get all S3 buckets
    
    Args:
        s3_client: Boto3 S3 client
        
    Returns:
        list: List of S3 buckets
    """
    try:
        response = s3_client.list_buckets()
        return response.get('Buckets', [])
    except ClientError as e:
        raise ClientError(e.response, e.operation_name) from e
    except Exception as e:
        raise RuntimeError(f"Failed to get S3 buckets: {str(e)}") from e


def get_bucket_location(s3_client, bucket_name):
    """
    Get the region of an S3 bucket
    
    Args:
        s3_client: Boto3 S3 client
        bucket_name: Name of the S3 bucket
        
    Returns:
        str: Bucket region
    """
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        location = response.get('LocationConstraint')
        # us-east-1 returns None as LocationConstraint
        return location if location else 'us-east-1'
    except ClientError:
        # If we can't get location, assume us-east-1
        return 'us-east-1'


def get_bucket_public_access_block(s3_client, bucket_name):
    """
    Get bucket public access block configuration
    
    Args:
        s3_client: Boto3 S3 client
        bucket_name: Name of the S3 bucket
        
    Returns:
        dict: Public access block configuration
    """
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response.get('PublicAccessBlockConfiguration', {})
        return {
            'block_public_acls': config.get('BlockPublicAcls', False),
            'ignore_public_acls': config.get('IgnorePublicAcls', False),
            'block_public_policy': config.get('BlockPublicPolicy', False),
            'restrict_public_buckets': config.get('RestrictPublicBuckets', False),
            'has_public_access_block': True
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchPublicAccessBlockConfiguration':
            return {
                'block_public_acls': False,
                'ignore_public_acls': False,
                'block_public_policy': False,
                'restrict_public_buckets': False,
                'has_public_access_block': False
            }
        else:
            return {
                'block_public_acls': None,
                'ignore_public_acls': None,
                'block_public_policy': None,
                'restrict_public_buckets': None,
                'has_public_access_block': None,
                'error': str(e)
            }


def is_public_grantee(grantee):
    """Check if grantee is public"""
    if grantee.get('Type') == 'Group':
        uri = grantee.get('URI', '')
        return 'AllUsers' in uri or 'AuthenticatedUsers' in uri
    return False


def process_public_grant(permission, public_perms):
    """Process a public grant and update permissions"""
    if permission == 'READ':
        public_perms['public_read'] = True
    elif permission == 'WRITE':
        public_perms['public_write'] = True
    elif permission == 'READ_ACP':
        public_perms['public_read_acp'] = True
    elif permission == 'WRITE_ACP':
        public_perms['public_write_acp'] = True
    elif permission == 'FULL_CONTROL':
        public_perms['public_read'] = True
        public_perms['public_write'] = True
        public_perms['public_read_acp'] = True
        public_perms['public_write_acp'] = True


def check_bucket_acl_public(s3_client, bucket_name):
    """
    Check if bucket ACL has public permissions
    
    Args:
        s3_client: Boto3 S3 client
        bucket_name: Name of the S3 bucket
        
    Returns:
        dict: Bucket ACL public access information
    """
    try:
        response = s3_client.get_bucket_acl(Bucket=bucket_name)
        grants = response.get('Grants', [])
        
        public_perms = {
            'public_read': False,
            'public_write': False,
            'public_read_acp': False,
            'public_write_acp': False
        }
        
        for grant in grants:
            grantee = grant.get('Grantee', {})
            permission = grant.get('Permission', '')
            
            if is_public_grantee(grantee):
                process_public_grant(permission, public_perms)
        
        return {
            'public_read': public_perms['public_read'],
            'public_write': public_perms['public_write'],
            'public_read_acp': public_perms['public_read_acp'],
            'public_write_acp': public_perms['public_write_acp'],
            'has_public_acl': any(public_perms.values()),
            'error': None
        }
        
    except ClientError as e:
        return {
            'public_read': None,
            'public_write': None,
            'public_read_acp': None,
            'public_write_acp': None,
            'has_public_acl': None,
            'error': str(e)
        }


def is_principal_public(principal):
    """Check if principal allows public access"""
    if principal == '*':
        return True
    if isinstance(principal, dict):
        aws_principal = principal.get('AWS', [])
        if aws_principal == '*':
            return True
        if isinstance(aws_principal, list) and '*' in aws_principal:
            return True
    return False


def extract_public_statement_info(statement):
    """Extract public statement information"""
    return {
        'effect': statement.get('Effect', ''),
        'principal': statement.get('Principal', {}),
        'action': statement.get('Action', []),
        'resource': statement.get('Resource', [])
    }


def check_bucket_policy_public(s3_client, bucket_name):
    """
    Check if bucket policy allows public access
    
    Args:
        s3_client: Boto3 S3 client
        bucket_name: Name of the S3 bucket
        
    Returns:
        dict: Bucket policy public access information
    """
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_str = response.get('Policy', '{}')
        policy = json.loads(policy_str)
        
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        public_statements = []
        
        for statement in statements:
            effect = statement.get('Effect', '')
            principal = statement.get('Principal', {})
            
            if is_principal_public(principal) and effect == 'Allow':
                public_statements.append(extract_public_statement_info(statement))
        
        return {
            'has_public_policy': len(public_statements) > 0,
            'public_statements_count': len(public_statements),
            'public_statements': public_statements,
            'error': None
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchBucketPolicy':
            return {
                'has_public_policy': False,
                'public_statements_count': 0,
                'public_statements': [],
                'error': None
            }
        else:
            return {
                'has_public_policy': None,
                'public_statements_count': 0,
                'public_statements': [],
                'error': str(e)
            }


def analyze_bucket_public_access(s3_client, bucket):
    """
    Analyze public access configuration for an S3 bucket
    
    Args:
        s3_client: Boto3 S3 client
        bucket: S3 bucket dict
        
    Returns:
        dict: Complete bucket public access analysis
    """
    bucket_name = bucket['Name']
    creation_date = bucket['CreationDate']
    
    # Get bucket location
    bucket_region = get_bucket_location(s3_client, bucket_name)
    
    # Get public access block configuration
    public_access_block = get_bucket_public_access_block(s3_client, bucket_name)
    
    # Check bucket ACL
    bucket_acl = check_bucket_acl_public(s3_client, bucket_name)
    
    # Check bucket policy
    bucket_policy = check_bucket_policy_public(s3_client, bucket_name)
    
    # Determine if bucket has any public access
    # Flag as public if Block all public access is turned off AND ACL allows public access
    # Also flag if bucket policy allows public access
    block_all_public_access = (
        public_access_block.get('block_public_acls', False) and
        public_access_block.get('ignore_public_acls', False) and
        public_access_block.get('block_public_policy', False) and
        public_access_block.get('restrict_public_buckets', False)
    )
    
    has_public_access = (
        (not block_all_public_access and bucket_acl.get('has_public_acl', False)) or
        bucket_policy.get('has_public_policy', False)
    )
    
    return {
        'bucket_name': bucket_name,
        'bucket_region': bucket_region,
        'creation_date': creation_date.isoformat() if creation_date else 'Unknown',
        'has_public_access': has_public_access,
        'block_all_public_access': block_all_public_access,
        'public_access_block': public_access_block,
        'bucket_acl': bucket_acl,
        'bucket_policy': bucket_policy
    }


def check_s3_public_access():
    """
    Check S3 bucket public access configuration
    
    Returns:
        dict: Complete check results
    """
    try:
        # S3 is a global service, but we use us-east-1 for consistency
        s3_client = boto3.client('s3', region_name='us-east-1')
        
        # Get all buckets
        buckets = get_s3_buckets(s3_client)
        
        # Analyze each bucket
        bucket_analyses = []
        public_buckets = []
        error_buckets = []
        
        for bucket in buckets:
            analysis = analyze_bucket_public_access(s3_client, bucket)
            bucket_analyses.append(analysis)
            
            # Check for errors in any component
            has_errors = (
                analysis['public_access_block'].get('error') or
                analysis['bucket_acl'].get('error') or
                analysis['bucket_policy'].get('error')
            )
            
            if has_errors:
                error_buckets.append(analysis)
            elif analysis['has_public_access']:
                public_buckets.append(analysis)
        
        return {
            'total_buckets': len(buckets),
            'private_buckets': len([b for b in bucket_analyses if not b['has_public_access'] and not any([
                b['public_access_block'].get('error'),
                b['bucket_acl'].get('error'),
                b['bucket_policy'].get('error')
            ])]),
            'public_buckets': len(public_buckets),
            'error_buckets': len(error_buckets),
            'buckets': bucket_analyses,
            'public_items': public_buckets,
            'error_items': error_buckets,
            'error': None
        }
        
    except ClientError as e:
        error_msg = f"AWS API error: {str(e)}"
        return {
            'total_buckets': 0,
            'private_buckets': 0,
            'public_buckets': 0,
            'error_buckets': 0,
            'buckets': [],
            'public_items': [],
            'error_items': [],
            'error': error_msg
        }
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        return {
            'total_buckets': 0,
            'private_buckets': 0,
            'public_buckets': 0,
            'error_buckets': 0,
            'buckets': [],
            'public_items': [],
            'error_items': [],
            'error': error_msg
        }


def determine_public_access_status(stats):
    """Determine overall public access status and message"""
    total_buckets = stats['total_buckets']
    public_buckets = stats['public_buckets']
    error_buckets = stats['error_buckets']
    
    if total_buckets == 0:
        status = 'Success'
        message = 'No S3 buckets found in the account.'
    elif public_buckets == 0 and error_buckets == 0:
        status = 'Success'
        message = f'All {total_buckets} S3 buckets are private with no public access.'
    elif public_buckets > 0 and error_buckets == 0:
        status = 'Warning'
        message = f'Found {public_buckets} S3 buckets with public access out of {total_buckets} total buckets.'
    elif public_buckets == 0 and error_buckets > 0:
        status = 'Warning'
        message = f'Could not determine public access status for {error_buckets} S3 buckets out of {total_buckets} total buckets.'
    else:
        status = 'Warning'
        message = f'Found {public_buckets} public and {error_buckets} error S3 buckets out of {total_buckets} total buckets.'
    
    return status, message


def check_s3_buckets_public_access(profile_name=None):
    """
    Main function to check S3 bucket public access configuration
    
    Args:
        profile_name: AWS profile name (optional)
        
    Returns:
        dict: Complete check results in JSON format
    """
    timestamp = datetime.now(timezone.utc).isoformat() + 'Z'
    
    try:
        # Create session and S3 client
        session = boto3.Session(profile_name=profile_name)
        
        # Override the default client creation for this specific check
        original_client = boto3.client
        boto3.client = lambda service, **kwargs: session.client(service, **kwargs)
        
        try:
            # Perform the public access check
            result = check_s3_public_access()
        finally:
            # Restore original client function
            boto3.client = original_client
        
        # Determine overall status
        stats = {
            'total_buckets': result['total_buckets'],
            'private_buckets': result['private_buckets'],
            'public_buckets': result['public_buckets'],
            'error_buckets': result['error_buckets']
        }
        
        status, message = determine_public_access_status(stats)
        
        # Build final result
        final_result = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'check_type': 's3_public_access',
            'total_buckets': result['total_buckets'],
            'private_buckets': result['private_buckets'],
            'public_buckets': result['public_buckets'],
            'error_buckets': result['error_buckets'],
            'buckets': result['buckets'],
            'public_items': result['public_items']
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
            'check_type': 's3_public_access',
            'total_buckets': 0,
            'private_buckets': 0,
            'public_buckets': 0,
            'error_buckets': 0,
            'buckets': [],
            'public_items': []
        }
    except Exception as e:
        return {
            'timestamp': timestamp,
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'check_type': 's3_public_access',
            'total_buckets': 0,
            'private_buckets': 0,
            'public_buckets': 0,
            'error_buckets': 0,
            'buckets': [],
            'public_items': []
        }


def print_public_access_block_details(pab):
    """Print public access block details"""
    if pab.get('has_public_access_block'):
        print("   Public Access Block:")
        print(f"     Block Public ACLs: {pab.get('block_public_acls', 'N/A')}")
        print(f"     Ignore Public ACLs: {pab.get('ignore_public_acls', 'N/A')}")
        print(f"     Block Public Policy: {pab.get('block_public_policy', 'N/A')}")
        print(f"     Restrict Public Buckets: {pab.get('restrict_public_buckets', 'N/A')}")
    else:
        print("   Public Access Block: Not configured")


def print_bucket_acl_details(acl):
    """Print bucket ACL details"""
    if acl.get('has_public_acl'):
        print("   Bucket ACL Public Permissions:")
        if acl.get('public_read'):
            print("     Public Read: Yes")
        if acl.get('public_write'):
            print("     Public Write: Yes")


def print_bucket_policy_details(policy):
    """Print bucket policy details"""
    if policy.get('has_public_policy'):
        print(f"   Bucket Policy: {policy.get('public_statements_count', 0)} public statements")


def collect_bucket_errors(bucket):
    """Collect all errors from bucket analysis"""
    errors = []
    pab = bucket['public_access_block']
    acl = bucket['bucket_acl']
    policy = bucket['bucket_policy']
    
    if pab.get('error'):
        errors.append(f"Public Access Block: {pab['error']}")
    if acl.get('error'):
        errors.append(f"Bucket ACL: {acl['error']}")
    if policy.get('error'):
        errors.append(f"Bucket Policy: {policy['error']}")
    
    return errors


def print_bucket_details(bucket, index):
    """Print detailed information about an S3 bucket"""
    print(f"\n{index}. S3 Bucket Details:")
    print(f"   Bucket Name: {bucket['bucket_name']}")
    print(f"   Region: {bucket['bucket_region']}")
    print(f"   Created: {bucket['creation_date']}")
    print(f"   Has Public Access: {'Yes' if bucket['has_public_access'] else 'No'}")
    print(f"   Block All Public Access: {'Yes' if bucket.get('block_all_public_access', False) else 'No'}")
    
    # Print component details
    print_public_access_block_details(bucket['public_access_block'])
    print_bucket_acl_details(bucket['bucket_acl'])
    print_bucket_policy_details(bucket['bucket_policy'])
    
    # Print errors if any
    errors = collect_bucket_errors(bucket)
    if errors:
        print("   Errors:")
        for error in errors:
            print(f"     {error}")


def print_basic_summary(result):
    """Print basic summary information"""
    print("\nS3 Public Access Check")
    print("=" * 50)
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Buckets: {result['total_buckets']}")
    print(f"Private Buckets: {result['private_buckets']}")
    print(f"Public Buckets: {result['public_buckets']}")
    print(f"Error Buckets: {result['error_buckets']}")


def print_public_buckets(buckets):
    """Print details of S3 buckets with public access"""
    if buckets:
        print(f"\nS3 Buckets with Public Access ({len(buckets)}):")
        for i, bucket in enumerate(buckets, 1):
            print_bucket_details(bucket, i)


def print_error_buckets(buckets):
    """Print details of S3 buckets with errors"""
    if buckets:
        print(f"\nS3 Buckets with Errors ({len(buckets)}):")
        for i, bucket in enumerate(buckets, 1):
            print_bucket_details(bucket, i)


def print_summary_output(result):
    """Print human-readable summary output"""
    print_basic_summary(result)
    
    public_buckets = result.get('public_items', [])
    print_public_buckets(public_buckets)
    
    error_buckets = result.get('error_items', [])
    print_error_buckets(error_buckets)


def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check S3 bucket public access configuration")
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--output', choices=['json', 'summary'], default='json',
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_s3_buckets_public_access(profile_name=args.profile)
    
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
