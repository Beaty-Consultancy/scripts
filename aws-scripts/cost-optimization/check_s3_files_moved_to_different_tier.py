#!/usr/bin/env python3
"""
AWS S3 Storage Tier Optimization Check Script

This script analyzes S3 buckets and objects to identify cost optimization opportunities
by suggesting appropriate storage classes based on access patterns and object age.

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timedelta

# Constants
STANDARD_TIER = 'STANDARD'
IA_TIER = 'STANDARD_IA'
GLACIER_TIER = 'GLACIER'
GLACIER_IR_TIER = 'GLACIER_IR'
DEEP_ARCHIVE_TIER = 'DEEP_ARCHIVE'

# Age thresholds for tier recommendations (in days)
IA_THRESHOLD_DAYS = 30
GLACIER_THRESHOLD_DAYS = 90
DEEP_ARCHIVE_THRESHOLD_DAYS = 180


def analyze_bucket_purpose(bucket_name):
    """Analyze bucket name to determine its likely purpose"""
    bucket_lower = bucket_name.lower()
    
    if any(keyword in bucket_lower for keyword in ['log', 'logs', 'logging']):
        return 'logs'
    elif any(keyword in bucket_lower for keyword in ['backup', 'backups', 'archive']):
        return 'backups'
    elif any(keyword in bucket_lower for keyword in ['static', 'assets', 'cdn', 'media']):
        return 'static-assets'
    elif any(keyword in bucket_lower for keyword in ['temp', 'tmp', 'temporary']):
        return 'temporary'
    else:
        return 'general'


def get_tier_for_logs(object_age_days):
    """Get recommended tier for log files based on age"""
    if object_age_days > DEEP_ARCHIVE_THRESHOLD_DAYS:
        return DEEP_ARCHIVE_TIER
    elif object_age_days > GLACIER_THRESHOLD_DAYS:
        return GLACIER_TIER
    elif object_age_days > IA_THRESHOLD_DAYS:
        return IA_TIER
    return None


def get_tier_for_backups(object_age_days):
    """Get recommended tier for backup files based on age"""
    if object_age_days > GLACIER_THRESHOLD_DAYS:
        return DEEP_ARCHIVE_TIER
    elif object_age_days > IA_THRESHOLD_DAYS:
        return GLACIER_TIER
    return None


def get_tier_for_static_assets(object_age_days):
    """Get recommended tier for static assets based on age"""
    if object_age_days > IA_THRESHOLD_DAYS:
        return IA_TIER
    return None


def get_tier_for_general(object_age_days):
    """Get recommended tier for general purpose files based on age"""
    if object_age_days > DEEP_ARCHIVE_THRESHOLD_DAYS:
        return GLACIER_TIER
    elif object_age_days > GLACIER_THRESHOLD_DAYS:
        return IA_TIER
    return None


def get_recommended_tier(object_age_days, bucket_purpose, current_tier):
    """Get recommended storage tier based on object age and bucket purpose"""
    if current_tier != STANDARD_TIER:
        return None  # Already optimized or in a specialized tier
    
    tier_functions = {
        'logs': get_tier_for_logs,
        'backups': get_tier_for_backups,
        'static-assets': get_tier_for_static_assets,
        'general': get_tier_for_general,
        'temporary': get_tier_for_general
    }
    
    tier_function = tier_functions.get(bucket_purpose, get_tier_for_general)
    return tier_function(object_age_days)


def should_exclude_from_optimization(object_key):
    """Check if an object should be excluded from storage tier optimization"""
    object_key_lower = object_key.lower()
    
    # Terraform state files - need frequent access
    if 'terraform.tfstate' in object_key_lower or object_key_lower.endswith('.tfstate'):
        return True
    
    # Add other exclusions here if needed
    # if 'some-other-pattern' in object_key_lower:
    #     return True
    
    return False


def analyze_bucket_objects(s3_client, bucket_name, bucket_purpose, max_objects=100):
    """Analyze objects in a bucket for storage tier recommendations"""
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=max_objects)
        objects = response.get('Contents', [])
        
        recommendations = []
        total_size = 0
        current_date = datetime.now()
        
        for obj in objects:
            object_key = obj['Key']
            
            # Skip objects that should be excluded from optimization
            if should_exclude_from_optimization(object_key):
                continue
                
            last_modified = obj['LastModified'].replace(tzinfo=None)
            age_days = (current_date - last_modified).days
            current_tier = obj.get('StorageClass', STANDARD_TIER)
            size_bytes = obj['Size']
            
            recommended_tier = get_recommended_tier(age_days, bucket_purpose, current_tier)
            
            if recommended_tier:
                recommendations.append({
                    'key': object_key,
                    'current_tier': current_tier,
                    'recommended_tier': recommended_tier,
                    'age_days': age_days,
                    'size_bytes': size_bytes,
                    'size_mb': round(size_bytes / (1024 * 1024), 2)
                })
                total_size += size_bytes
        
        return recommendations, total_size, len(objects), None
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            return [], 0, 0, f"Access denied when analyzing objects in bucket: {bucket_name}"
        else:
            return [], 0, 0, f"Error analyzing objects in bucket {bucket_name}: {e.response['Error']['Message']}"


def check_s3_storage_optimization(profile_name=None, max_buckets=50, max_objects_per_bucket=100):
    """
    Check S3 storage tier optimization opportunities
    
    Args:
        profile_name (str): AWS profile name (optional)
        max_buckets (int): Maximum number of buckets to analyze
        max_objects_per_bucket (int): Maximum objects to analyze per bucket
        
    Returns:
        dict: Structured result for dashboard compatibility
    """
    
    try:
        # Initialize session with profile
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
        else:
            session = boto3.Session()
        
        # Initialize S3 client
        s3_client = session.client('s3')
        
        # Get all buckets
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])[:max_buckets]
        
        bucket_recommendations = []
        total_potential_savings_objects = 0
        total_analyzed_size = 0
        warnings = []
        
        # Analyze each bucket
        for bucket in buckets:
            bucket_name = bucket['Name']
            bucket_purpose = analyze_bucket_purpose(bucket_name)
            
            recommendations, bucket_size, object_count, warning = analyze_bucket_objects(
                s3_client, bucket_name, bucket_purpose, max_objects_per_bucket
            )
            
            if warning:
                warnings.append(warning)
                continue
            
            total_analyzed_size += bucket_size
            
            if recommendations:
                bucket_recommendations.append({
                    'bucket': bucket_name,
                    'purpose': bucket_purpose,
                    'total_objects_analyzed': object_count,
                    'objects_with_recommendations': len(recommendations),
                    'total_size_mb': round(bucket_size / (1024 * 1024), 2),
                    'recommendations': recommendations[:10]  # Limit to first 10 for readability
                })
                total_potential_savings_objects += len(recommendations)
        
        # Generate summary
        total_buckets_analyzed = len(buckets)
        buckets_with_recommendations = len(bucket_recommendations)
        
        # Add informational warnings
        if total_potential_savings_objects > 0:
            warnings.append(f"{total_potential_savings_objects} object(s) found that could benefit from storage tier optimization")
        
        if max_buckets < len(response.get('Buckets', [])):
            warnings.append(f"Analysis limited to {max_buckets} buckets out of {len(response.get('Buckets', []))} total")
        
        return {
            'status': 'Success',
            'message': f'{total_buckets_analyzed} bucket(s) analyzed. {buckets_with_recommendations} bucket(s) have optimization opportunities.',
            'timestamp': datetime.now().isoformat(),
            'total_buckets_analyzed': str(total_buckets_analyzed),
            'details': {
                'buckets_with_recommendations': buckets_with_recommendations,
                'total_objects_with_recommendations': total_potential_savings_objects,
                'total_analyzed_size_mb': round(total_analyzed_size / (1024 * 1024), 2),
                'bucket_recommendations': bucket_recommendations,
                'optimization_thresholds': {
                    'infrequent_access_days': IA_THRESHOLD_DAYS,
                    'glacier_days': GLACIER_THRESHOLD_DAYS,
                    'deep_archive_days': DEEP_ARCHIVE_THRESHOLD_DAYS
                },
                'warnings': warnings
            }
        }
        
    except NoCredentialsError:
        return {
            'status': 'Error',
            'message': 'AWS credentials not found. Please configure your credentials.',
            'timestamp': datetime.now().isoformat(),
            'total_buckets_analyzed': '0',
            'details': {
                'error_type': 'NoCredentialsError',
                'error_message': 'AWS credentials not found',
                'buckets_with_recommendations': 0,
                'total_objects_with_recommendations': 0,
                'bucket_recommendations': [],
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
            'total_buckets_analyzed': '0',
            'details': {
                'error_type': error_code,
                'error_message': error_message,
                'buckets_with_recommendations': 0,
                'total_objects_with_recommendations': 0,
                'bucket_recommendations': [],
                'warnings': []
            }
        }
    
    except Exception as e:
        return {
            'status': 'Error',
            'message': f'Unexpected error: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'total_buckets_analyzed': '0',
            'details': {
                'error_type': 'UnexpectedError',
                'error_message': str(e),
                'buckets_with_recommendations': 0,
                'total_objects_with_recommendations': 0,
                'bucket_recommendations': [],
                'warnings': []
            }
        }


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check AWS S3 storage tier optimization opportunities')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--max-buckets', type=int, default=50,
                       help='Maximum number of buckets to analyze (default: 50)')
    parser.add_argument('--max-objects', type=int, default=100,
                       help='Maximum objects to analyze per bucket (default: 100)')
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_s3_storage_optimization(
        profile_name=args.profile,
        max_buckets=args.max_buckets,
        max_objects_per_bucket=args.max_objects
    )
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        # Summary output
        print(f"Status: {result['status']}")
        print(f"Message: {result['message']}")
        print(f"Total Buckets Analyzed: {result['total_buckets_analyzed']}")
        print(f"Buckets with Recommendations: {result['details']['buckets_with_recommendations']}")
        print(f"Objects with Recommendations: {result['details']['total_objects_with_recommendations']}")
        print(f"Total Analyzed Size: {result['details']['total_analyzed_size_mb']} MB")
        
        if result['details']['bucket_recommendations']:
            print("\nBuckets with Storage Optimization Opportunities:")
            for i, bucket in enumerate(result['details']['bucket_recommendations'], 1):
                print(f"  {i}. {bucket['bucket']} ({bucket['purpose']})")
                print(f"     Objects needing optimization: {bucket['objects_with_recommendations']}")
                print(f"     Total size: {bucket['total_size_mb']} MB")
                print()
        
        if result['details']['warnings']:
            print("Warnings:")
            for warning in result['details']['warnings']:
                print(f"  - {warning}")


if __name__ == "__main__":
    main()
