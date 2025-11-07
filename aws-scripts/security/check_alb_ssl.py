#!/usr/bin/env python3
"""
ALB SSL Security Policy Check Script

This script checks Application Load Balancer SSL security policies by examining:
- Current SSL policies attached to HTTPS listeners
- Compliance with recommended security policies

Recommended policy: ELBSecurityPolicy-TLS13-1-2-Res-2021-06

Returns structured data for dashboard compatibility.
"""

import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime

# Constants
RECOMMENDED_SSL_POLICY = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"


def get_resource_name(tags, resource_id):
    """Extract resource name from tags or use resource ID as fallback"""
    if tags:
        for tag in tags:
            if tag.get('Key', '').lower() == 'name':
                return tag.get('Value', resource_id)
    return resource_id


def get_alb_listeners(elbv2_client, alb_arn):
    """Get all listeners for a specific ALB"""
    try:
        response = elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)
        return response.get('Listeners', [])
    except ClientError as e:
        return {'error': f'Failed to get listeners: {e.response["Error"]["Code"]}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


def analyze_listener_ssl_policy(listener):
    """Analyze SSL policy compliance for a listener"""
    protocol = listener.get('Protocol', '')
    port = listener.get('Port', 0)
    ssl_policy = listener.get('SslPolicy', '')
    
    # Only check HTTPS listeners
    if protocol != 'HTTPS':
        return None
    
    is_compliant = ssl_policy == RECOMMENDED_SSL_POLICY
    
    return {
        'listenerArn': listener.get('ListenerArn', ''),
        'port': port,
        'protocol': protocol,
        'sslPolicy': ssl_policy,
        'isCompliant': is_compliant,
        'recommendedPolicy': RECOMMENDED_SSL_POLICY
    }


def get_alb_tags_and_name(elbv2_client, alb_arn, alb_name):
    """Get ALB tags and display name"""
    try:
        tags_response = elbv2_client.describe_tags(ResourceArns=[alb_arn])
        tags = tags_response.get('TagDescriptions', [{}])[0].get('Tags', [])
        display_name = get_resource_name(tags, alb_name)
        return display_name, tags
    except Exception:
        return alb_name, []


def create_alb_data(alb_arn, alb_name, display_name, alb_dns, alb_scheme, alb_state, region_name, listeners_result):
    """Create ALB data structure with SSL policy analysis"""
    if isinstance(listeners_result, dict) and 'error' in listeners_result:
        return {
            'albArn': alb_arn,
            'albName': alb_name,
            'displayName': display_name,
            'dnsName': alb_dns,
            'scheme': alb_scheme,
            'state': alb_state,
            'region': region_name,
            'httpsListeners': [],
            'hasHttpsListeners': False,
            'compliantListeners': 0,
            'totalHttpsListeners': 0,
            'isCompliant': False,
            'error': listeners_result['error']
        }
    
    # Analyze HTTPS listeners
    https_listeners = []
    compliant_count = 0
    
    for listener in listeners_result:
        ssl_analysis = analyze_listener_ssl_policy(listener)
        if ssl_analysis:  # Only HTTPS listeners
            https_listeners.append(ssl_analysis)
            if ssl_analysis['isCompliant']:
                compliant_count += 1
    
    total_https = len(https_listeners)
    has_https = total_https > 0
    is_compliant = has_https and compliant_count == total_https
    
    return {
        'albArn': alb_arn,
        'albName': alb_name,
        'displayName': display_name,
        'dnsName': alb_dns,
        'scheme': alb_scheme,
        'state': alb_state,
        'region': region_name,
        'httpsListeners': https_listeners,
        'hasHttpsListeners': has_https,
        'compliantListeners': compliant_count,
        'totalHttpsListeners': total_https,
        'isCompliant': is_compliant
    }


def check_alb_ssl_policies(session, region_name):
    """Check SSL policies for all ALBs in a region"""
    try:
        elbv2_client = session.client('elbv2', region_name=region_name)
        
        # Get all Application Load Balancers
        response = elbv2_client.describe_load_balancers()
        load_balancers = response.get('LoadBalancers', [])
        
        alb_results = []
        
        for lb in load_balancers:
            # Only check Application Load Balancers
            if lb.get('Type') != 'application':
                continue
                
            alb_arn = lb.get('LoadBalancerArn', '')
            alb_name = lb.get('LoadBalancerName', '')
            alb_dns = lb.get('DNSName', '')
            alb_scheme = lb.get('Scheme', '')
            alb_state = lb.get('State', {}).get('Code', '')
            
            # Get tags for display name
            display_name, _ = get_alb_tags_and_name(elbv2_client, alb_arn, alb_name)
            
            # Get listeners for this ALB
            listeners_result = get_alb_listeners(elbv2_client, alb_arn)
            
            # Create ALB data structure
            alb_data = create_alb_data(
                alb_arn, alb_name, display_name, alb_dns, alb_scheme, 
                alb_state, region_name, listeners_result
            )
            
            alb_results.append(alb_data)
        
        return alb_results
        
    except ClientError as e:
        return {'error': f'ELBv2 error: {e.response["Error"]["Code"]}'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


def check_region_alb_ssl(session, region_name):
    """Check ALB SSL policies in a specific region"""
    region_results = {
        'region': region_name,
        'albs': [],
        'errors': []
    }
    
    # Get ALB SSL policy information
    albs_result = check_alb_ssl_policies(session, region_name)
    if isinstance(albs_result, dict) and 'error' in albs_result:
        region_results['errors'].append(f"ALB SSL Policies: {albs_result['error']}")
    elif isinstance(albs_result, list):
        region_results['albs'] = albs_result
    
    return region_results


def get_all_regions(session):
    """Get all available AWS regions"""
    try:
        ec2_client = session.client('ec2', region_name='us-east-1')
        regions_response = ec2_client.describe_regions()
        return [region['RegionName'] for region in regions_response['Regions']]
    except Exception:
        # Fallback to common regions if API call fails
        return [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1',
            'ap-northeast-2', 'ap-south-1', 'ca-central-1',
            'sa-east-1'
        ]


def analyze_alb_ssl_stats(albs):
    """Analyze SSL policy statistics for ALBs"""
    return {
        'count': len(albs),
        'has_albs': len(albs) > 0,
        'compliant_count': len([alb for alb in albs if alb.get('isCompliant', False)]),
        'with_https_count': len([alb for alb in albs if alb.get('hasHttpsListeners', False)])
    }


def determine_overall_status(alb_stats):
    """Determine overall status based on ALB SSL policy compliance"""
    total_albs = alb_stats['count']
    compliant_albs = alb_stats['compliant_count']
    albs_with_https = alb_stats['with_https_count']
    
    if total_albs == 0:
        return {
            'status': 'Success',
            'message': 'No Application Load Balancers found in the checked regions.'
        }
    elif compliant_albs == albs_with_https and albs_with_https > 0:
        return {
            'status': 'Success',
            'message': f'All {compliant_albs} ALBs with HTTPS listeners are using recommended SSL security policies.'
        }
    elif compliant_albs > 0:
        non_compliant = albs_with_https - compliant_albs
        return {
            'status': 'Warning',
            'message': f'{compliant_albs} ALBs are compliant but {non_compliant} ALBs with HTTPS listeners need SSL policy updates to {RECOMMENDED_SSL_POLICY}.'
        }
    else:
        return {
            'status': 'Warning',
            'message': f'None of the {albs_with_https} ALBs with HTTPS listeners are using the recommended SSL policy {RECOMMENDED_SSL_POLICY}.'
        }


def analyze_alb_ssl_configuration(all_region_results):
    """Analyze ALB SSL configuration across all regions"""
    all_albs = []
    total_albs = 0
    regions_with_albs = 0
    
    # Collect all ALBs from all regions
    for region_result in all_region_results:
        albs = region_result.get('albs', [])
        total_albs += len(albs)
        all_albs.extend(albs)
        
        if albs:
            regions_with_albs += 1
    
    # Analyze statistics
    alb_stats = analyze_alb_ssl_stats(all_albs)
    
    # Determine overall status
    status_info = determine_overall_status(alb_stats)
    
    return {
        'status': status_info['status'],
        'message': status_info['message'],
        'analysis': {
            'total_albs': total_albs,
            'compliant_albs': alb_stats['compliant_count'],
            'albs_with_https': alb_stats['with_https_count'],
            'regions_with_albs': regions_with_albs,
            'has_albs': alb_stats['has_albs'],
            'recommended_policy': RECOMMENDED_SSL_POLICY
        }
    }


def create_error_result(status, message, error_type, error_message):
    """Create error result dictionary"""
    return {
        'status': status,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'regions_checked': '0',
        'total_albs': '0',
        'compliant_albs': '0',
        'albs_with_https': '0',
        'details': {
            'error_type': error_type,
            'error_message': error_message,
            'region_results': []
        }
    }


def process_regions(session, regions_to_check):
    """Process all regions and collect results"""
    all_region_results = []
    
    for region in regions_to_check:
        try:
            region_result = check_region_alb_ssl(session, region)
            all_region_results.append(region_result)
        except Exception as e:
            # Add error info for this region
            all_region_results.append({
                'region': region,
                'albs': [],
                'errors': [f'Region check failed: {str(e)}']
            })
    
    return all_region_results


def check_alb_ssl(profile_name=None, region_name=None):
    """
    Check ALB SSL security policies across all regions or specific region
    
    Args:
        profile_name (str): AWS profile name (optional)
        region_name (str): AWS region name (optional, if not provided checks all regions)
        
    Returns:
        dict: Structured result for dashboard compatibility
    """
    
    try:
        # Initialize session with profile
        if profile_name:
            session = boto3.Session(profile_name=profile_name)
        else:
            session = boto3.Session()
        
        # Determine which regions to check
        if region_name:
            regions_to_check = [region_name]
        else:
            regions_to_check = get_all_regions(session)
        
        # Check each region
        all_region_results = process_regions(session, regions_to_check)
        regions_checked = len(regions_to_check)
        
        # Analyze results
        analysis = analyze_alb_ssl_configuration(all_region_results)
        
        return {
            'status': analysis['status'],
            'message': analysis['message'],
            'timestamp': datetime.now().isoformat(),
            'regions_checked': str(regions_checked),
            'total_albs': str(analysis['analysis']['total_albs']),
            'compliant_albs': str(analysis['analysis']['compliant_albs']),
            'albs_with_https': str(analysis['analysis']['albs_with_https']),
            'details': {
                'region_results': all_region_results,
                'analysis': analysis['analysis'],
                'recommended_policy': RECOMMENDED_SSL_POLICY
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


def print_alb_details(alb, index):
    """Print detailed information for an ALB"""
    print(f"  {index}. {alb['displayName']} ({alb['albName']})")
    print(f"     State: {alb['state']}")
    print(f"     Scheme: {alb['scheme']}")
    print(f"     Region: {alb['region']}")
    print(f"     DNS Name: {alb['dnsName']}")
    print(f"     HTTPS Listeners: {alb['totalHttpsListeners']}")
    print(f"     Compliant Listeners: {alb['compliantListeners']}")
    print(f"     Overall Compliant: {alb['isCompliant']}")
    
    if alb.get('error'):
        print(f"     Error: {alb['error']}")
    elif alb['httpsListeners']:
        print("     HTTPS Listener Details:")
        for i, listener in enumerate(alb['httpsListeners'], 1):
            status = "✓ Compliant" if listener['isCompliant'] else "✗ Non-compliant"
            print(f"       {i}. Port {listener['port']}: {listener['sslPolicy']} ({status})")
    
    print()


def print_region_details(region_result):
    """Print details for a specific region"""
    region = region_result['region']
    albs = region_result.get('albs', [])
    errors = region_result.get('errors', [])
    
    print(f"\n  Region: {region}")
    print(f"    Total ALBs: {len(albs)}")
    print(f"    Compliant ALBs: {len([alb for alb in albs if alb.get('isCompliant', False)])}")
    print(f"    ALBs with HTTPS: {len([alb for alb in albs if alb.get('hasHttpsListeners', False)])}")
    
    if errors:
        print(f"    Errors: {', '.join(errors)}")
    
    if albs:
        print("\n    ALB Details:")
        for i, alb in enumerate(albs, 1):
            print_alb_details(alb, i)


def print_summary_output(result):
    """Print summary output for ALB SSL policy check"""
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Regions Checked: {result['regions_checked']}")
    print(f"Total ALBs: {result['total_albs']}")
    print(f"Compliant ALBs: {result['compliant_albs']}")
    print(f"ALBs with HTTPS: {result['albs_with_https']}")
    
    if result['details']['region_results']:
        print(f"\nRecommended SSL Policy: {result['details']['recommended_policy']}")
        
        print("\nRegion-by-Region Results:")
        for region_result in result['details']['region_results']:
            print_region_details(region_result)


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Check ALB SSL security policies')
    parser.add_argument('--profile', help='AWS profile name', default=None)
    parser.add_argument('--region', help='AWS region name', default=None)
    parser.add_argument('--output', choices=['json', 'summary'], default='json', 
                       help='Output format (json or summary)')
    
    args = parser.parse_args()
    
    # Execute the check
    result = check_alb_ssl(
        profile_name=args.profile,
        region_name=args.region
    )
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    else:
        print_summary_output(result)


if __name__ == "__main__":
    main()
