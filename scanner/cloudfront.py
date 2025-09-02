"""
CloudFront Scanner Module - Detects publicly accessible CloudFront distributions
"""
import boto3
from botocore.exceptions import ClientError


def scan_cloudfront_distributions(region=None):
    """
    Scan CloudFront distributions for public access settings
    
    Args:
        region (str, optional): AWS region to scan. CloudFront is global, so this parameter is ignored.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    # Note: CloudFront is a global service, region parameter is ignored
    try:
        # CloudFront is a global service, but we'll use us-east-1 as the region
        cloudfront_client = boto3.client('cloudfront')
        
        # Get all distributions
        paginator = cloudfront_client.get_paginator('list_distributions')
        distribution_count = 0
        
        for page in paginator.paginate():
            if 'Items' in page.get('DistributionList', {}):
                distributions = page['DistributionList']['Items']
                distribution_count += len(distributions)
                
                if distributions:
                    for i, distribution in enumerate(distributions, 1):
                        dist_id = distribution.get('Id')
                        domain_name = distribution.get('DomainName')
                        origin_domains = [origin.get('DomainName', 'Unknown') for origin in distribution.get('Origins', {}).get('Items', [])]
                        enabled = distribution.get('Enabled', False)
                        
                        # Check if distribution is enabled
                        if not enabled:
                            continue
                        
                        # Check if distribution has viewer restrictions
                        if not distribution.get('Restrictions', {}).get('GeoRestriction', {}).get('Quantity', 0) > 0:
                            # No geo restrictions
                            
                            # Check if distribution has WAF protection
                            web_acl_id = distribution.get('WebACLId', '')
                            if not web_acl_id:
                                # No WAF protection
                                
                                # Check if distribution has custom error responses
                                has_custom_error = distribution.get('CustomErrorResponses', {}).get('Quantity', 0) > 0
                                
                                # Check if distribution has default root object
                                default_root_object = distribution.get('DefaultRootObject', '')
                                
                                # If no WAF, no geo restrictions, and no default root object, it might be misconfigured
                                if not default_root_object and not has_custom_error:
                                    findings.append({
                                        'ResourceType': 'CloudFront Distribution',
                                        'ResourceId': dist_id,
                                        'ResourceName': domain_name,
                                        'Origins': origin_domains,
                                        'Region': 'global',
                                        'Risk': 'MEDIUM',
                                        'Issue': 'CloudFront distribution is publicly accessible without WAF, geo restrictions, or default root object',
                                        'Recommendation': 'Consider adding WAF protection, geo restrictions, or setting a default root object'
                                    })
                                
                                # Check if S3 origin is configured securely
                                for origin in distribution.get('Origins', {}).get('Items', []):
                                    origin_domain = origin.get('DomainName', '')
                                    if 's3' in origin_domain.lower() and '.s3.amazonaws.com' in origin_domain.lower():
                                        # Check if OAI/OAC is configured
                                        has_oai = origin.get('S3OriginConfig', {}).get('OriginAccessIdentity', '') != ''
                                        
                                        if not has_oai:
                                            findings.append({
                                                'ResourceType': 'CloudFront Distribution',
                                                'ResourceId': dist_id,
                                                'ResourceName': domain_name,
                                                'Origins': origin_domains,
                                                'Region': 'global',
                                                'Risk': 'HIGH',
                                                'Issue': f'CloudFront distribution with S3 origin ({origin_domain}) does not use Origin Access Identity',
                                                'Recommendation': 'Configure Origin Access Identity (OAI) or Origin Access Control (OAC) for S3 origins'
                                            })
    except Exception as e:
        pass
    
    return findings