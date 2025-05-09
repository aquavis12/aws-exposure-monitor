"""
WAF Scanner Module - Detects security issues with AWS WAF configurations
"""
import boto3
from botocore.exceptions import ClientError


def scan_waf(region=None):
    """
    Scan AWS WAF for security issues like:
    - Missing rule groups
    - Permissive rules
    - Logging configuration
    - Web ACL associations
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting WAF scan...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
            print(f"Scanning region: {region}")
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
            print(f"Scanning {len(regions)} regions")
        
        # Also scan global WAF (WAFv2)
        regions.append('global')
        
        region_count = 0
        total_acl_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
            
            # For WAFv2
            try:
                if current_region == 'global':
                    wafv2_client = boto3.client('wafv2', region_name='us-east-1')
                    scope = 'CLOUDFRONT'
                else:
                    wafv2_client = boto3.client('wafv2', region_name=current_region)
                    scope = 'REGIONAL'
                
                # Get all Web ACLs
                web_acls = []
                paginator = wafv2_client.get_paginator('list_web_acls')
                
                for page in paginator.paginate(Scope=scope):
                    web_acls.extend(page.get('WebACLs', []))
                
                acl_count = len(web_acls)
                
                if acl_count > 0:
                    total_acl_count += acl_count
                    print(f"  Found {acl_count} WAFv2 Web ACLs in {current_region}")
                    
                    for i, acl in enumerate(web_acls, 1):
                        acl_name = acl.get('Name')
                        acl_id = acl.get('Id')
                        acl_arn = acl.get('ARN')
                        
                        # Print progress every 5 ACLs or for the last one
                        if i % 5 == 0 or i == acl_count:
                            print(f"  Progress: {i}/{acl_count}")
                        
                        # Get detailed ACL info
                        acl_detail = wafv2_client.get_web_acl(
                            Name=acl_name,
                            Id=acl_id,
                            Scope=scope
                        )
                        
                        # Check for logging configuration
                        try:
                            logging_config = wafv2_client.get_logging_configuration(
                                ResourceArn=acl_arn
                            )
                            has_logging = True
                        except ClientError:
                            has_logging = False
                        
                        if not has_logging:
                            findings.append({
                                'ResourceType': 'WAFv2 Web ACL',
                                'ResourceId': acl_id,
                                'ResourceName': acl_name,
                                'Region': current_region if current_region != 'global' else 'global (CloudFront)',
                                'Risk': 'MEDIUM',
                                'Issue': 'WAF Web ACL does not have logging enabled',
                                'Recommendation': 'Enable logging for WAF Web ACL to monitor and respond to attacks'
                            })
                            print(f"    [!] FINDING: WAF Web ACL {acl_name} has no logging enabled - MEDIUM risk")
                        
                        # Check for empty rule groups
                        rules = acl_detail.get('WebACL', {}).get('Rules', [])
                        if not rules:
                            findings.append({
                                'ResourceType': 'WAFv2 Web ACL',
                                'ResourceId': acl_id,
                                'ResourceName': acl_name,
                                'Region': current_region if current_region != 'global' else 'global (CloudFront)',
                                'Risk': 'HIGH',
                                'Issue': 'WAF Web ACL does not have any rules configured',
                                'Recommendation': 'Add rules to the Web ACL to protect against common web attacks'
                            })
                            print(f"    [!] FINDING: WAF Web ACL {acl_name} has no rules - HIGH risk")
                        
                        # Check for missing AWS managed rule groups
                        managed_rule_found = False
                        for rule in rules:
                            if rule.get('Statement', {}).get('ManagedRuleGroupStatement'):
                                managed_rule_found = True
                                break
                        
                        if not managed_rule_found:
                            findings.append({
                                'ResourceType': 'WAFv2 Web ACL',
                                'ResourceId': acl_id,
                                'ResourceName': acl_name,
                                'Region': current_region if current_region != 'global' else 'global (CloudFront)',
                                'Risk': 'MEDIUM',
                                'Issue': 'WAF Web ACL does not use any AWS managed rule groups',
                                'Recommendation': 'Add AWS managed rule groups like AWSManagedRulesCommonRuleSet for baseline protection'
                            })
                            print(f"    [!] FINDING: WAF Web ACL {acl_name} has no managed rule groups - MEDIUM risk")
                        
                        # Check for resource associations
                        try:
                            resources = wafv2_client.list_resources_for_web_acl(
                                WebACLArn=acl_arn,
                                ResourceType='APPLICATION_LOAD_BALANCER' if scope == 'REGIONAL' else 'CLOUDFRONT'
                            )
                            
                            if not resources.get('ResourceArns'):
                                findings.append({
                                    'ResourceType': 'WAFv2 Web ACL',
                                    'ResourceId': acl_id,
                                    'ResourceName': acl_name,
                                    'Region': current_region if current_region != 'global' else 'global (CloudFront)',
                                    'Risk': 'LOW',
                                    'Issue': 'WAF Web ACL is not associated with any resources',
                                    'Recommendation': 'Associate the Web ACL with resources like ALBs, CloudFront, or API Gateway'
                                })
                                print(f"    [!] FINDING: WAF Web ACL {acl_name} has no resource associations - LOW risk")
                        except ClientError:
                            pass
                        
                        # Check for default action
                        default_action = acl_detail.get('WebACL', {}).get('DefaultAction', {})
                        if 'Allow' in default_action:
                            findings.append({
                                'ResourceType': 'WAFv2 Web ACL',
                                'ResourceId': acl_id,
                                'ResourceName': acl_name,
                                'Region': current_region if current_region != 'global' else 'global (CloudFront)',
                                'Risk': 'MEDIUM',
                                'Issue': 'WAF Web ACL has a default action of Allow',
                                'Recommendation': 'Consider changing default action to Block for better security posture'
                            })
                            print(f"    [!] FINDING: WAF Web ACL {acl_name} has default action Allow - MEDIUM risk")
            
            except ClientError as e:
                print(f"  Error scanning WAFv2 in {current_region}: {e}")
            
            # For WAF Classic (only in regions that support it)
            if current_region not in ['global', 'eu-south-1', 'af-south-1', 'eu-south-2', 'ap-southeast-3', 'ap-southeast-4', 'eu-central-2', 'ap-south-2', 'me-central-1', 'me-south-1', 'il-central-1']:
                try:
                    waf_client = boto3.client('waf-regional', region_name=current_region)
                    
                    # Get all Web ACLs
                    classic_web_acls = waf_client.list_web_acls().get('WebACLs', [])
                    classic_acl_count = len(classic_web_acls)
                    
                    if classic_acl_count > 0:
                        total_acl_count += classic_acl_count
                        print(f"  Found {classic_acl_count} WAF Classic Web ACLs in {current_region}")
                        
                        for i, acl in enumerate(classic_web_acls, 1):
                            acl_name = acl.get('Name')
                            acl_id = acl.get('WebACLId')
                            
                            # Print progress every 5 ACLs or for the last one
                            if i % 5 == 0 or i == classic_acl_count:
                                print(f"  Progress: {i}/{classic_acl_count} (Classic)")
                            
                            # Get detailed ACL info
                            acl_detail = waf_client.get_web_acl(WebACLId=acl_id)
                            
                            # Check for empty rules
                            rules = acl_detail.get('WebACL', {}).get('Rules', [])
                            if not rules:
                                findings.append({
                                    'ResourceType': 'WAF Classic Web ACL',
                                    'ResourceId': acl_id,
                                    'ResourceName': acl_name,
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': 'WAF Classic Web ACL does not have any rules configured',
                                    'Recommendation': 'Add rules to the Web ACL or migrate to WAFv2'
                                })
                                print(f"    [!] FINDING: WAF Classic Web ACL {acl_name} has no rules - HIGH risk")
                            
                            # Check for default action
                            default_action = acl_detail.get('WebACL', {}).get('DefaultAction', {}).get('Type')
                            if default_action == 'ALLOW':
                                findings.append({
                                    'ResourceType': 'WAF Classic Web ACL',
                                    'ResourceId': acl_id,
                                    'ResourceName': acl_name,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'WAF Classic Web ACL has a default action of ALLOW',
                                    'Recommendation': 'Consider changing default action to BLOCK or migrate to WAFv2'
                                })
                                print(f"    [!] FINDING: WAF Classic Web ACL {acl_name} has default action ALLOW - MEDIUM risk")
                            
                            # Check for resource associations
                            resources = waf_client.list_resources_for_web_acl(WebACLId=acl_id)
                            
                            if not resources.get('ResourceArns'):
                                findings.append({
                                    'ResourceType': 'WAF Classic Web ACL',
                                    'ResourceId': acl_id,
                                    'ResourceName': acl_name,
                                    'Region': current_region,
                                    'Risk': 'LOW',
                                    'Issue': 'WAF Classic Web ACL is not associated with any resources',
                                    'Recommendation': 'Associate the Web ACL with resources or migrate to WAFv2'
                                })
                                print(f"    [!] FINDING: WAF Classic Web ACL {acl_name} has no resource associations - LOW risk")
                            
                            # Recommend migration to WAFv2
                            findings.append({
                                'ResourceType': 'WAF Classic Web ACL',
                                'ResourceId': acl_id,
                                'ResourceName': acl_name,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': 'Using WAF Classic instead of WAFv2',
                                'Recommendation': 'Migrate to WAFv2 for improved features and security capabilities'
                            })
                            print(f"    [!] FINDING: WAF Classic Web ACL {acl_name} should be migrated to WAFv2 - LOW risk")
                
                except ClientError as e:
                    print(f"  Error scanning WAF Classic in {current_region}: {e}")
        
        if total_acl_count == 0:
            print("No WAF Web ACLs found.")
        else:
            print(f"WAF scan complete. Scanned {total_acl_count} Web ACLs.")
    
    except Exception as e:
        print(f"Error scanning WAF: {e}")
    
    if findings:
        print(f"Found {len(findings)} WAF security issues.")
    else:
        print("No WAF security issues found.")
    
    return findings