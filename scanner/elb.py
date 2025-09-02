"""
Elastic Load Balancer Scanner Module - Detects publicly accessible ELBs with security issues
"""
import boto3
from botocore.exceptions import ClientError


def scan_load_balancers(region=None):
    """
    Scan Elastic Load Balancers for public access and security issues
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        region_count = 0
        total_elb_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                pass
                
            # Scan Classic Load Balancers
            try:
                elb_client = boto3.client('elb', region_name=current_region)
                classic_lbs = elb_client.describe_load_balancers().get('LoadBalancerDescriptions', [])
                classic_count = len(classic_lbs)
                
                if classic_count > 0:
                    total_elb_count += classic_count
                    print(f"  Found {classic_count} Classic Load Balancers in {current_region}")
                    
                    for i, lb in enumerate(classic_lbs, 1):
                        lb_name = lb.get('LoadBalancerName')
                        dns_name = lb.get('DNSName', 'Unknown')
                        scheme = lb.get('Scheme', 'Unknown')
                        
                        # Print progress every 5 LBs or for the last one
                        if i % 5 == 0 or i == classic_count:
                            print(f"  Progress: {i}/{classic_count} Classic LBs")
                        
                        # Check if load balancer is internet-facing
                        if scheme == 'internet-facing':
                            # Check for SSL/TLS issues
                            ssl_policies = []
                            for listener in lb.get('ListenerDescriptions', []):
                                listener_config = listener.get('Listener', {})
                                if listener_config.get('Protocol') in ['HTTPS', 'SSL']:
                                    policy_names = listener.get('PolicyNames', [])
                                    if policy_names:
                                        policies = elb_client.describe_load_balancer_policies(
                                            LoadBalancerName=lb_name,
                                            PolicyNames=policy_names
                                        )
                                        ssl_policies.extend(policies.get('PolicyDescriptions', []))
                            
                            # Check for weak SSL policies
                            has_weak_ssl = False
                            for policy in ssl_policies:
                                for attribute in policy.get('PolicyAttributeDescriptions', []):
                                    # Check for outdated protocols or ciphers
                                    if attribute.get('AttributeName') in ['Protocol-SSLv2', 'Protocol-SSLv3', 'Protocol-TLSv1']:
                                        if attribute.get('AttributeValue') == 'true':
                                            has_weak_ssl = True
                                            break
                            
                            if has_weak_ssl:
                                findings.append({
                                    'ResourceType': 'Classic Load Balancer',
                                    'ResourceId': lb_name,
                                    'ResourceName': lb_name,
                                    'DNSName': dns_name,
                                    'Scheme': scheme,
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': 'Internet-facing Classic Load Balancer uses outdated SSL/TLS protocols',
                                    'Recommendation': 'Update SSL policy to use only TLSv1.2 or later'
                                })
                            
                            # Check if access logs are enabled
                            if not lb.get('AccessLog', {}).get('Enabled', False):
                                findings.append({
                                    'ResourceType': 'Classic Load Balancer',
                                    'ResourceId': lb_name,
                                    'ResourceName': lb_name,
                                    'DNSName': dns_name,
                                    'Scheme': scheme,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'Internet-facing Classic Load Balancer does not have access logs enabled',
                                    'Recommendation': 'Enable access logs to monitor traffic'
                                })
            
            except ClientError as e:
                pass
            
            # Scan Application and Network Load Balancers
            try:
                elbv2_client = boto3.client('elbv2', region_name=current_region)
                v2_lbs = elbv2_client.describe_load_balancers().get('LoadBalancers', [])
                v2_count = len(v2_lbs)
                
                if v2_count > 0:
                    total_elb_count += v2_count
                    print(f"  Found {v2_count} Application/Network Load Balancers in {current_region}")
                    
                    for i, lb in enumerate(v2_lbs, 1):
                        lb_arn = lb.get('LoadBalancerArn')
                        lb_name = lb.get('LoadBalancerName')
                        dns_name = lb.get('DNSName', 'Unknown')
                        scheme = lb.get('Scheme', 'Unknown')
                        lb_type = lb.get('Type', 'Unknown')
                        
                        # Print progress every 5 LBs or for the last one
                        if i % 5 == 0 or i == v2_count:
                            print(f"  Progress: {i}/{v2_count} {lb_type} LBs")
                        
                        # Check for IPv6 support
                        ip_address_type = lb.get('IpAddressType', 'ipv4')
                        is_dualstack = 'dualstack' in ip_address_type.lower() or 'dualstack' in dns_name.lower()
                        
                        if is_dualstack and scheme == 'internet-facing':
                            findings.append({
                                'ResourceType': f'{lb_type} Load Balancer',
                                'ResourceId': lb_name,
                                'ResourceName': lb_name,
                                'DNSName': dns_name,
                                'Scheme': scheme,
                                'IpAddressType': ip_address_type,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': f'Internet-facing {lb_type} Load Balancer is configured for dual-stack (IPv4 and IPv6)',
                                'Recommendation': 'Ensure security groups and network ACLs properly restrict IPv6 traffic'
                            })
                        
                        # Check if load balancer is internet-facing
                        if scheme == 'internet-facing':
                            # Get listeners
                            try:
                                listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn).get('Listeners', [])
                                
                                # For Application Load Balancers
                                if lb_type == 'application':
                                    # Check for HTTP listeners (not redirecting to HTTPS)
                                    for listener in listeners:
                                        if listener.get('Protocol') == 'HTTP':
                                            # Check if this listener redirects to HTTPS
                                            redirects_to_https = False
                                            for action in listener.get('DefaultActions', []):
                                                if action.get('Type') == 'redirect' and action.get('RedirectConfig', {}).get('Protocol') == 'HTTPS':
                                                    redirects_to_https = True
                                                    break
                                            
                                            if not redirects_to_https:
                                                findings.append({
                                                    'ResourceType': 'Application Load Balancer',
                                                    'ResourceId': lb_name,
                                                    'ResourceName': lb_name,
                                                    'DNSName': dns_name,
                                                    'Scheme': scheme,
                                                    'Region': current_region,
                                                    'Risk': 'MEDIUM',
                                                    'Issue': 'Internet-facing ALB has HTTP listener without HTTPS redirect',
                                                    'Recommendation': 'Configure HTTP to HTTPS redirect for all listeners'
                                                })
                                    
                                    # Check if WAF is enabled
                                    try:
                                        wafv2_client = boto3.client('wafv2', region_name=current_region)
                                        web_acls = wafv2_client.list_web_acls(Scope='REGIONAL').get('WebACLs', [])
                                        
                                        # Check if any WAF is associated with this ALB
                                        has_waf = False
                                        for acl in web_acls:
                                            acl_arn = acl.get('ARN')
                                            resources = wafv2_client.list_resources_for_web_acl(
                                                WebACLArn=acl_arn,
                                                ResourceType='APPLICATION_LOAD_BALANCER'
                                            ).get('ResourceArns', [])
                                            
                                            if lb_arn in resources:
                                                has_waf = True
                                                break
                                        
                                        if not has_waf:
                                            findings.append({
                                                'ResourceType': 'Application Load Balancer',
                                                'ResourceId': lb_name,
                                                'ResourceName': lb_name,
                                                'DNSName': dns_name,
                                                'Scheme': scheme,
                                                'Region': current_region,
                                                'Risk': 'MEDIUM',
                                                'Issue': 'Internet-facing ALB does not have WAF enabled',
                                                'Recommendation': 'Enable AWS WAF to protect against common web exploits'
                                            })
                                    except ClientError:
                                        # WAF might not be available in this region
                                        pass
                                
                                # For Network Load Balancers
                                if lb_type == 'network':
                                    # Check for TCP listeners on sensitive ports
                                    sensitive_ports = [22, 3389, 1433, 3306, 5432, 27017, 6379]
                                    for listener in listeners:
                                        if listener.get('Protocol') == 'TCP':
                                            port = listener.get('Port')
                                            if port in sensitive_ports:
                                                findings.append({
                                                    'ResourceType': 'Network Load Balancer',
                                                    'ResourceId': lb_name,
                                                    'ResourceName': lb_name,
                                                    'DNSName': dns_name,
                                                    'Scheme': scheme,
                                                    'Region': current_region,
                                                    'Risk': 'HIGH',
                                                    'Issue': f'Internet-facing NLB exposes sensitive port {port}',
                                                    'Recommendation': 'Restrict access to this port or use a private NLB'
                                                })
                            
                            except ClientError as e:
                                pass
                            
                            # Check if access logs are enabled
                            try:
                                attrs = elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn).get('Attributes', [])
                                access_logs_enabled = False
                                
                                for attr in attrs:
                                    if attr.get('Key') == 'access_logs.s3.enabled' and attr.get('Value') == 'true':
                                        access_logs_enabled = True
                                        break
                                
                                if not access_logs_enabled:
                                    findings.append({
                                        'ResourceType': f'{lb_type.capitalize()} Load Balancer',
                                        'ResourceId': lb_name,
                                        'ResourceName': lb_name,
                                        'DNSName': dns_name,
                                        'Scheme': scheme,
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': f'Internet-facing {lb_type.upper()} does not have access logs enabled',
                                        'Recommendation': 'Enable access logs to monitor traffic'
                                    })
                            
                            except ClientError as e:
                                pass
            
            except ClientError as e:
                pass
    except Exception as e:
        pass
    
    return findings