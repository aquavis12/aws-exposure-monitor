"""
Elastic Load Balancer Scanner Module - Detects publicly accessible ELBs with security issues
"""
import boto3
from botocore.exceptions import ClientError


def scan_load_balancers():
    """
    Scan Elastic Load Balancers for public access and security issues
    Returns a list of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting Elastic Load Balancer scan...")
    
    try:
        # Get all regions
        ec2_client = boto3.client('ec2')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        print(f"Scanning {len(regions)} regions")
        
        region_count = 0
        total_elb_count = 0
        
        for region in regions:
            region_count += 1
            print(f"[{region_count}/{len(regions)}] Scanning region: {region}")
            
            # Scan Classic Load Balancers
            try:
                elb_client = boto3.client('elb', region_name=region)
                classic_lbs = elb_client.describe_load_balancers().get('LoadBalancerDescriptions', [])
                classic_count = len(classic_lbs)
                total_elb_count += classic_count
                
                if classic_count > 0:
                    print(f"  Scanning {classic_count} Classic Load Balancers in {region}")
                    
                    for lb in classic_lbs:
                        lb_name = lb.get('LoadBalancerName')
                        dns_name = lb.get('DNSName', 'Unknown')
                        scheme = lb.get('Scheme', 'Unknown')
                        
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
                                    'Region': region,
                                    'Risk': 'HIGH',
                                    'Issue': 'Internet-facing Classic Load Balancer uses outdated SSL/TLS protocols',
                                    'Recommendation': 'Update SSL policy to use only TLSv1.2 or later'
                                })
                                print(f"    [!] FINDING: Classic LB {lb_name} uses outdated SSL/TLS protocols - HIGH risk")
                            
                            # Check if access logs are enabled
                            if not lb.get('AccessLog', {}).get('Enabled', False):
                                findings.append({
                                    'ResourceType': 'Classic Load Balancer',
                                    'ResourceId': lb_name,
                                    'ResourceName': lb_name,
                                    'DNSName': dns_name,
                                    'Scheme': scheme,
                                    'Region': region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'Internet-facing Classic Load Balancer does not have access logs enabled',
                                    'Recommendation': 'Enable access logs to monitor traffic'
                                })
                                print(f"    [!] FINDING: Classic LB {lb_name} has no access logs enabled - MEDIUM risk")
            
            except ClientError as e:
                print(f"  Error scanning Classic Load Balancers in {region}: {e}")
            
            # Scan Application and Network Load Balancers
            try:
                elbv2_client = boto3.client('elbv2', region_name=region)
                v2_lbs = elbv2_client.describe_load_balancers().get('LoadBalancers', [])
                v2_count = len(v2_lbs)
                total_elb_count += v2_count
                
                if v2_count > 0:
                    print(f"  Scanning {v2_count} Application/Network Load Balancers in {region}")
                    
                    for lb in v2_lbs:
                        lb_arn = lb.get('LoadBalancerArn')
                        lb_name = lb.get('LoadBalancerName')
                        dns_name = lb.get('DNSName', 'Unknown')
                        scheme = lb.get('Scheme', 'Unknown')
                        lb_type = lb.get('Type', 'Unknown')
                        
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
                                                    'Region': region,
                                                    'Risk': 'MEDIUM',
                                                    'Issue': 'Internet-facing ALB has HTTP listener without HTTPS redirect',
                                                    'Recommendation': 'Configure HTTP to HTTPS redirect for all listeners'
                                                })
                                                print(f"    [!] FINDING: ALB {lb_name} has HTTP listener without HTTPS redirect - MEDIUM risk")
                                    
                                    # Check if WAF is enabled
                                    try:
                                        wafv2_client = boto3.client('wafv2', region_name=region)
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
                                                'Region': region,
                                                'Risk': 'MEDIUM',
                                                'Issue': 'Internet-facing ALB does not have WAF enabled',
                                                'Recommendation': 'Enable AWS WAF to protect against common web exploits'
                                            })
                                            print(f"    [!] FINDING: ALB {lb_name} has no WAF protection - MEDIUM risk")
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
                                                    'Region': region,
                                                    'Risk': 'HIGH',
                                                    'Issue': f'Internet-facing NLB exposes sensitive port {port}',
                                                    'Recommendation': 'Restrict access to this port or use a private NLB'
                                                })
                                                print(f"    [!] FINDING: NLB {lb_name} exposes sensitive port {port} - HIGH risk")
                            
                            except ClientError as e:
                                print(f"    Error checking listeners for {lb_name}: {e}")
                            
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
                                        'Region': region,
                                        'Risk': 'MEDIUM',
                                        'Issue': f'Internet-facing {lb_type.upper()} does not have access logs enabled',
                                        'Recommendation': 'Enable access logs to monitor traffic'
                                    })
                                    print(f"    [!] FINDING: {lb_type.upper()} {lb_name} has no access logs enabled - MEDIUM risk")
                            
                            except ClientError as e:
                                print(f"    Error checking attributes for {lb_name}: {e}")
            
            except ClientError as e:
                print(f"  Error scanning Application/Network Load Balancers in {region}: {e}")
        
        if total_elb_count == 0:
            print("No Elastic Load Balancers found.")
        else:
            print(f"Elastic Load Balancer scan complete. Scanned {total_elb_count} load balancers.")
    
    except Exception as e:
        print(f"Error scanning Elastic Load Balancers: {e}")
    
    if findings:
        print(f"Found {len(findings)} Elastic Load Balancer issues.")
    else:
        print("No Elastic Load Balancer issues found.")
    
    return findings