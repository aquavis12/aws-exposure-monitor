"""
Elasticsearch Scanner Module - Detects publicly accessible Elasticsearch domains
"""
import boto3
from botocore.exceptions import ClientError


def scan_elasticsearch_domains(region=None):
    """
    Scan Elasticsearch domains for public access and security issues
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting Elasticsearch domain scan...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
            print(f"Scanning region: {region}")
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
            print(f"Scanning {len(regions)} regions")
        
        region_count = 0
        total_domain_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            try:
                es_client = boto3.client('es', region_name=current_region)
                
                # List all Elasticsearch domains
                domains = es_client.list_domain_names().get('DomainNames', [])
                domain_count = len(domains)
                
                if domain_count > 0:
                    total_domain_count += domain_count
                    print(f"  Found {domain_count} Elasticsearch domains in {current_region}")
                    
                    for i, domain_info in enumerate(domains, 1):
                        domain_name = domain_info.get('DomainName')
                        
                        # Print progress every 5 domains or for the last one
                        if i % 5 == 0 or i == domain_count:
                            print(f"  Progress: {i}/{domain_count}")
                        
                        # Get domain configuration
                        try:
                            domain = es_client.describe_elasticsearch_domain(DomainName=domain_name)
                            domain_config = domain.get('DomainStatus', {})
                            
                            # Get endpoint information
                            endpoint = domain_config.get('Endpoint', 'Unknown')
                            vpc_options = domain_config.get('VPCOptions', {})
                            is_vpc = bool(vpc_options)
                            
                            # Check if domain is publicly accessible
                            access_policies = domain_config.get('AccessPolicies', '')
                            
                            # Check if domain has public access
                            if not is_vpc:
                                # Check if domain has a public endpoint
                                if endpoint and endpoint != 'Unknown':
                                    # Check if access policies allow public access
                                    if '"Principal": "*"' in access_policies or '"Principal":{"AWS":"*"}' in access_policies:
                                        findings.append({
                                            'ResourceType': 'Elasticsearch Domain',
                                            'ResourceId': domain_name,
                                            'ResourceName': domain_name,
                                            'Endpoint': endpoint,
                                            'Region': current_region,
                                            'Risk': 'HIGH',
                                            'Issue': 'Elasticsearch domain is publicly accessible',
                                            'Recommendation': 'Move domain to VPC or restrict access policies'
                                        })
                                        print(f"    [!] FINDING: Elasticsearch domain {domain_name} is publicly accessible - HIGH risk")
                            
                            # Check if encryption at rest is enabled
                            encryption_at_rest = domain_config.get('EncryptionAtRestOptions', {}).get('Enabled', False)
                            if not encryption_at_rest:
                                findings.append({
                                    'ResourceType': 'Elasticsearch Domain',
                                    'ResourceId': domain_name,
                                    'ResourceName': domain_name,
                                    'Endpoint': endpoint if not is_vpc else 'VPC Endpoint',
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'Elasticsearch domain does not have encryption at rest enabled',
                                    'Recommendation': 'Enable encryption at rest for the domain'
                                })
                                print(f"    [!] FINDING: Elasticsearch domain {domain_name} has no encryption at rest - MEDIUM risk")
                            
                            # Check if node-to-node encryption is enabled
                            node_to_node_encryption = domain_config.get('NodeToNodeEncryptionOptions', {}).get('Enabled', False)
                            if not node_to_node_encryption:
                                findings.append({
                                    'ResourceType': 'Elasticsearch Domain',
                                    'ResourceId': domain_name,
                                    'ResourceName': domain_name,
                                    'Endpoint': endpoint if not is_vpc else 'VPC Endpoint',
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'Elasticsearch domain does not have node-to-node encryption enabled',
                                    'Recommendation': 'Enable node-to-node encryption for the domain'
                                })
                                print(f"    [!] FINDING: Elasticsearch domain {domain_name} has no node-to-node encryption - MEDIUM risk")
                            
                            # Check if HTTPS is enforced
                            enforce_https = domain_config.get('DomainEndpointOptions', {}).get('EnforceHTTPS', False)
                            if not enforce_https:
                                findings.append({
                                    'ResourceType': 'Elasticsearch Domain',
                                    'ResourceId': domain_name,
                                    'ResourceName': domain_name,
                                    'Endpoint': endpoint if not is_vpc else 'VPC Endpoint',
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'Elasticsearch domain does not enforce HTTPS',
                                    'Recommendation': 'Enable HTTPS enforcement for the domain'
                                })
                                print(f"    [!] FINDING: Elasticsearch domain {domain_name} does not enforce HTTPS - MEDIUM risk")
                            
                            # Check TLS version
                            tls_security_policy = domain_config.get('DomainEndpointOptions', {}).get('TLSSecurityPolicy', '')
                            if tls_security_policy in ['Policy-Min-TLS-1-0-2019-07', '']:
                                findings.append({
                                    'ResourceType': 'Elasticsearch Domain',
                                    'ResourceId': domain_name,
                                    'ResourceName': domain_name,
                                    'Endpoint': endpoint if not is_vpc else 'VPC Endpoint',
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': f'Elasticsearch domain uses outdated TLS policy: {tls_security_policy or "default"}',
                                    'Recommendation': 'Update to at least Policy-Min-TLS-1-2-2019-07'
                                })
                                print(f"    [!] FINDING: Elasticsearch domain {domain_name} uses outdated TLS policy - MEDIUM risk")
                        
                        except ClientError as e:
                            print(f"    Error checking domain {domain_name}: {e}")
            
            except ClientError as e:
                if 'AccessDeniedException' in str(e) or 'UnrecognizedClientException' in str(e):
                    print(f"  Elasticsearch service not available or not accessible in {current_region}")
                else:
                    print(f"  Error scanning Elasticsearch domains in {current_region}: {e}")
        
        if total_domain_count == 0:
            print("No Elasticsearch domains found.")
        else:
            print(f"Elasticsearch domain scan complete. Scanned {total_domain_count} domains.")
    
    except Exception as e:
        print(f"Error scanning Elasticsearch domains: {e}")
    
    if findings:
        print(f"Found {len(findings)} Elasticsearch domain issues.")
    else:
        print("No Elasticsearch domain issues found.")
    
    return findings