"""
OpenSearch Scanner Module - Detects security issues with AWS OpenSearch
"""
import boto3
from botocore.exceptions import ClientError

def scan_opensearch(region=None):
    """
    Scan OpenSearch domains for security issues
    
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
            regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
        
        for current_region in regions:
            
            try:
                opensearch_client = boto3.client('opensearch', region_name=current_region)
                
                # Get all domains
                domains = opensearch_client.list_domain_names()['DomainNames']
                
                for domain_info in domains:
                    domain_name = domain_info['DomainName']
                    
                    try:
                        domain = opensearch_client.describe_domain(DomainName=domain_name)['DomainStatus']
                        
                        # Check public access
                        vpc_options = domain.get('VPCOptions', {})
                        if not vpc_options.get('VPCId'):
                            findings.append({
                                'ResourceType': 'OpenSearch Domain',
                                'ResourceId': domain_name,
                                'ResourceName': domain_name,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'OpenSearch domain is not in a VPC',
                                'Recommendation': 'Deploy OpenSearch domain within a VPC'
                            })
                        
                        # Check encryption at rest
                        encryption_at_rest = domain.get('EncryptionAtRestOptions', {})
                        if not encryption_at_rest.get('Enabled', False):
                            findings.append({
                                'ResourceType': 'OpenSearch Domain',
                                'ResourceId': domain_name,
                                'ResourceName': domain_name,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'OpenSearch domain encryption at rest is not enabled',
                                'Recommendation': 'Enable encryption at rest for OpenSearch domain'
                            })
                        
                        # Check node-to-node encryption
                        node_to_node = domain.get('NodeToNodeEncryptionOptions', {})
                        if not node_to_node.get('Enabled', False):
                            findings.append({
                                'ResourceType': 'OpenSearch Domain',
                                'ResourceId': domain_name,
                                'ResourceName': domain_name,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'OpenSearch domain node-to-node encryption is not enabled',
                                'Recommendation': 'Enable node-to-node encryption for OpenSearch domain'
                            })
                        
                        # Check domain endpoint options
                        domain_endpoint = domain.get('DomainEndpointOptions', {})
                        if not domain_endpoint.get('EnforceHTTPS', False):
                            findings.append({
                                'ResourceType': 'OpenSearch Domain',
                                'ResourceId': domain_name,
                                'ResourceName': domain_name,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'OpenSearch domain does not enforce HTTPS',
                                'Recommendation': 'Enable HTTPS enforcement for OpenSearch domain'
                            })
                    
                    except ClientError as e:
                        pass
            
            except ClientError as e:
                pass
    except Exception as e:
        pass
    
    return findings