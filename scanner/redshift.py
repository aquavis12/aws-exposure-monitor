"""
Redshift Scanner Module - Detects security issues with AWS Redshift
"""
import boto3
from botocore.exceptions import ClientError

def scan_redshift(region=None):
    """
    Scan Redshift clusters for security issues
    
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
                redshift_client = boto3.client('redshift', region_name=current_region)
                
                # Get all clusters
                clusters = redshift_client.describe_clusters()['Clusters']
                
                for cluster in clusters:
                    cluster_id = cluster['ClusterIdentifier']
                    
                    # Check public accessibility
                    if cluster.get('PubliclyAccessible', False):
                        findings.append({
                            'ResourceType': 'Redshift Cluster',
                            'ResourceId': cluster_id,
                            'ResourceName': cluster_id,
                            'Region': current_region,
                            'Risk': 'HIGH',
                            'Issue': 'Redshift cluster is publicly accessible',
                            'Recommendation': 'Disable public accessibility for Redshift cluster'
                        })
                    
                    # Check encryption
                    if not cluster.get('Encrypted', False):
                        findings.append({
                            'ResourceType': 'Redshift Cluster',
                            'ResourceId': cluster_id,
                            'ResourceName': cluster_id,
                            'Region': current_region,
                            'Risk': 'HIGH',
                            'Issue': 'Redshift cluster is not encrypted',
                            'Recommendation': 'Enable encryption for Redshift cluster'
                        })
                    
                    # Check logging
                    try:
                        logging = redshift_client.describe_logging_status(ClusterIdentifier=cluster_id)
                        if not logging.get('LoggingEnabled', False):
                            findings.append({
                                'ResourceType': 'Redshift Cluster',
                                'ResourceId': cluster_id,
                                'ResourceName': cluster_id,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'Redshift cluster logging is not enabled',
                                'Recommendation': 'Enable audit logging for Redshift cluster'
                            })
                    except ClientError:
                        pass
            
            except ClientError as e:
                pass
    except Exception as e:
        pass
    
    return findings