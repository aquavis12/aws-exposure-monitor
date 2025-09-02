"""
ElastiCache Scanner Module - Detects security issues with AWS ElastiCache
"""
import boto3
from botocore.exceptions import ClientError

def scan_elasticache(region=None):
    """
    Scan ElastiCache clusters for security issues
    
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
                elasticache_client = boto3.client('elasticache', region_name=current_region)
                
                # Get Redis clusters
                redis_clusters = elasticache_client.describe_replication_groups()['ReplicationGroups']
                
                for cluster in redis_clusters:
                    cluster_id = cluster['ReplicationGroupId']
                    
                    # Check encryption at rest
                    if not cluster.get('AtRestEncryptionEnabled', False):
                        findings.append({
                            'ResourceType': 'ElastiCache Redis',
                            'ResourceId': cluster_id,
                            'ResourceName': cluster_id,
                            'Region': current_region,
                            'Risk': 'HIGH',
                            'Issue': 'ElastiCache Redis cluster encryption at rest is not enabled',
                            'Recommendation': 'Enable encryption at rest for ElastiCache Redis cluster'
                        })
                    
                    # Check encryption in transit
                    if not cluster.get('TransitEncryptionEnabled', False):
                        findings.append({
                            'ResourceType': 'ElastiCache Redis',
                            'ResourceId': cluster_id,
                            'ResourceName': cluster_id,
                            'Region': current_region,
                            'Risk': 'HIGH',
                            'Issue': 'ElastiCache Redis cluster encryption in transit is not enabled',
                            'Recommendation': 'Enable encryption in transit for ElastiCache Redis cluster'
                        })
                    
                    # Check auth token
                    if not cluster.get('AuthTokenEnabled', False):
                        findings.append({
                            'ResourceType': 'ElastiCache Redis',
                            'ResourceId': cluster_id,
                            'ResourceName': cluster_id,
                            'Region': current_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'ElastiCache Redis cluster does not have auth token enabled',
                            'Recommendation': 'Enable auth token for ElastiCache Redis cluster'
                        })
                
                # Get Memcached clusters
                memcached_clusters = elasticache_client.describe_cache_clusters()['CacheClusters']
                
                for cluster in memcached_clusters:
                    if cluster.get('Engine') == 'memcached':
                        cluster_id = cluster['CacheClusterId']
                        
                        # Memcached doesn't support encryption, but check for public access
                        subnet_group = cluster.get('CacheSubnetGroupName')
                        if subnet_group:
                            try:
                                subnet_groups = elasticache_client.describe_cache_subnet_groups(
                                    CacheSubnetGroupName=subnet_group
                                )
                                for sg in subnet_groups['CacheSubnetGroups']:
                                    for subnet in sg['Subnets']:
                                        subnet_id = subnet['SubnetIdentifier']
                                        
                                        # Check if subnet is public
                                        ec2_regional = boto3.client('ec2', region_name=current_region)
                                        subnet_info = ec2_regional.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
                                        
                                        if subnet_info.get('MapPublicIpOnLaunch', False):
                                            findings.append({
                                                'ResourceType': 'ElastiCache Memcached',
                                                'ResourceId': cluster_id,
                                                'ResourceName': cluster_id,
                                                'Region': current_region,
                                                'Risk': 'HIGH',
                                                'Issue': 'ElastiCache Memcached cluster is in a public subnet',
                                                'Recommendation': 'Move ElastiCache cluster to private subnets'
                                            })
                                            break
                            except ClientError:
                                pass
            
            except ClientError as e:
                pass
    except Exception as e:
        pass
    
    return findings