"""
Aurora Scanner Module - Detects security issues with Amazon Aurora clusters
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan_aurora_clusters(region=None):
    """
    Scan Aurora clusters for security issues like:
    - Public accessibility
    - Encryption at rest
    - Backup retention
    - Deletion protection
    - Engine version
    
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
        total_cluster_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                pass
            rds_client = boto3.client('rds', region_name=current_region)
            
            try:
                # Get all Aurora clusters
                clusters = rds_client.describe_db_clusters().get('DBClusters', [])
                
                # Filter for Aurora clusters
                aurora_clusters = [c for c in clusters if 'aurora' in c.get('Engine', '').lower()]
                cluster_count = len(aurora_clusters)
                
                if cluster_count > 0:
                    total_cluster_count += cluster_count
                    print(f"  Found {cluster_count} Aurora clusters in {current_region}")
                    
                    for i, cluster in enumerate(aurora_clusters, 1):
                        cluster_id = cluster.get('DBClusterIdentifier')
                        engine = cluster.get('Engine')
                        engine_version = cluster.get('EngineVersion')
                        
                        # Get cluster name from tags
                        cluster_name = cluster_id
                        for tag in cluster.get('TagList', []):
                            if tag.get('Key') == 'Name':
                                cluster_name = tag.get('Value')
                                break
                        
                        # Print progress every 5 clusters or for the last one
                        if i % 5 == 0 or i == cluster_count:
                            print(f"  Progress: {i}/{cluster_count}")
                        
                        # Check if cluster is publicly accessible
                        is_public = cluster.get('PubliclyAccessible', False)
                        if is_public:
                            findings.append({
                                'ResourceType': 'Aurora Cluster',
                                'ResourceId': cluster_id,
                                'ResourceName': cluster_name,
                                'Engine': engine,
                                'EngineVersion': engine_version,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'Aurora cluster is publicly accessible',
                                'Recommendation': 'Disable public accessibility and use private subnets with VPC endpoints'
                            })
                        
                        # Check for encryption at rest
                        if not cluster.get('StorageEncrypted', False):
                            findings.append({
                                'ResourceType': 'Aurora Cluster',
                                'ResourceId': cluster_id,
                                'ResourceName': cluster_name,
                                'Engine': engine,
                                'EngineVersion': engine_version,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'Aurora cluster is not encrypted at rest',
                                'Recommendation': 'Enable encryption at rest for Aurora clusters'
                            })
                        
                        # Check backup retention period
                        backup_retention = cluster.get('BackupRetentionPeriod', 0)
                        if backup_retention < 7:
                            findings.append({
                                'ResourceType': 'Aurora Cluster',
                                'ResourceId': cluster_id,
                                'ResourceName': cluster_name,
                                'Engine': engine,
                                'EngineVersion': engine_version,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': f'Aurora cluster has short backup retention period ({backup_retention} days)',
                                'Recommendation': 'Increase backup retention period to at least 7 days'
                            })
                        
                        # Check for deletion protection
                        if not cluster.get('DeletionProtection', False):
                            findings.append({
                                'ResourceType': 'Aurora Cluster',
                                'ResourceId': cluster_id,
                                'ResourceName': cluster_name,
                                'Engine': engine,
                                'EngineVersion': engine_version,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'Aurora cluster does not have deletion protection enabled',
                                'Recommendation': 'Enable deletion protection for production Aurora clusters'
                            })
                        
                        # Check for outdated engine versions
                        if engine == 'aurora-mysql':
                            major_version = engine_version.split('.')[0]
                            if int(major_version) < 5:
                                findings.append({
                                    'ResourceType': 'Aurora Cluster',
                                    'ResourceId': cluster_id,
                                    'ResourceName': cluster_name,
                                    'Engine': engine,
                                    'EngineVersion': engine_version,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': f'Aurora MySQL cluster is using outdated engine version {engine_version}',
                                    'Recommendation': 'Upgrade to the latest Aurora MySQL version for security updates'
                                })
                        elif engine == 'aurora-postgresql':
                            major_version = engine_version.split('.')[0]
                            if int(major_version) < 11:
                                findings.append({
                                    'ResourceType': 'Aurora Cluster',
                                    'ResourceId': cluster_id,
                                    'ResourceName': cluster_name,
                                    'Engine': engine,
                                    'EngineVersion': engine_version,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': f'Aurora PostgreSQL cluster is using outdated engine version {engine_version}',
                                    'Recommendation': 'Upgrade to the latest Aurora PostgreSQL version for security updates'
                                })
                        
                        # Check for IAM authentication
                        if not cluster.get('IAMDatabaseAuthenticationEnabled', False):
                            findings.append({
                                'ResourceType': 'Aurora Cluster',
                                'ResourceId': cluster_id,
                                'ResourceName': cluster_name,
                                'Engine': engine,
                                'EngineVersion': engine_version,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': 'Aurora cluster does not have IAM authentication enabled',
                                'Recommendation': 'Enable IAM authentication for better access control'
                            })
                        
                        # Check for enhanced monitoring
                        instances = rds_client.describe_db_instances(
                            Filters=[{'Name': 'db-cluster-id', 'Values': [cluster_id]}]
                        ).get('DBInstances', [])
                        
                        for instance in instances:
                            instance_id = instance.get('DBInstanceIdentifier')
                            monitoring_interval = instance.get('MonitoringInterval', 0)
                            
                            if monitoring_interval == 0:
                                findings.append({
                                    'ResourceType': 'Aurora Instance',
                                    'ResourceId': instance_id,
                                    'ResourceName': f"{cluster_name}/{instance_id}",
                                    'Engine': engine,
                                    'EngineVersion': engine_version,
                                    'Region': current_region,
                                    'Risk': 'LOW',
                                    'Issue': 'Aurora instance does not have enhanced monitoring enabled',
                                    'Recommendation': 'Enable enhanced monitoring for better visibility'
                                })
            
            except ClientError as e:
                pass
    except Exception as e:
        pass
    
    return findings