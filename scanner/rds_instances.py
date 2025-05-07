"""
RDS Instance Scanner Module - Detects publicly accessible RDS instances
"""
import boto3
from botocore.exceptions import ClientError


def scan_rds_instances():
    """
    Scan RDS instances for public accessibility
    Returns a list of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting RDS instance scan...")
    
    try:
        # Get all regions
        ec2_client = boto3.client('ec2')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        print(f"Scanning {len(regions)} regions")
        
        region_count = 0
        total_instance_count = 0
        
        for region in regions:
            region_count += 1
            print(f"[{region_count}/{len(regions)}] Scanning region: {region}")
            rds_client = boto3.client('rds', region_name=region)
            
            try:
                # Get all RDS instances
                instances = []
                paginator = rds_client.get_paginator('describe_db_instances')
                
                for page in paginator.paginate():
                    instances.extend(page.get('DBInstances', []))
                
                instance_count = len(instances)
                total_instance_count += instance_count
                
                if instance_count > 0:
                    print(f"  Scanning {instance_count} RDS instances in {region}")
                    
                    for i, instance in enumerate(instances, 1):
                        instance_id = instance.get('DBInstanceIdentifier')
                        engine = instance.get('Engine', 'Unknown')
                        endpoint = instance.get('Endpoint', {}).get('Address', 'Unknown')
                        publicly_accessible = instance.get('PubliclyAccessible', False)
                        storage_encrypted = instance.get('StorageEncrypted', False)
                        
                        # Print progress every 5 instances or for the last one
                        if i % 5 == 0 or i == instance_count:
                            print(f"  Progress: {i}/{instance_count}")
                        
                        # Check if instance is publicly accessible
                        if publicly_accessible:
                            findings.append({
                                'ResourceType': 'RDS Instance',
                                'ResourceId': instance_id,
                                'ResourceName': instance_id,
                                'Endpoint': endpoint,
                                'Engine': engine,
                                'Region': region,
                                'Risk': 'HIGH',
                                'Issue': 'RDS instance is publicly accessible',
                                'Recommendation': 'Disable public accessibility and use private subnets with VPC endpoints'
                            })
                            print(f"    [!] FINDING: RDS instance {instance_id} is publicly accessible - HIGH risk")
                        
                        # Check if storage is not encrypted
                        if not storage_encrypted:
                            findings.append({
                                'ResourceType': 'RDS Instance',
                                'ResourceId': instance_id,
                                'ResourceName': instance_id,
                                'Endpoint': endpoint,
                                'Engine': engine,
                                'Region': region,
                                'Risk': 'MEDIUM',
                                'Issue': 'RDS instance storage is not encrypted',
                                'Recommendation': 'Enable storage encryption for the RDS instance'
                            })
                            print(f"    [!] FINDING: RDS instance {instance_id} storage is not encrypted - MEDIUM risk")
                        
                        # Check if instance has enhanced monitoring enabled
                        if instance.get('MonitoringInterval', 0) == 0:
                            findings.append({
                                'ResourceType': 'RDS Instance',
                                'ResourceId': instance_id,
                                'ResourceName': instance_id,
                                'Endpoint': endpoint,
                                'Engine': engine,
                                'Region': region,
                                'Risk': 'LOW',
                                'Issue': 'RDS instance does not have enhanced monitoring enabled',
                                'Recommendation': 'Enable enhanced monitoring for better visibility'
                            })
                            print(f"    [!] FINDING: RDS instance {instance_id} has no enhanced monitoring - LOW risk")
                
                # Get all Aurora clusters
                clusters = []
                cluster_paginator = rds_client.get_paginator('describe_db_clusters')
                
                for page in cluster_paginator.paginate():
                    clusters.extend(page.get('DBClusters', []))
                
                cluster_count = len(clusters)
                
                if cluster_count > 0:
                    print(f"  Scanning {cluster_count} Aurora clusters in {region}")
                    
                    for i, cluster in enumerate(clusters, 1):
                        cluster_id = cluster.get('DBClusterIdentifier')
                        engine = cluster.get('Engine', 'Unknown')
                        endpoint = cluster.get('Endpoint', 'Unknown')
                        publicly_accessible = False
                        storage_encrypted = cluster.get('StorageEncrypted', False)
                        
                        # Check if any instance in the cluster is publicly accessible
                        for instance in cluster.get('DBClusterMembers', []):
                            instance_id = instance.get('DBInstanceIdentifier')
                            try:
                                instance_details = rds_client.describe_db_instances(DBInstanceIdentifier=instance_id)
                                if instance_details['DBInstances'][0].get('PubliclyAccessible', False):
                                    publicly_accessible = True
                                    break
                            except ClientError:
                                pass
                        
                        # Check if cluster is publicly accessible
                        if publicly_accessible:
                            findings.append({
                                'ResourceType': 'Aurora Cluster',
                                'ResourceId': cluster_id,
                                'ResourceName': cluster_id,
                                'Endpoint': endpoint,
                                'Engine': engine,
                                'Region': region,
                                'Risk': 'HIGH',
                                'Issue': 'Aurora cluster has publicly accessible instances',
                                'Recommendation': 'Disable public accessibility for all instances in the cluster'
                            })
                            print(f"    [!] FINDING: Aurora cluster {cluster_id} has publicly accessible instances - HIGH risk")
                        
                        # Check if storage is not encrypted
                        if not storage_encrypted:
                            findings.append({
                                'ResourceType': 'Aurora Cluster',
                                'ResourceId': cluster_id,
                                'ResourceName': cluster_id,
                                'Endpoint': endpoint,
                                'Engine': engine,
                                'Region': region,
                                'Risk': 'MEDIUM',
                                'Issue': 'Aurora cluster storage is not encrypted',
                                'Recommendation': 'Enable storage encryption for the Aurora cluster'
                            })
                            print(f"    [!] FINDING: Aurora cluster {cluster_id} storage is not encrypted - MEDIUM risk")
            
            except ClientError as e:
                print(f"  Error scanning RDS instances in {region}: {e}")
        
        if total_instance_count == 0:
            print("No RDS instances found.")
        else:
            print(f"RDS instance scan complete. Scanned {total_instance_count} instances.")
    
    except Exception as e:
        print(f"Error scanning RDS instances: {e}")
    
    if findings:
        print(f"Found {len(findings)} RDS instance issues.")
    else:
        print("No RDS instance issues found.")
    
    return findings