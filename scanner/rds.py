"""
RDS Scanner Module - Detects publicly accessible RDS snapshots
"""
import boto3
from botocore.exceptions import ClientError


def scan_rds_snapshots():
    """
    Scan RDS snapshots for public access settings
    Returns a list of dictionaries containing vulnerable resources
    """
    findings = []
    
    try:
        # Get all regions
        ec2_client = boto3.client('ec2')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        for region in regions:
            rds_client = boto3.client('rds', region_name=region)
            
            # Check DB snapshots
            try:
                snapshots = rds_client.describe_db_snapshots()
                for snapshot in snapshots.get('DBSnapshots', []):
                    snapshot_id = snapshot['DBSnapshotIdentifier']
                    
                    # Check if snapshot is public
                    if snapshot.get('Shared') or snapshot.get('SnapshotType') == 'public':
                        findings.append({
                            'ResourceType': 'RDS Snapshot',
                            'ResourceId': snapshot_id,
                            'Region': region,
                            'Risk': 'HIGH',
                            'Issue': 'RDS snapshot is publicly accessible',
                            'Recommendation': 'Remove public access permissions from the snapshot'
                        })
                    
                    # Check attribute specifically
                    try:
                        attrs = rds_client.describe_db_snapshot_attributes(
                            DBSnapshotIdentifier=snapshot_id
                        )
                        
                        for attr_set in attrs.get('DBSnapshotAttributesResult', {}).get('DBSnapshotAttributes', []):
                            if attr_set.get('AttributeName') == 'restore':
                                if 'all' in attr_set.get('AttributeValues', []):
                                    findings.append({
                                        'ResourceType': 'RDS Snapshot',
                                        'ResourceId': snapshot_id,
                                        'Region': region,
                                        'Risk': 'HIGH',
                                        'Issue': 'RDS snapshot is publicly accessible',
                                        'Recommendation': 'Remove public access permissions from the snapshot'
                                    })
                    except ClientError as e:
                        print(f"Error checking snapshot attributes for {snapshot_id} in {region}: {e}")
            
            except ClientError as e:
                print(f"Error listing RDS snapshots in {region}: {e}")
            
            # Check cluster snapshots
            try:
                cluster_snapshots = rds_client.describe_db_cluster_snapshots()
                for snapshot in cluster_snapshots.get('DBClusterSnapshots', []):
                    snapshot_id = snapshot['DBClusterSnapshotIdentifier']
                    
                    # Check attribute specifically
                    try:
                        attrs = rds_client.describe_db_cluster_snapshot_attributes(
                            DBClusterSnapshotIdentifier=snapshot_id
                        )
                        
                        for attr_set in attrs.get('DBClusterSnapshotAttributesResult', {}).get('DBClusterSnapshotAttributes', []):
                            if attr_set.get('AttributeName') == 'restore':
                                if 'all' in attr_set.get('AttributeValues', []):
                                    findings.append({
                                        'ResourceType': 'RDS Cluster Snapshot',
                                        'ResourceId': snapshot_id,
                                        'Region': region,
                                        'Risk': 'HIGH',
                                        'Issue': 'RDS cluster snapshot is publicly accessible',
                                        'Recommendation': 'Remove public access permissions from the cluster snapshot'
                                    })
                    except ClientError as e:
                        print(f"Error checking cluster snapshot attributes for {snapshot_id} in {region}: {e}")
            
            except ClientError as e:
                print(f"Error listing RDS cluster snapshots in {region}: {e}")
    
    except Exception as e:
        print(f"Error scanning RDS snapshots: {e}")
    
    return findings