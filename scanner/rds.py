"""
RDS Scanner Module - Detects publicly accessible RDS snapshots
"""
import boto3
from botocore.exceptions import ClientError


def scan_rds_snapshots(region=None):
    """
    Scan RDS snapshots for public access settings
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting RDS snapshot scan...")
    
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
        total_snapshots_found = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            rds_client = boto3.client('rds', region_name=current_region)
            
            # Check DB snapshots
            try:
                snapshots = rds_client.describe_db_snapshots()
                db_snapshots = snapshots.get('DBSnapshots', [])
                
                if db_snapshots:
                    total_snapshots_found += len(db_snapshots)
                    print(f"  Found {len(db_snapshots)} RDS snapshots in {current_region}")
                    
                    for i, snapshot in enumerate(db_snapshots, 1):
                        snapshot_id = snapshot['DBSnapshotIdentifier']
                        db_instance_id = snapshot.get('DBInstanceIdentifier', 'Unknown')
                        engine = snapshot.get('Engine', 'Unknown')
                        snapshot_type = snapshot.get('SnapshotType', 'Unknown')
                        
                        # Print progress every 10 snapshots or for the last one
                        if i % 10 == 0 or i == len(db_snapshots):
                            print(f"  Scanning snapshot {i}/{len(db_snapshots)}: {snapshot_id} ({engine})")
                        
                        # Check if snapshot is public
                        if snapshot.get('Shared') or snapshot.get('SnapshotType') == 'public':
                            findings.append({
                                'ResourceType': 'RDS Snapshot',
                                'ResourceId': snapshot_id,
                                'ResourceName': snapshot_id,
                                'DBInstanceId': db_instance_id,
                                'Engine': engine,
                                'SnapshotType': snapshot_type,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'RDS snapshot is publicly accessible',
                                'Recommendation': 'Remove public access permissions from the snapshot'
                            })
                            print(f"    [!] FINDING: Snapshot {snapshot_id} is publicly accessible - HIGH risk")
                        
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
                                            'ResourceName': snapshot_id,
                                            'DBInstanceId': db_instance_id,
                                            'Engine': engine,
                                            'SnapshotType': snapshot_type,
                                            'Region': current_region,
                                            'Risk': 'HIGH',
                                            'Issue': 'RDS snapshot has public restore attribute',
                                            'Recommendation': 'Remove public access permissions from the snapshot'
                                        })
                                        print(f"    [!] FINDING: Snapshot {snapshot_id} has public restore attribute - HIGH risk")
                        except ClientError as e:
                            print(f"    Error checking snapshot attributes for {snapshot_id}: {e}")
            
            except ClientError as e:
                print(f"  Error listing RDS snapshots in {current_region}: {e}")
            
            # Check cluster snapshots
            try:
                cluster_snapshots_response = rds_client.describe_db_cluster_snapshots()
                cluster_snapshots = cluster_snapshots_response.get('DBClusterSnapshots', [])
                
                if cluster_snapshots:
                    total_snapshots_found += len(cluster_snapshots)
                    print(f"  Found {len(cluster_snapshots)} RDS cluster snapshots in {current_region}")
                    
                    for i, snapshot in enumerate(cluster_snapshots, 1):
                        snapshot_id = snapshot['DBClusterSnapshotIdentifier']
                        cluster_id = snapshot.get('DBClusterIdentifier', 'Unknown')
                        engine = snapshot.get('Engine', 'Unknown')
                        snapshot_type = snapshot.get('SnapshotType', 'Unknown')
                        
                        # Print progress every 10 snapshots or for the last one
                        if i % 10 == 0 or i == len(cluster_snapshots):
                            print(f"  Scanning cluster snapshot {i}/{len(cluster_snapshots)}: {snapshot_id} ({engine})")
                        
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
                                            'ResourceName': snapshot_id,
                                            'DBClusterId': cluster_id,
                                            'Engine': engine,
                                            'SnapshotType': snapshot_type,
                                            'Region': current_region,
                                            'Risk': 'HIGH',
                                            'Issue': 'RDS cluster snapshot is publicly accessible',
                                            'Recommendation': 'Remove public access permissions from the cluster snapshot'
                                        })
                                        print(f"    [!] FINDING: Cluster snapshot {snapshot_id} is publicly accessible - HIGH risk")
                        except ClientError as e:
                            print(f"    Error checking cluster snapshot attributes for {snapshot_id}: {e}")
            
            except ClientError as e:
                print(f"  Error listing RDS cluster snapshots in {current_region}: {e}")
    
    except Exception as e:
        print(f"Error scanning RDS snapshots: {e}")
    
    if total_snapshots_found == 0:
        print("No RDS snapshots found.")
    else:
        print(f"RDS snapshot scan complete. Scanned {total_snapshots_found} snapshots.")
    
    if findings:
        print(f"Found {len(findings)} RDS snapshot issues.")
    else:
        print("No RDS snapshot issues found.")
    
    return findings