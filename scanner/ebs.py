"""
EBS Scanner Module - Detects publicly accessible EBS snapshots and encryption issues
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime


def scan_ebs_snapshots():
    """
    Scan EBS snapshots for public access settings and encryption
    Returns a list of dictionaries containing vulnerable resources
    """
    findings = []
    ec2_client = boto3.client('ec2')
    
    print("Starting EBS snapshot and volume scan...")
    
    try:
        # Get all regions
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        print(f"Found {len(regions)} regions to scan")
        
        region_count = 0
        for region in regions:
            region_count += 1
            print(f"[{region_count}/{len(regions)}] Scanning region: {region}")
            regional_client = boto3.client('ec2', region_name=region)
            
            # Check owned snapshots
            try:
                owned_snapshots = regional_client.describe_snapshots(OwnerIds=['self'])
                snapshots = owned_snapshots.get('Snapshots', [])
                print(f"  Found {len(snapshots)} EBS snapshots in {region}")
                
                snapshot_count = 0
                for snapshot in snapshots:
                    snapshot_count += 1
                    snapshot_id = snapshot['SnapshotId']
                    volume_id = snapshot.get('VolumeId', 'Unknown')
                    description = snapshot.get('Description', '')
                    start_time = snapshot.get('StartTime')
                    
                    # Format start time for display
                    if start_time:
                        if isinstance(start_time, datetime):
                            start_time_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            start_time_str = str(start_time)
                    else:
                        start_time_str = 'Unknown'
                    
                    # Create a resource name from the description or snapshot ID
                    resource_name = description if description else snapshot_id
                    
                    # Print progress every 10 snapshots or for the last one
                    if snapshot_count % 10 == 0 or snapshot_count == len(snapshots):
                        print(f"  Scanning snapshot {snapshot_count}/{len(snapshots)}: {snapshot_id} - {resource_name[:30]}...")
                    
                    # Check if snapshot is public
                    try:
                        attribute = regional_client.describe_snapshot_attribute(
                            SnapshotId=snapshot_id,
                            Attribute='createVolumePermission'
                        )
                        
                        for permission in attribute.get('CreateVolumePermissions', []):
                            if permission.get('Group') == 'all':
                                findings.append({
                                    'ResourceType': 'EBS Snapshot',
                                    'ResourceId': snapshot_id,
                                    'ResourceName': resource_name,
                                    'VolumeId': volume_id,
                                    'CreationDate': start_time_str,
                                    'Region': region,
                                    'Risk': 'HIGH',
                                    'Issue': 'EBS snapshot is publicly accessible',
                                    'Recommendation': 'Remove public access permissions from the snapshot'
                                })
                                print(f"    [!] FINDING: Snapshot {snapshot_id} is publicly accessible - HIGH risk")
                                break
                    except ClientError as e:
                        print(f"    Error checking snapshot {snapshot_id} permissions: {e}")
                    
                    # Check if snapshot is encrypted
                    encrypted = snapshot.get('Encrypted', False)
                    if not encrypted:
                        findings.append({
                            'ResourceType': 'EBS Snapshot',
                            'ResourceId': snapshot_id,
                            'ResourceName': resource_name,
                            'VolumeId': volume_id,
                            'CreationDate': start_time_str,
                            'Region': region,
                            'Risk': 'MEDIUM',
                            'Issue': 'EBS snapshot is not encrypted',
                            'Recommendation': 'Create encrypted snapshots and consider migrating data to encrypted volumes'
                        })
                        print(f"    [!] FINDING: Snapshot {snapshot_id} is not encrypted - MEDIUM risk")
            
            except ClientError as e:
                print(f"  Error listing snapshots in {region}: {e}")
            
            # Check for EBS volumes
            try:
                volumes_response = regional_client.describe_volumes()
                volumes = volumes_response.get('Volumes', [])
                print(f"  Found {len(volumes)} EBS volumes in {region}")
                
                volume_count = 0
                for volume in volumes:
                    volume_count += 1
                    volume_id = volume.get('VolumeId')
                    encrypted = volume.get('Encrypted', False)
                    state = volume.get('State', 'unknown')
                    size = volume.get('Size', 0)
                    
                    # Get volume name from tags
                    volume_name = volume_id
                    for tag in volume.get('Tags', []):
                        if tag.get('Key') == 'Name':
                            volume_name = tag.get('Value')
                            break
                    
                    # Print progress every 10 volumes or for the last one
                    if volume_count % 10 == 0 or volume_count == len(volumes):
                        print(f"  Scanning volume {volume_count}/{len(volumes)}: {volume_id} - {volume_name[:30]} ({size} GB, {state})")
                    
                    if not encrypted:
                        findings.append({
                            'ResourceType': 'EBS Volume',
                            'ResourceId': volume_id,
                            'ResourceName': volume_name,
                            'Size': f"{size} GB",
                            'State': state,
                            'Region': region,
                            'Risk': 'MEDIUM',
                            'Issue': 'EBS volume is not encrypted',
                            'Recommendation': 'Create an encrypted snapshot, create a new encrypted volume from the snapshot, and replace the original volume'
                        })
                        print(f"    [!] FINDING: Volume {volume_id} ({volume_name}) is not encrypted - MEDIUM risk")
            
            except ClientError as e:
                print(f"  Error checking EBS volumes in {region}: {e}")
            
            print("")  # Add a blank line between regions
    
    except Exception as e:
        print(f"Error scanning EBS snapshots and volumes: {e}")
    
    print(f"EBS scan complete. Found {len(findings)} issues.")
    return findings