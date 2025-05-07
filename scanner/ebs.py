"""
EBS Scanner Module - Detects publicly accessible EBS snapshots
"""
import boto3
from botocore.exceptions import ClientError


def scan_ebs_snapshots():
    """
    Scan EBS snapshots for public access settings
    Returns a list of dictionaries containing vulnerable resources
    """
    findings = []
    ec2_client = boto3.client('ec2')
    
    try:
        # Get all regions
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        for region in regions:
            regional_client = boto3.client('ec2', region_name=region)
            
            # Check owned snapshots
            owned_snapshots = regional_client.describe_snapshots(OwnerIds=['self'])
            
            for snapshot in owned_snapshots.get('Snapshots', []):
                snapshot_id = snapshot['SnapshotId']
                
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
                                'Region': region,
                                'Risk': 'HIGH',
                                'Issue': 'EBS snapshot is publicly accessible',
                                'Recommendation': 'Remove public access permissions from the snapshot'
                            })
                            break
                except ClientError as e:
                    print(f"Error checking snapshot {snapshot_id} in {region}: {e}")
    
    except Exception as e:
        print(f"Error scanning EBS snapshots: {e}")
    
    return findings