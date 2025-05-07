"""
AMI Scanner Module - Detects publicly accessible AMIs and encryption issues
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime


def scan_amis():
    """
    Scan AMIs for public access settings and encryption
    Returns a list of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting AMI scan...")
    
    try:
        # Get all regions
        ec2_client = boto3.client('ec2')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        print(f"Found {len(regions)} regions to scan")
        
        region_count = 0
        for region in regions:
            region_count += 1
            print(f"[{region_count}/{len(regions)}] Scanning region: {region}")
            regional_client = boto3.client('ec2', region_name=region)
            
            # Get owned AMIs
            try:
                images = regional_client.describe_images(Owners=['self'])
                ami_count = len(images.get('Images', []))
                print(f"  Found {ami_count} AMIs in {region}")
                
                for i, image in enumerate(images.get('Images', []), 1):
                    image_id = image['ImageId']
                    
                    # Get image name and other details
                    image_name = image.get('Name', image_id)
                    description = image.get('Description', '')
                    creation_date = image.get('CreationDate', '')
                    platform = image.get('Platform', 'Linux/UNIX')
                    state = image.get('State', '')
                    
                    # Print progress for each AMI
                    print(f"  [{i}/{ami_count}] Scanning AMI: {image_id} - {image_name[:30]} ({platform}, {state})")
                    
                    # Check if AMI is public
                    if image.get('Public', False):
                        findings.append({
                            'ResourceType': 'AMI',
                            'ResourceId': image_id,
                            'ResourceName': image_name,
                            'Description': description,
                            'Platform': platform,
                            'CreationDate': creation_date,
                            'State': state,
                            'Region': region,
                            'Risk': 'HIGH',
                            'Issue': 'AMI is publicly accessible',
                            'Recommendation': 'Make the AMI private or delete if not needed'
                        })
                        print(f"    [!] FINDING: AMI is publicly accessible - HIGH risk")
                    
                    # Check launch permissions
                    try:
                        perms = regional_client.describe_image_attribute(
                            ImageId=image_id,
                            Attribute='launchPermission'
                        )
                        
                        for perm in perms.get('LaunchPermissions', []):
                            if perm.get('Group') == 'all':
                                findings.append({
                                    'ResourceType': 'AMI',
                                    'ResourceId': image_id,
                                    'ResourceName': image_name,
                                    'Description': description,
                                    'Platform': platform,
                                    'CreationDate': creation_date,
                                    'State': state,
                                    'Region': region,
                                    'Risk': 'HIGH',
                                    'Issue': 'AMI has public launch permissions',
                                    'Recommendation': 'Remove public launch permissions from the AMI'
                                })
                                print(f"    [!] FINDING: AMI has public launch permissions - HIGH risk")
                                break
                    except ClientError as e:
                        print(f"    Error checking AMI permissions: {e}")
                    
                    # Check if AMI is encrypted
                    # Get block device mappings
                    block_devices = image.get('BlockDeviceMappings', [])
                    print(f"    Checking {len(block_devices)} block devices for encryption")
                    
                    unencrypted_volumes = []
                    
                    for device in block_devices:
                        if 'Ebs' in device:
                            ebs = device['Ebs']
                            device_name = device.get('DeviceName', '')
                            snapshot_id = ebs.get('SnapshotId')
                            
                            if snapshot_id:
                                try:
                                    # Check if the snapshot is encrypted
                                    snapshot = regional_client.describe_snapshots(SnapshotIds=[snapshot_id])
                                    if snapshot['Snapshots'] and not snapshot['Snapshots'][0].get('Encrypted', False):
                                        unencrypted_volumes.append(f"{device_name} (snapshot: {snapshot_id})")
                                except ClientError as e:
                                    print(f"    Error checking snapshot encryption for {snapshot_id}: {e}")
                    
                    if unencrypted_volumes:
                        findings.append({
                            'ResourceType': 'AMI',
                            'ResourceId': image_id,
                            'ResourceName': image_name,
                            'Description': description,
                            'Platform': platform,
                            'CreationDate': creation_date,
                            'State': state,
                            'UnencryptedVolumes': unencrypted_volumes,
                            'Region': region,
                            'Risk': 'MEDIUM',
                            'Issue': f'AMI contains unencrypted volumes: {", ".join(unencrypted_volumes)}',
                            'Recommendation': 'Create a new AMI with encrypted snapshots'
                        })
                        print(f"    [!] FINDING: AMI contains {len(unencrypted_volumes)} unencrypted volumes - MEDIUM risk")
                
                print("")  # Add a blank line between regions
            
            except ClientError as e:
                print(f"  Error listing AMIs in {region}: {e}")
    
    except Exception as e:
        print(f"Error scanning AMIs: {e}")
    
    print(f"AMI scan complete. Found {len(findings)} issues.")
    return findings