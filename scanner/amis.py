"""
AMI Scanner Module - Detects publicly accessible AMIs and encryption issues
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime


def scan_amis(region=None):
    """
    Scan AMIs for public access settings and encryption
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting AMI scan...")
    
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
        total_amis_found = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            regional_client = boto3.client('ec2', region_name=current_region)
            
            # Get owned AMIs
            try:
                images = regional_client.describe_images(Owners=['self'])
                ami_list = images.get('Images', [])
                
                if ami_list:
                    ami_count = len(ami_list)
                    total_amis_found += ami_count
                    print(f"  Found {ami_count} AMIs in {current_region}")
                    
                    for i, image in enumerate(ami_list, 1):
                        image_id = image['ImageId']
                        
                        # Get image name and other details
                        image_name = image.get('Name', image_id)
                        description = image.get('Description', '')
                        creation_date = image.get('CreationDate', '')
                        platform = image.get('Platform', 'Linux/UNIX')
                        state = image.get('State', '')
                        
                        # Print progress every 5 AMIs or for the last one
                        if i % 5 == 0 or i == ami_count:
                            print(f"  Progress: {i}/{ami_count}")
                        
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
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'AMI is publicly accessible',
                                'Recommendation': 'Make the AMI private or delete if not needed'
                            })
                            print(f"    [!] FINDING: AMI {image_id} is publicly accessible - HIGH risk")
                        
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
                                        'Region': current_region,
                                        'Risk': 'HIGH',
                                        'Issue': 'AMI has public launch permissions',
                                        'Recommendation': 'Remove public launch permissions from the AMI'
                                    })
                                    print(f"    [!] FINDING: AMI {image_id} has public launch permissions - HIGH risk")
                                    break
                        except ClientError as e:
                            # Silently handle errors checking permissions
                            pass
                        
                        # Check if AMI is encrypted
                        # Get block device mappings
                        block_devices = image.get('BlockDeviceMappings', [])
                        
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
                                    except ClientError:
                                        # Silently handle errors checking snapshots
                                        pass
                        
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
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': f'AMI contains unencrypted volumes: {", ".join(unencrypted_volumes)}',
                                'Recommendation': 'Create a new AMI with encrypted snapshots'
                            })
                            print(f"    [!] FINDING: AMI {image_id} contains {len(unencrypted_volumes)} unencrypted volumes - MEDIUM risk")
            
            except ClientError as e:
                print(f"  Error listing AMIs in {current_region}: {e}")
    
    except Exception as e:
        print(f"Error scanning AMIs: {e}")
    
    if total_amis_found == 0:
        print("No AMIs found.")
    else:
        print(f"AMI scan complete. Scanned {total_amis_found} AMIs.")
    
    if findings:
        print(f"Found {len(findings)} AMI issues.")
    else:
        print("No AMI issues found.")
    
    return findings