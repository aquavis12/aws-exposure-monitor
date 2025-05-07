"""
AMI Scanner Module - Detects publicly accessible AMIs
"""
import boto3
from botocore.exceptions import ClientError


def scan_amis():
    """
    Scan AMIs for public access settings
    Returns a list of dictionaries containing vulnerable resources
    """
    findings = []
    
    try:
        # Get all regions
        ec2_client = boto3.client('ec2')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        for region in regions:
            regional_client = boto3.client('ec2', region_name=region)
            
            # Get owned AMIs
            try:
                images = regional_client.describe_images(Owners=['self'])
                
                for image in images.get('Images', []):
                    image_id = image['ImageId']
                    
                    # Check if AMI is public
                    if image.get('Public', False):
                        findings.append({
                            'ResourceType': 'AMI',
                            'ResourceId': image_id,
                            'Region': region,
                            'Risk': 'HIGH',
                            'Issue': 'AMI is publicly accessible',
                            'Recommendation': 'Make the AMI private or delete if not needed'
                        })
                    
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
                                    'Region': region,
                                    'Risk': 'HIGH',
                                    'Issue': 'AMI has public launch permissions',
                                    'Recommendation': 'Remove public launch permissions from the AMI'
                                })
                                break
                    except ClientError as e:
                        print(f"Error checking AMI permissions for {image_id} in {region}: {e}")
            
            except ClientError as e:
                print(f"Error listing AMIs in {region}: {e}")
    
    except Exception as e:
        print(f"Error scanning AMIs: {e}")
    
    return findings