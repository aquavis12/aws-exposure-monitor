"""
EFS Scanner Module - Detects security issues with AWS EFS
"""
import boto3
from botocore.exceptions import ClientError

def scan_efs(region=None):
    """
    Scan EFS file systems for security issues
    
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
                efs_client = boto3.client('efs', region_name=current_region)
                
                # Get all file systems
                file_systems = efs_client.describe_file_systems()['FileSystems']
                
                for fs in file_systems:
                    fs_id = fs['FileSystemId']
                    fs_name = fs.get('Name', fs_id)
                    
                    # Check encryption
                    if not fs.get('Encrypted', False):
                        findings.append({
                            'ResourceType': 'EFS File System',
                            'ResourceId': fs_id,
                            'ResourceName': fs_name,
                            'Region': current_region,
                            'Risk': 'HIGH',
                            'Issue': 'EFS file system is not encrypted',
                            'Recommendation': 'Enable encryption for EFS file system'
                        })
                    
                    # Check mount targets for public access
                    try:
                        mount_targets = efs_client.describe_mount_targets(FileSystemId=fs_id)
                        for mt in mount_targets['MountTargets']:
                            subnet_id = mt['SubnetId']
                            
                            # Check if subnet is public
                            ec2_regional = boto3.client('ec2', region_name=current_region)
                            subnet = ec2_regional.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
                            
                            if subnet.get('MapPublicIpOnLaunch', False):
                                findings.append({
                                    'ResourceType': 'EFS Mount Target',
                                    'ResourceId': mt['MountTargetId'],
                                    'ResourceName': f"Mount Target for {fs_name}",
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'EFS mount target is in a public subnet',
                                    'Recommendation': 'Move EFS mount targets to private subnets'
                                })
                    except ClientError:
                        pass
            
            except ClientError as e:
                pass
    except Exception as e:
        pass
    
    return findings