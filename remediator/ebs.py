"""
EBS Remediator Module - Automatically fixes public EBS snapshot issues
"""
import boto3
from botocore.exceptions import ClientError


def remediate_ebs_snapshot(snapshot_id, region):
    """
    Remediate public access issues for an EBS snapshot
    
    Args:
        snapshot_id (str): The ID of the snapshot to remediate
        region (str): The AWS region where the snapshot exists
    
    Returns:
        dict: A dictionary with the remediation status and details
    """
    ec2_client = boto3.client('ec2', region_name=region)
    result = {
        'snapshot_id': snapshot_id,
        'region': region,
        'success': False,
        'actions': [],
        'errors': []
    }
    
    try:
        # Check if snapshot exists and is owned by us
        try:
            snapshot = ec2_client.describe_snapshots(SnapshotIds=[snapshot_id], OwnerIds=['self'])
            if not snapshot.get('Snapshots'):
                result['errors'].append(f"Snapshot {snapshot_id} not found or not owned by this account")
                return result
        except ClientError as e:
            result['errors'].append(f"Error checking snapshot: {str(e)}")
            return result
        
        # Check if snapshot is public
        try:
            attribute = ec2_client.describe_snapshot_attribute(
                SnapshotId=snapshot_id,
                Attribute='createVolumePermission'
            )
            
            is_public = False
            for permission in attribute.get('CreateVolumePermissions', []):
                if permission.get('Group') == 'all':
                    is_public = True
                    break
            
            if is_public:
                # Remove public access
                ec2_client.modify_snapshot_attribute(
                    SnapshotId=snapshot_id,
                    CreateVolumePermission={
                        'Remove': [{'Group': 'all'}]
                    },
                    OperationType='remove'
                )
                result['actions'].append('Removed public access permissions from snapshot')
                result['success'] = True
            else:
                result['actions'].append('Snapshot is already private')
                result['success'] = True
        
        except ClientError as e:
            result['errors'].append(f"Failed to modify snapshot permissions: {str(e)}")
        
    except Exception as e:
        result['errors'].append(f"General error during remediation: {str(e)}")
    
    return result


def remediate_ebs_findings(findings):
    """
    Remediate all EBS snapshot-related findings
    
    Args:
        findings (list): A list of findings to remediate
    
    Returns:
        list: A list of remediation results
    """
    results = []
    
    for finding in findings:
        if finding.get('ResourceType') == 'EBS Snapshot':
            snapshot_id = finding.get('ResourceId')
            region = finding.get('Region', 'us-east-1')
            
            if snapshot_id:
                result = remediate_ebs_snapshot(snapshot_id, region)
                results.append(result)
    
    return results