"""
Inspector Scanner Module - Checks if Amazon Inspector is enabled for vulnerability assessments
"""
import boto3
from botocore.exceptions import ClientError

def scan_inspector(region=None):
    """
    Scan Amazon Inspector configuration - informational only, not flagged as exposure
    
    Returns:
        list: List of dictionaries containing Inspector status information
    """
    findings = []
    
    try:
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        for current_region in regions:
            try:
                inspector_client = boto3.client('inspector2', region_name=current_region)
                
                # Check if Inspector is enabled
                try:
                    account_status = inspector_client.batch_get_account_status()
                    accounts = account_status.get('accounts', [])
                    
                    if not accounts:
                        # Inspector not configured
                        findings.append({
                            'ResourceType': 'Inspector',
                            'ResourceId': 'inspector-status',
                            'ResourceName': 'Amazon Inspector',
                            'Region': current_region,
                            'Risk': 'INFO',
                            'Issue': 'Amazon Inspector is not enabled',
                            'Recommendation': 'Consider enabling Inspector for vulnerability assessments'
                        })
                    else:
                        for account in accounts:
                            account_id = account.get('accountId')
                            resource_state = account.get('resourceState', {})
                            
                            # Check ECR scanning
                            ecr_status = resource_state.get('ecr', {}).get('status')
                            if ecr_status != 'ENABLED':
                                findings.append({
                                    'ResourceType': 'Inspector Configuration',
                                    'ResourceId': f'inspector-ecr-{account_id}',
                                    'ResourceName': 'Inspector ECR Scanning',
                                    'Region': current_region,
                                    'Risk': 'INFO',
                                    'Issue': 'Inspector ECR vulnerability scanning is disabled',
                                    'Recommendation': 'Consider enabling ECR scanning for container image vulnerabilities (optional)'
                                })
                            
                            # Check EC2 scanning
                            ec2_status = resource_state.get('ec2', {}).get('status')
                            if ec2_status != 'ENABLED':
                                findings.append({
                                    'ResourceType': 'Inspector Configuration',
                                    'ResourceId': f'inspector-ec2-{account_id}',
                                    'ResourceName': 'Inspector EC2 Scanning',
                                    'Region': current_region,
                                    'Risk': 'INFO',
                                    'Issue': 'Inspector EC2 vulnerability scanning is disabled',
                                    'Recommendation': 'Consider enabling EC2 scanning for instance vulnerabilities (optional)'
                                })
                                
                except ClientError:
                    findings.append({
                        'ResourceType': 'Inspector',
                        'ResourceId': 'inspector-disabled',
                        'ResourceName': 'Amazon Inspector',
                        'Region': current_region,
                        'Risk': 'INFO',
                        'Issue': 'Amazon Inspector is not enabled',
                        'Recommendation': 'Consider enabling Inspector for vulnerability assessments'
                    })
                        
            except ClientError:
                # Inspector might not be available in this region
                pass
                
    except Exception:
        pass
    
    return findings