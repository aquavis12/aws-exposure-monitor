"""
Security Hub Scanner Module - Checks if AWS Security Hub is enabled for centralized security findings
"""
import boto3
from botocore.exceptions import ClientError

def scan_security_hub(region=None):
    """
    Scan AWS Security Hub configuration - informational only, not flagged as exposure
    
    Returns:
        list: List of dictionaries containing Security Hub status information
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
                securityhub_client = boto3.client('securityhub', region_name=current_region)
                
                # Check if Security Hub is enabled
                try:
                    hub_status = securityhub_client.describe_hub()
                    
                    # Security Hub is enabled, check standards subscriptions
                    try:
                        standards = securityhub_client.get_enabled_standards()
                        enabled_standards = standards.get('StandardsSubscriptions', [])
                        
                        if not enabled_standards:
                            findings.append({
                                'ResourceType': 'Security Hub Configuration',
                                'ResourceId': 'securityhub-standards',
                                'ResourceName': 'Security Hub Standards',
                                'Region': current_region,
                                'Risk': 'INFO',
                                'Issue': 'Security Hub is enabled but no security standards are subscribed',
                                'Recommendation': 'Consider enabling AWS Foundational Security Standard and CIS benchmarks (optional)'
                            })
                        else:
                            # Check which standards are enabled
                            standard_names = []
                            for standard in enabled_standards:
                                standard_arn = standard.get('StandardsArn', '')
                                if 'aws-foundational' in standard_arn:
                                    standard_names.append('AWS Foundational')
                                elif 'cis' in standard_arn:
                                    standard_names.append('CIS')
                                elif 'pci-dss' in standard_arn:
                                    standard_names.append('PCI DSS')
                            
                            if standard_names:
                                findings.append({
                                    'ResourceType': 'Security Hub Configuration',
                                    'ResourceId': 'securityhub-enabled',
                                    'ResourceName': 'Security Hub Standards',
                                    'Region': current_region,
                                    'Risk': 'INFO',
                                    'Issue': f'Security Hub enabled with standards: {", ".join(standard_names)}',
                                    'Recommendation': 'Security Hub is properly configured for centralized security monitoring'
                                })
                                
                    except ClientError:
                        pass
                        
                except ClientError as e:
                    if 'InvalidAccessException' in str(e) or 'not subscribed' in str(e).lower():
                        # Security Hub is not enabled
                        findings.append({
                            'ResourceType': 'Security Hub Configuration',
                            'ResourceId': 'securityhub-status',
                            'ResourceName': 'AWS Security Hub',
                            'Region': current_region,
                            'Risk': 'INFO',
                            'Issue': 'AWS Security Hub is not enabled',
                            'Recommendation': 'Consider enabling Security Hub for centralized security findings management (optional)'
                        })
                    
            except ClientError:
                # Security Hub might not be available in this region
                pass
                
    except Exception:
        pass
    
    return findings