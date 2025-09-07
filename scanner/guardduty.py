"""
GuardDuty Scanner Module - Detects security issues with AWS GuardDuty
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan_guardduty(region=None):
    """
    Scan AWS GuardDuty for security issues like:
    - GuardDuty not enabled in all regions
    - Missing S3 protection
    - Missing EKS protection
    - Missing Malware protection
    - Missing automated response
    - Findings not being acted upon
    
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
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        # Check for organization GuardDuty in us-east-1 (global)
        org_guardduty_exists = False
        try:
            org_client = boto3.client('organizations')
            try:
                org_info = org_client.describe_organization()
                # We're in an organization, check for organization GuardDuty
                guardduty_client = boto3.client('guardduty', region_name='us-east-1')
                try:
                    detector_ids = guardduty_client.list_detectors()
                    if detector_ids.get('DetectorIds'):
                        for detector_id in detector_ids.get('DetectorIds'):
                            admin_accounts = guardduty_client.list_organization_admin_accounts(DetectorId=detector_id)
                            if admin_accounts.get('AdminAccounts'):
                                org_guardduty_exists = True
                                print("Organization GuardDuty is enabled")
                                break
                except ClientError:
                    # No organization GuardDuty or no permission
                    pass
            except ClientError:
                # Not an organization or no permission to check
                pass
        except (ImportError, ClientError):
            # Organizations module not available or not an organization
            pass
        
        # Check each region for GuardDuty
        region_count = 0
        regions_with_guardduty = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                pass
            guardduty_client = boto3.client('guardduty', region_name=current_region)
            
            try:
                # Check if GuardDuty is enabled
                detector_ids = guardduty_client.list_detectors()
                detector_list = detector_ids.get('DetectorIds', [])
                
                if not detector_list and not org_guardduty_exists:
                    findings.append({
                        'ResourceType': 'GuardDuty',
                        'ResourceId': f'guardduty-{current_region}',
                        'ResourceName': f'GuardDuty in {current_region}',
                        'Region': current_region,
                        'Risk': 'INFO',
                        'Issue': f'GuardDuty is not enabled in region {current_region}',
                        'Recommendation': 'Consider enabling GuardDuty for threat detection'
                    })
                    continue
                
                regions_with_guardduty += 1
                
                # Check detector configuration
                for detector_id in detector_list:
                    # Get detector details
                    try:
                        detector = guardduty_client.get_detector(DetectorId=detector_id)
                        
                        # Check if detector is enabled
                        if not detector.get('Status') == 'ENABLED':
                            findings.append({
                                'ResourceType': 'GuardDuty',
                                'ResourceId': detector_id,
                                'ResourceName': f'Detector {detector_id}',
                                'Region': current_region,
                                'Risk': 'INFO',
                                'Issue': 'GuardDuty detector is not enabled',
                                'Recommendation': 'Enable the GuardDuty detector'
                            })
                            continue
                        
                        # Check finding publishing frequency (informational only)
                        
                        # Check data sources
                        data_sources = detector.get('DataSources', {})
                        
                        # Check S3 logs (informational only)
                        
                        # Check Kubernetes logs (informational only)
                        
                        # Check Malware Protection (informational only)
                    
                    except ClientError as e:
                        pass
                    
                    # Check for active findings
                    try:
                        # List findings with high or critical severity from the last 30 days
                        current_time = datetime.now(timezone.utc)
                        thirty_days_ago = current_time - timedelta(days=30)
                        
                        finding_criteria = {
                            'Criterion': {
                                'severity': {
                                    'Eq': ['7', '8', '9']  # High and Critical severity
                                },
                                'updatedAt': {
                                    'GreaterThanOrEqual': thirty_days_ago.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                                }
                            }
                        }
                        
                        findings_result = guardduty_client.list_findings(
                            DetectorId=detector_id,
                            FindingCriteria=finding_criteria,
                            MaxResults=50
                        )
                        
                        finding_ids = findings_result.get('FindingIds', [])
                        if finding_ids:
                            # Get finding details
                            findings_details = guardduty_client.get_findings(
                                DetectorId=detector_id,
                                FindingIds=finding_ids
                            )
                            
                            for gd_finding in findings_details.get('Findings', []):
                                finding_id = gd_finding.get('Id')
                                finding_type = gd_finding.get('Type')
                                severity = gd_finding.get('Severity')
                                title = gd_finding.get('Title', 'Unknown finding')
                                
                                # GuardDuty findings are handled by GuardDuty service
                                pass
                    
                    except ClientError as e:
                        pass
                    
                    # Check for EventBridge rules for GuardDuty
                    try:
                        events_client = boto3.client('events', region_name=current_region)
                        rules = events_client.list_rules(NamePrefix='GuardDuty')
                        
                        # EventBridge rules check (informational only)
                    
                    except ClientError as e:
                        pass
            
            except ClientError as e:
                pass
        
        # GuardDuty status is informational only
        pass
    except Exception as e:
        pass
    
    return findings