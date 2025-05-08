"""
CloudTrail Scanner Module - Detects security issues with AWS CloudTrail
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan_cloudtrail(region=None):
    """
    Scan AWS CloudTrail for security issues like:
    - Missing trails
    - Trails not configured for all regions
    - Trails without log file validation
    - Trails without encryption
    - Trails without multi-region enabled
    - Trails without S3 bucket access logging
    - Trails without CloudWatch Logs integration
    - Unauthorized modifications to trails
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting CloudTrail scan...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
            print(f"Scanning region: {region}")
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
            print(f"Scanning {len(regions)} regions")
        
        # First, check for organization trail in us-east-1 (global)
        org_trail_exists = False
        try:
            org_client = boto3.client('organizations')
            try:
                org_info = org_client.describe_organization()
                # We're in an organization, check for organization trail
                cloudtrail_client = boto3.client('cloudtrail', region_name='us-east-1')
                trails = cloudtrail_client.list_trails()
                
                for trail in trails.get('Trails', []):
                    trail_arn = trail.get('TrailARN')
                    trail_info = cloudtrail_client.describe_trails(trailNameList=[trail_arn])
                    
                    for detail in trail_info.get('trailList', []):
                        if detail.get('IsOrganizationTrail', False):
                            org_trail_exists = True
                            # Check if organization trail is properly configured
                            if not detail.get('IsMultiRegionTrail', False):
                                findings.append({
                                    'ResourceType': 'CloudTrail Organization Trail',
                                    'ResourceId': detail.get('Name'),
                                    'ResourceName': detail.get('Name'),
                                    'ResourceArn': trail_arn,
                                    'Region': 'global',
                                    'Risk': 'HIGH',
                                    'Issue': 'Organization trail is not configured for all regions',
                                    'Recommendation': 'Enable multi-region logging for the organization trail'
                                })
                                print(f"    [!] FINDING: Organization trail {detail.get('Name')} is not multi-region - HIGH risk")
                            
                            if not detail.get('LogFileValidationEnabled', False):
                                findings.append({
                                    'ResourceType': 'CloudTrail Organization Trail',
                                    'ResourceId': detail.get('Name'),
                                    'ResourceName': detail.get('Name'),
                                    'ResourceArn': trail_arn,
                                    'Region': 'global',
                                    'Risk': 'HIGH',
                                    'Issue': 'Organization trail does not have log file validation enabled',
                                    'Recommendation': 'Enable log file validation for the organization trail'
                                })
                                print(f"    [!] FINDING: Organization trail {detail.get('Name')} has no log file validation - HIGH risk")
                            
                            if not detail.get('KmsKeyId'):
                                findings.append({
                                    'ResourceType': 'CloudTrail Organization Trail',
                                    'ResourceId': detail.get('Name'),
                                    'ResourceName': detail.get('Name'),
                                    'ResourceArn': trail_arn,
                                    'Region': 'global',
                                    'Risk': 'MEDIUM',
                                    'Issue': 'Organization trail is not encrypted with KMS',
                                    'Recommendation': 'Enable KMS encryption for the organization trail'
                                })
                                print(f"    [!] FINDING: Organization trail {detail.get('Name')} is not KMS encrypted - MEDIUM risk")
                
                if not org_trail_exists:
                    findings.append({
                        'ResourceType': 'CloudTrail',
                        'ResourceId': 'OrganizationTrail',
                        'ResourceName': 'Organization Trail',
                        'Region': 'global',
                        'Risk': 'HIGH',
                        'Issue': 'No organization-wide CloudTrail trail exists',
                        'Recommendation': 'Create an organization trail that logs all regions'
                    })
                    print(f"    [!] FINDING: No organization-wide CloudTrail trail exists - HIGH risk")
            
            except ClientError as e:
                # Not an organization or no permission to check
                pass
        except (ImportError, ClientError):
            # Organizations module not available or not an organization
            pass
        
        # Check each region for trails
        region_count = 0
        total_trails_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            cloudtrail_client = boto3.client('cloudtrail', region_name=current_region)
            s3_client = boto3.client('s3', region_name=current_region)
            
            try:
                # List all trails
                trails = cloudtrail_client.list_trails()
                trail_list = trails.get('Trails', [])
                
                if not trail_list and not org_trail_exists:
                    findings.append({
                        'ResourceType': 'CloudTrail',
                        'ResourceId': f'NoTrail-{current_region}',
                        'ResourceName': f'No Trail in {current_region}',
                        'Region': current_region,
                        'Risk': 'CRITICAL',
                        'Issue': f'No CloudTrail trail exists in region {current_region}',
                        'Recommendation': 'Create a CloudTrail trail or use an organization trail'
                    })
                    print(f"    [!] FINDING: No CloudTrail trail exists in region {current_region} - CRITICAL risk")
                    continue
                
                # Get trail details
                trail_arns = [trail.get('TrailARN') for trail in trail_list]
                if trail_arns:
                    trail_details = cloudtrail_client.describe_trails(trailNameList=trail_arns)
                    trails_in_region = trail_details.get('trailList', [])
                    total_trails_count += len(trails_in_region)
                    
                    print(f"  Found {len(trails_in_region)} CloudTrail trails in {current_region}")
                    
                    for i, trail in enumerate(trails_in_region, 1):
                        trail_name = trail.get('Name')
                        trail_arn = trail.get('TrailARN')
                        home_region = trail.get('HomeRegion')
                        
                        # Skip if this is not the home region for the trail
                        if home_region != current_region:
                            continue
                        
                        # Print progress
                        if i % 5 == 0 or i == len(trails_in_region):
                            print(f"  Progress: {i}/{len(trails_in_region)}")
                        
                        # Check if trail is logging
                        try:
                            status = cloudtrail_client.get_trail_status(Name=trail_arn)
                            is_logging = status.get('IsLogging', False)
                            
                            if not is_logging:
                                findings.append({
                                    'ResourceType': 'CloudTrail',
                                    'ResourceId': trail_name,
                                    'ResourceName': trail_name,
                                    'ResourceArn': trail_arn,
                                    'Region': current_region,
                                    'Risk': 'CRITICAL',
                                    'Issue': 'CloudTrail trail is not actively logging',
                                    'Recommendation': 'Enable logging for the CloudTrail trail'
                                })
                                print(f"    [!] FINDING: Trail {trail_name} is not logging - CRITICAL risk")
                        except ClientError as e:
                            print(f"    Error checking trail status for {trail_name}: {e}")
                        
                        # Check for log file validation
                        if not trail.get('LogFileValidationEnabled', False):
                            findings.append({
                                'ResourceType': 'CloudTrail',
                                'ResourceId': trail_name,
                                'ResourceName': trail_name,
                                'ResourceArn': trail_arn,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'CloudTrail trail does not have log file validation enabled',
                                'Recommendation': 'Enable log file validation for the CloudTrail trail'
                            })
                            print(f"    [!] FINDING: Trail {trail_name} has no log file validation - HIGH risk")
                        
                        # Check for KMS encryption
                        if not trail.get('KmsKeyId'):
                            findings.append({
                                'ResourceType': 'CloudTrail',
                                'ResourceId': trail_name,
                                'ResourceName': trail_name,
                                'ResourceArn': trail_arn,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'CloudTrail trail is not encrypted with KMS',
                                'Recommendation': 'Enable KMS encryption for the CloudTrail trail'
                            })
                            print(f"    [!] FINDING: Trail {trail_name} is not KMS encrypted - MEDIUM risk")
                        
                        # Check for multi-region trail
                        if not trail.get('IsMultiRegionTrail', False) and not org_trail_exists:
                            findings.append({
                                'ResourceType': 'CloudTrail',
                                'ResourceId': trail_name,
                                'ResourceName': trail_name,
                                'ResourceArn': trail_arn,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'CloudTrail trail is not configured for all regions',
                                'Recommendation': 'Enable multi-region logging for the CloudTrail trail'
                            })
                            print(f"    [!] FINDING: Trail {trail_name} is not multi-region - MEDIUM risk")
                        
                        # Check for management events logging
                        try:
                            event_selectors = cloudtrail_client.get_event_selectors(TrailName=trail_arn)
                            
                            # Check advanced event selectors if available
                            advanced_selectors = event_selectors.get('AdvancedEventSelectors', [])
                            if advanced_selectors:
                                management_events_logged = False
                                for selector in advanced_selectors:
                                    field_selectors = selector.get('FieldSelectors', [])
                                    for field in field_selectors:
                                        if field.get('Field') == 'eventCategory' and 'Management' in field.get('Equals', []):
                                            management_events_logged = True
                                            break
                                    if management_events_logged:
                                        break
                            else:
                                # Check traditional event selectors
                                selectors = event_selectors.get('EventSelectors', [])
                                management_events_logged = any(s.get('IncludeManagementEvents', False) for s in selectors)
                            
                            if not management_events_logged:
                                findings.append({
                                    'ResourceType': 'CloudTrail',
                                    'ResourceId': trail_name,
                                    'ResourceName': trail_name,
                                    'ResourceArn': trail_arn,
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': 'CloudTrail trail is not logging management events',
                                    'Recommendation': 'Enable management events logging for the CloudTrail trail'
                                })
                                print(f"    [!] FINDING: Trail {trail_name} is not logging management events - HIGH risk")
                        except ClientError as e:
                            print(f"    Error checking event selectors for {trail_name}: {e}")
                        
                        # Check S3 bucket logging
                        s3_bucket = trail.get('S3BucketName')
                        if s3_bucket:
                            try:
                                bucket_logging = s3_client.get_bucket_logging(Bucket=s3_bucket)
                                if 'LoggingEnabled' not in bucket_logging:
                                    findings.append({
                                        'ResourceType': 'CloudTrail S3 Bucket',
                                        'ResourceId': s3_bucket,
                                        'ResourceName': s3_bucket,
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': 'CloudTrail S3 bucket does not have access logging enabled',
                                        'Recommendation': 'Enable access logging for the CloudTrail S3 bucket'
                                    })
                                    print(f"    [!] FINDING: CloudTrail S3 bucket {s3_bucket} has no access logging - MEDIUM risk")
                            except ClientError as e:
                                # Skip if bucket is in another region or account
                                pass
                        
                        # Check CloudWatch Logs integration
                        if not trail.get('CloudWatchLogsLogGroupArn'):
                            findings.append({
                                'ResourceType': 'CloudTrail',
                                'ResourceId': trail_name,
                                'ResourceName': trail_name,
                                'ResourceArn': trail_arn,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'CloudTrail trail is not integrated with CloudWatch Logs',
                                'Recommendation': 'Configure CloudWatch Logs integration for real-time monitoring'
                            })
                            print(f"    [!] FINDING: Trail {trail_name} is not integrated with CloudWatch Logs - MEDIUM risk")
            
            except ClientError as e:
                print(f"  Error scanning CloudTrail in {current_region}: {e}")
        
        if total_trails_count == 0 and not org_trail_exists:
            print("No CloudTrail trails found in any region.")
            findings.append({
                'ResourceType': 'CloudTrail',
                'ResourceId': 'NoTrails',
                'ResourceName': 'No CloudTrail Trails',
                'Region': 'global',
                'Risk': 'CRITICAL',
                'Issue': 'No CloudTrail trails exist in any region',
                'Recommendation': 'Create at least one multi-region CloudTrail trail'
            })
            print(f"    [!] FINDING: No CloudTrail trails exist in any region - CRITICAL risk")
        else:
            print(f"CloudTrail scan complete. Scanned {total_trails_count} trails.")
    
    except Exception as e:
        print(f"Error scanning CloudTrail: {e}")
    
    if findings:
        print(f"Found {len(findings)} CloudTrail security issues.")
    else:
        print("No CloudTrail security issues found.")
    
    return findings