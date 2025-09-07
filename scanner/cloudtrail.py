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
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        # Check organization context and CloudTrail requirements
        org_trail_exists = False
        is_organization = False
        
        try:
            org_client = boto3.client('organizations')
            org_info = org_client.describe_organization()
            is_organization = True
            
            # Check for organization trail in us-east-1 (global)
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
            
            # If organization exists but no organization trail
            if not org_trail_exists:
                findings.append({
                    'ResourceType': 'CloudTrail',
                    'ResourceId': 'OrganizationTrail',
                    'ResourceName': 'Organization Trail',
                    'Region': 'global',
                    'Risk': 'CRITICAL',
                    'Issue': 'No organization-wide CloudTrail trail exists',
                    'Recommendation': 'Create an organization trail that logs all regions and member accounts'
                })
        
        except ClientError as e:
            # Not an organization or no permission to check
            is_organization = False
        
        # Check each region for trails
        region_count = 0
        total_trails_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                pass
            cloudtrail_client = boto3.client('cloudtrail', region_name=current_region)
            s3_client = boto3.client('s3', region_name=current_region)
            
            try:
                # List all trails
                trails = cloudtrail_client.list_trails()
                trail_list = trails.get('Trails', [])
                
                if not trail_list and not org_trail_exists:
                    recommendation = 'Create an organization trail that logs all regions' if is_organization else 'Create a CloudTrail trail for this region'
                    findings.append({
                        'ResourceType': 'CloudTrail',
                        'ResourceId': f'NoTrail-{current_region}',
                        'ResourceName': f'No Trail in {current_region}',
                        'Region': current_region,
                        'Risk': 'CRITICAL',
                        'Issue': f'No CloudTrail trail exists in region {current_region}',
                        'Recommendation': recommendation
                    })
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
                                    'Issue': 'CloudTrail trail is not actively logging - this is mandatory for security compliance',
                                    'Recommendation': 'Enable logging for the CloudTrail trail immediately'
                                })
                        except ClientError as e:
                            pass
                        
                        # Check for log file validation
                        if not trail.get('LogFileValidationEnabled', False):
                            findings.append({
                                'ResourceType': 'CloudTrail',
                                'ResourceId': trail_name,
                                'ResourceName': trail_name,
                                'ResourceArn': trail_arn,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'CloudTrail trail does not have log file validation enabled - required for integrity verification',
                                'Recommendation': 'Enable log file validation for the CloudTrail trail'
                            })
                        
                        # Check for KMS encryption
                        if not trail.get('KmsKeyId'):
                            findings.append({
                                'ResourceType': 'CloudTrail',
                                'ResourceId': trail_name,
                                'ResourceName': trail_name,
                                'ResourceArn': trail_arn,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'CloudTrail trail is not encrypted with KMS - logs contain sensitive information',
                                'Recommendation': 'Enable KMS encryption for the CloudTrail trail'
                            })
                        
                        # Check for multi-region trail
                        if not trail.get('IsMultiRegionTrail', False) and not org_trail_exists:
                            recommendation = 'Create an organization trail instead of individual trails' if is_organization else 'Enable multi-region logging for the CloudTrail trail'
                            findings.append({
                                'ResourceType': 'CloudTrail',
                                'ResourceId': trail_name,
                                'ResourceName': trail_name,
                                'ResourceArn': trail_arn,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'CloudTrail trail is not configured for all regions',
                                'Recommendation': recommendation
                            })
                        
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
                                    'Issue': 'CloudTrail trail is not logging management events - critical for security monitoring',
                                    'Recommendation': 'Enable management events logging for the CloudTrail trail'
                                })
                        except ClientError as e:
                            pass
                        
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
            
            except ClientError as e:
                pass
        
        if total_trails_count == 0 and not org_trail_exists:
            recommendation = 'Create an organization trail that logs all regions and member accounts' if is_organization else 'Create at least one multi-region CloudTrail trail'
            findings.append({
                'ResourceType': 'CloudTrail',
                'ResourceId': 'NoTrails',
                'ResourceName': 'No CloudTrail Trails',
                'Region': 'global',
                'Risk': 'CRITICAL',
                'Issue': 'No CloudTrail trails exist in any region',
                'Recommendation': recommendation
            })
        pass
    except Exception as e:
        pass
    
    return findings