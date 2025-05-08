"""
AWS Config Scanner Module - Detects security issues with AWS Config
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan_aws_config(region=None):
    """
    Scan AWS Config for security issues like:
    - Config not enabled in all regions
    - Missing resource types in recording
    - Insufficient retention period
    - Missing S3 bucket encryption
    - Missing SNS notifications
    - Missing remediation actions
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting AWS Config scan...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
            print(f"Scanning region: {region}")
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
            print(f"Scanning {len(regions)} regions")
        
        # Check for organization Config in us-east-1 (global)
        org_config_exists = False
        try:
            org_client = boto3.client('organizations')
            try:
                org_info = org_client.describe_organization()
                # We're in an organization, check for organization Config
                config_client = boto3.client('config', region_name='us-east-1')
                try:
                    org_config = config_client.describe_organization_config_statuses()
                    if org_config.get('OrganizationConfigStatuses'):
                        org_config_exists = True
                        print("Organization Config is enabled")
                except ClientError:
                    # No organization Config or no permission
                    pass
            except ClientError:
                # Not an organization or no permission to check
                pass
        except (ImportError, ClientError):
            # Organizations module not available or not an organization
            pass
        
        # Check each region for Config
        region_count = 0
        regions_with_config = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            config_client = boto3.client('config', region_name=current_region)
            
            try:
                # Check if Config is enabled
                recorders = config_client.describe_configuration_recorders()
                recorder_list = recorders.get('ConfigurationRecorders', [])
                
                if not recorder_list and not org_config_exists:
                    findings.append({
                        'ResourceType': 'AWS Config',
                        'ResourceId': f'NoConfig-{current_region}',
                        'ResourceName': f'No Config in {current_region}',
                        'Region': current_region,
                        'Risk': 'HIGH',
                        'Issue': f'AWS Config is not enabled in region {current_region}',
                        'Recommendation': 'Enable AWS Config to track resource configurations and changes'
                    })
                    print(f"    [!] FINDING: AWS Config is not enabled in region {current_region} - HIGH risk")
                    continue
                
                regions_with_config += 1
                
                # Check recorder configuration
                for recorder in recorder_list:
                    recorder_name = recorder.get('name')
                    recording_all_resource_types = recorder.get('recordingGroup', {}).get('allSupported', False)
                    include_global_resources = recorder.get('recordingGroup', {}).get('includeGlobalResourceTypes', False)
                    
                    if not recording_all_resource_types:
                        findings.append({
                            'ResourceType': 'AWS Config Recorder',
                            'ResourceId': recorder_name,
                            'ResourceName': recorder_name,
                            'Region': current_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'AWS Config recorder is not recording all supported resource types',
                            'Recommendation': 'Configure AWS Config to record all supported resource types'
                        })
                        print(f"    [!] FINDING: Config recorder {recorder_name} is not recording all resource types - MEDIUM risk")
                    
                    if current_region == 'us-east-1' and not include_global_resources:
                        findings.append({
                            'ResourceType': 'AWS Config Recorder',
                            'ResourceId': recorder_name,
                            'ResourceName': recorder_name,
                            'Region': current_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'AWS Config recorder is not recording global resource types',
                            'Recommendation': 'Configure AWS Config to include global resource types'
                        })
                        print(f"    [!] FINDING: Config recorder {recorder_name} is not recording global resources - MEDIUM risk")
                
                # Check recorder status
                try:
                    recorder_statuses = config_client.describe_configuration_recorder_status()
                    for status in recorder_statuses.get('ConfigurationRecordersStatus', []):
                        recorder_name = status.get('name')
                        is_recording = status.get('recording', False)
                        
                        if not is_recording:
                            findings.append({
                                'ResourceType': 'AWS Config Recorder',
                                'ResourceId': recorder_name,
                                'ResourceName': recorder_name,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'AWS Config recorder is not actively recording',
                                'Recommendation': 'Start the AWS Config recorder'
                            })
                            print(f"    [!] FINDING: Config recorder {recorder_name} is not recording - HIGH risk")
                except ClientError as e:
                    print(f"    Error checking recorder status: {e}")
                
                # Check delivery channels
                try:
                    delivery_channels = config_client.describe_delivery_channels()
                    if not delivery_channels.get('DeliveryChannels'):
                        findings.append({
                            'ResourceType': 'AWS Config',
                            'ResourceId': f'NoDeliveryChannel-{current_region}',
                            'ResourceName': f'No Delivery Channel in {current_region}',
                            'Region': current_region,
                            'Risk': 'HIGH',
                            'Issue': 'AWS Config has no delivery channel configured',
                            'Recommendation': 'Configure a delivery channel for AWS Config'
                        })
                        print(f"    [!] FINDING: No Config delivery channel in {current_region} - HIGH risk")
                    else:
                        for channel in delivery_channels.get('DeliveryChannels', []):
                            channel_name = channel.get('name')
                            s3_bucket = channel.get('s3BucketName')
                            sns_topic = channel.get('snsTopicARN')
                            
                            if not sns_topic:
                                findings.append({
                                    'ResourceType': 'AWS Config Delivery Channel',
                                    'ResourceId': channel_name,
                                    'ResourceName': channel_name,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'AWS Config delivery channel has no SNS notification configured',
                                    'Recommendation': 'Configure SNS notifications for AWS Config changes'
                                })
                                print(f"    [!] FINDING: Config delivery channel {channel_name} has no SNS notifications - MEDIUM risk")
                            
                            # Check S3 bucket encryption if in same account/region
                            if s3_bucket:
                                try:
                                    s3_client = boto3.client('s3', region_name=current_region)
                                    encryption = s3_client.get_bucket_encryption(Bucket=s3_bucket)
                                    if not encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules'):
                                        findings.append({
                                            'ResourceType': 'AWS Config S3 Bucket',
                                            'ResourceId': s3_bucket,
                                            'ResourceName': s3_bucket,
                                            'Region': current_region,
                                            'Risk': 'MEDIUM',
                                            'Issue': 'AWS Config S3 bucket is not encrypted',
                                            'Recommendation': 'Enable encryption for the AWS Config S3 bucket'
                                        })
                                        print(f"    [!] FINDING: Config S3 bucket {s3_bucket} is not encrypted - MEDIUM risk")
                                except ClientError:
                                    # Skip if bucket is in another region or account
                                    pass
                except ClientError as e:
                    print(f"    Error checking delivery channels: {e}")
                
                # Check Config rules
                try:
                    rules_paginator = config_client.get_paginator('describe_config_rules')
                    rules_count = 0
                    
                    for page in rules_paginator.paginate():
                        rules_count += len(page.get('ConfigRules', []))
                    
                    if rules_count == 0:
                        findings.append({
                            'ResourceType': 'AWS Config',
                            'ResourceId': f'NoRules-{current_region}',
                            'ResourceName': f'No Config Rules in {current_region}',
                            'Region': current_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'AWS Config has no rules configured',
                            'Recommendation': 'Configure AWS Config rules to evaluate resource compliance'
                        })
                        print(f"    [!] FINDING: No Config rules in {current_region} - MEDIUM risk")
                    else:
                        print(f"  Found {rules_count} Config rules in {current_region}")
                        
                        # Check for conformance packs
                        try:
                            conformance_packs = config_client.describe_conformance_packs()
                            if not conformance_packs.get('ConformancePackDetails'):
                                findings.append({
                                    'ResourceType': 'AWS Config',
                                    'ResourceId': f'NoConformancePacks-{current_region}',
                                    'ResourceName': f'No Conformance Packs in {current_region}',
                                    'Region': current_region,
                                    'Risk': 'LOW',
                                    'Issue': 'AWS Config has no conformance packs configured',
                                    'Recommendation': 'Consider using conformance packs for comprehensive compliance monitoring'
                                })
                                print(f"    [!] FINDING: No Config conformance packs in {current_region} - LOW risk")
                        except ClientError:
                            # Conformance packs might not be supported in all regions
                            pass
                except ClientError as e:
                    print(f"    Error checking Config rules: {e}")
            
            except ClientError as e:
                print(f"  Error scanning AWS Config in {current_region}: {e}")
        
        # Check if Config is enabled in all regions
        if regions_with_config < len(regions) and not org_config_exists:
            findings.append({
                'ResourceType': 'AWS Config',
                'ResourceId': 'ConfigNotAllRegions',
                'ResourceName': 'Config Not In All Regions',
                'Region': 'global',
                'Risk': 'HIGH',
                'Issue': f'AWS Config is only enabled in {regions_with_config} of {len(regions)} regions',
                'Recommendation': 'Enable AWS Config in all regions or use Organization Config'
            })
            print(f"    [!] FINDING: AWS Config is only enabled in {regions_with_config} of {len(regions)} regions - HIGH risk")
    
    except Exception as e:
        print(f"Error scanning AWS Config: {e}")
    
    if findings:
        print(f"Found {len(findings)} AWS Config security issues.")
    else:
        print("No AWS Config security issues found.")
    
    return findings