"""
CloudWatch Logs Scanner Module - Detects security issues with CloudWatch Logs
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan_cloudwatch_logs(region=None):
    """
    Scan CloudWatch Logs for security issues like:
    - Missing encryption
    - Missing log retention policies
    - Indefinite retention (cost concerns)
    - Excessive retention periods
    - Missing log metric filters for security events
    
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
        
        region_count = 0
        total_log_groups_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                pass
            logs_client = boto3.client('logs', region_name=current_region)
            
            # Get current time for age calculations
            current_time = datetime.now(timezone.utc)
            
            # List all log groups
            log_groups = []
            paginator = logs_client.get_paginator('describe_log_groups')
            
            for page in paginator.paginate():
                log_groups.extend(page.get('logGroups', []))
            
            log_groups_count = len(log_groups)
            
            if log_groups_count > 0:
                total_log_groups_count += log_groups_count
                print(f"  Found {log_groups_count} CloudWatch Log groups in {current_region}")
                
                for i, log_group in enumerate(log_groups, 1):
                    log_group_name = log_group.get('logGroupName')
                    log_group_arn = log_group.get('arn')
                    retention_days = log_group.get('retentionInDays')
                    kms_key_id = log_group.get('kmsKeyId')
                    creation_time = log_group.get('creationTime')
                    
                    # Convert creation time from milliseconds to datetime
                    if creation_time:
                        creation_time = datetime.fromtimestamp(creation_time / 1000, tz=timezone.utc)
                        days_since_creation = (current_time - creation_time).days
                    else:
                        days_since_creation = None
                    
                    # Print progress every 10 log groups or for the last one
                    if i % 10 == 0 or i == log_groups_count:
                        print(f"  Progress: {i}/{log_groups_count}")
                    
                    # Check if encryption is enabled
                    if not kms_key_id:
                        findings.append({
                            'ResourceType': 'CloudWatch Log Group',
                            'ResourceId': log_group_name,
                            'ResourceName': log_group_name,
                            'ResourceArn': log_group_arn,
                            'Region': current_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'Log group is not encrypted with KMS',
                            'Recommendation': 'Enable KMS encryption for sensitive log data'
                        })
                    
                    # Check if retention is set
                    if not retention_days:
                        findings.append({
                            'ResourceType': 'CloudWatch Log Group',
                            'ResourceId': log_group_name,
                            'ResourceName': log_group_name,
                            'ResourceArn': log_group_arn,
                            'Region': current_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'Log group has no retention policy (logs kept indefinitely)',
                            'Recommendation': 'Set appropriate retention period to control costs'
                        })
                    elif retention_days > 365:
                        findings.append({
                            'ResourceType': 'CloudWatch Log Group',
                            'ResourceId': log_group_name,
                            'ResourceName': log_group_name,
                            'ResourceArn': log_group_arn,
                            'RetentionDays': retention_days,
                            'Region': current_region,
                            'Risk': 'LOW',
                            'Issue': f'Log group has excessive retention period ({retention_days} days)',
                            'Recommendation': 'Review retention needs and consider reducing to control costs'
                        })
                    elif retention_days < 30 and 'security' in log_group_name.lower():
                        findings.append({
                            'ResourceType': 'CloudWatch Log Group',
                            'ResourceId': log_group_name,
                            'ResourceName': log_group_name,
                            'ResourceArn': log_group_arn,
                            'RetentionDays': retention_days,
                            'Region': current_region,
                            'Risk': 'MEDIUM',
                            'Issue': f'Security-related log group has short retention period ({retention_days} days)',
                            'Recommendation': 'Increase retention period for security logs to at least 90 days'
                        })
                    
                    # Check for recent activity in log group
                    try:
                        # Get the most recent log stream
                        streams = logs_client.describe_log_streams(
                            logGroupName=log_group_name,
                            orderBy='LastEventTime',
                            descending=True,
                            limit=1
                        )
                        
                        if not streams.get('logStreams'):
                            findings.append({
                                'ResourceType': 'CloudWatch Log Group',
                                'ResourceId': log_group_name,
                                'ResourceName': log_group_name,
                                'ResourceArn': log_group_arn,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': 'Log group has no log streams',
                                'Recommendation': 'Delete unused log groups to reduce clutter and costs'
                            })
                        else:
                            last_event_timestamp = streams['logStreams'][0].get('lastEventTimestamp')
                            if last_event_timestamp:
                                last_event_time = datetime.fromtimestamp(last_event_timestamp / 1000, tz=timezone.utc)
                                days_since_last_event = (current_time - last_event_time).days
                                
                                if days_since_last_event > 90:
                                    findings.append({
                                        'ResourceType': 'CloudWatch Log Group',
                                        'ResourceId': log_group_name,
                                        'ResourceName': log_group_name,
                                        'ResourceArn': log_group_arn,
                                        'DaysSinceLastEvent': days_since_last_event,
                                        'Region': current_region,
                                        'Risk': 'LOW',
                                        'Issue': f'Log group has no activity for {days_since_last_event} days',
                                        'Recommendation': 'Consider deleting inactive log groups to reduce costs'
                                    })
                    except ClientError as e:
                        # Skip if we can't check log streams
                        pass
                
                # Check for security-related metric filters
                try:
                    # Get all metric filters
                    metric_filters = []
                    filter_paginator = logs_client.get_paginator('describe_metric_filters')
                    
                    for page in filter_paginator.paginate():
                        metric_filters.extend(page.get('metricFilters', []))
                    
                    # Check for common security filters
                    security_filters = {
                        'root_login': False,
                        'unauthorized_api': False,
                        'iam_changes': False,
                        'cloudtrail_changes': False,
                        'console_login_failure': False,
                        'network_acl_changes': False,
                        'security_group_changes': False
                    }
                    
                    for metric_filter in metric_filters:
                        filter_pattern = metric_filter.get('filterPattern', '').lower()
                        
                        if 'root' in filter_pattern and 'eventtype' in filter_pattern:
                            security_filters['root_login'] = True
                        
                        if 'unauthorized' in filter_pattern and 'api' in filter_pattern:
                            security_filters['unauthorized_api'] = True
                        
                        if ('iam' in filter_pattern and 'create' in filter_pattern) or \
                           ('iam' in filter_pattern and 'delete' in filter_pattern) or \
                           ('iam' in filter_pattern and 'update' in filter_pattern):
                            security_filters['iam_changes'] = True
                        
                        if 'cloudtrail' in filter_pattern and ('update' in filter_pattern or 'delete' in filter_pattern):
                            security_filters['cloudtrail_changes'] = True
                        
                        if 'consolelogin' in filter_pattern.replace(' ', '') and 'failure' in filter_pattern:
                            security_filters['console_login_failure'] = True
                        
                        if 'nacl' in filter_pattern.replace('-', '') or ('network' in filter_pattern and 'acl' in filter_pattern):
                            security_filters['network_acl_changes'] = True
                        
                        if 'securitygroup' in filter_pattern.replace(' ', '') or ('security' in filter_pattern and 'group' in filter_pattern):
                            security_filters['security_group_changes'] = True
                    
                    # Report missing security filters
                    missing_filters = [k for k, v in security_filters.items() if not v]
                    if missing_filters:
                        findings.append({
                            'ResourceType': 'CloudWatch Logs',
                            'ResourceId': 'metric_filters',
                            'ResourceName': 'Security Metric Filters',
                            'Region': current_region,
                            'Risk': 'MEDIUM',
                            'Issue': f'Missing security-related metric filters: {", ".join(missing_filters)}',
                            'Recommendation': 'Create metric filters and alarms for security-related events'
                        })
                
                except ClientError as e:
                    pass
            
                print(f"  No CloudWatch Log groups found in {current_region}")
    except Exception as e:
        pass
    
    return findings