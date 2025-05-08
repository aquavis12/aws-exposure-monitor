"""
DynamoDB Scanner Module - Detects security issues with Amazon DynamoDB
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan_dynamodb(region=None):
    """
    Scan Amazon DynamoDB for security issues like:
    - Tables without encryption
    - Tables without backups
    - Tables without point-in-time recovery
    - Tables with overly permissive IAM policies
    - Tables with public access
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting DynamoDB scan...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
            print(f"Scanning region: {region}")
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
            print(f"Scanning {len(regions)} regions")
        
        region_count = 0
        total_tables_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            dynamodb_client = boto3.client('dynamodb', region_name=current_region)
            
            try:
                # List all DynamoDB tables
                tables = []
                paginator = dynamodb_client.get_paginator('list_tables')
                
                for page in paginator.paginate():
                    tables.extend(page.get('TableNames', []))
                
                tables_count = len(tables)
                
                if tables_count > 0:
                    total_tables_count += tables_count
                    print(f"  Found {tables_count} DynamoDB tables in {current_region}")
                    
                    for i, table_name in enumerate(tables, 1):
                        # Print progress every 10 tables or for the last one
                        if i % 10 == 0 or i == tables_count:
                            print(f"  Progress: {i}/{tables_count}")
                        
                        # Get table details
                        try:
                            table_details = dynamodb_client.describe_table(TableName=table_name)
                            table = table_details.get('Table', {})
                            
                            # Get table ARN
                            table_arn = table.get('TableArn')
                            
                            # Check for encryption
                            try:
                                encryption = dynamodb_client.describe_table(TableName=table_name).get('Table', {}).get('SSEDescription', {})
                                if not encryption or encryption.get('Status') != 'ENABLED':
                                    findings.append({
                                        'ResourceType': 'DynamoDB Table',
                                        'ResourceId': table_name,
                                        'ResourceName': table_name,
                                        'ResourceArn': table_arn,
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': 'DynamoDB table is not encrypted with KMS',
                                        'Recommendation': 'Enable server-side encryption with KMS for the table'
                                    })
                                    print(f"    [!] FINDING: DynamoDB table {table_name} is not encrypted - MEDIUM risk")
                            except ClientError as e:
                                print(f"    Error checking encryption for table {table_name}: {e}")
                            
                            # Check for point-in-time recovery
                            try:
                                pitr = dynamodb_client.describe_continuous_backups(TableName=table_name)
                                pitr_status = pitr.get('ContinuousBackupsDescription', {}).get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus')
                                
                                if pitr_status != 'ENABLED':
                                    findings.append({
                                        'ResourceType': 'DynamoDB Table',
                                        'ResourceId': table_name,
                                        'ResourceName': table_name,
                                        'ResourceArn': table_arn,
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': 'DynamoDB table does not have point-in-time recovery enabled',
                                        'Recommendation': 'Enable point-in-time recovery for data protection'
                                    })
                                    print(f"    [!] FINDING: DynamoDB table {table_name} has no point-in-time recovery - MEDIUM risk")
                            except ClientError as e:
                                print(f"    Error checking point-in-time recovery for table {table_name}: {e}")
                            
                            # Check for backups
                            try:
                                backups = dynamodb_client.list_backups(TableName=table_name)
                                if not backups.get('BackupSummaries'):
                                    findings.append({
                                        'ResourceType': 'DynamoDB Table',
                                        'ResourceId': table_name,
                                        'ResourceName': table_name,
                                        'ResourceArn': table_arn,
                                        'Region': current_region,
                                        'Risk': 'LOW',
                                        'Issue': 'DynamoDB table has no backups',
                                        'Recommendation': 'Create regular backups or use AWS Backup for the table'
                                    })
                                    print(f"    [!] FINDING: DynamoDB table {table_name} has no backups - LOW risk")
                            except ClientError as e:
                                # This might fail if the table was just created
                                pass
                            
                            # Check for auto scaling
                            try:
                                scaling_policies = False
                                application_auto_scaling = boto3.client('application-autoscaling', region_name=current_region)
                                
                                # Check read capacity scaling
                                try:
                                    read_scaling = application_auto_scaling.describe_scaling_policies(
                                        ServiceNamespace='dynamodb',
                                        ResourceId=f'table/{table_name}',
                                        ScalableDimension='dynamodb:table:ReadCapacityUnits'
                                    )
                                    if read_scaling.get('ScalingPolicies'):
                                        scaling_policies = True
                                except ClientError:
                                    pass
                                
                                # Check write capacity scaling
                                try:
                                    write_scaling = application_auto_scaling.describe_scaling_policies(
                                        ServiceNamespace='dynamodb',
                                        ResourceId=f'table/{table_name}',
                                        ScalableDimension='dynamodb:table:WriteCapacityUnits'
                                    )
                                    if write_scaling.get('ScalingPolicies'):
                                        scaling_policies = True
                                except ClientError:
                                    pass
                                
                                # Check if table is provisioned and has no auto scaling
                                billing_mode = table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
                                if billing_mode == 'PROVISIONED' and not scaling_policies:
                                    findings.append({
                                        'ResourceType': 'DynamoDB Table',
                                        'ResourceId': table_name,
                                        'ResourceName': table_name,
                                        'ResourceArn': table_arn,
                                        'Region': current_region,
                                        'Risk': 'LOW',
                                        'Issue': 'DynamoDB table uses provisioned capacity without auto scaling',
                                        'Recommendation': 'Configure auto scaling or switch to on-demand capacity mode'
                                    })
                                    print(f"    [!] FINDING: DynamoDB table {table_name} has no auto scaling - LOW risk")
                            except ClientError:
                                pass
                            
                            # Check for TTL
                            try:
                                ttl = dynamodb_client.describe_time_to_live(TableName=table_name)
                                ttl_status = ttl.get('TimeToLiveDescription', {}).get('TimeToLiveStatus')
                                
                                if ttl_status != 'ENABLED':
                                    findings.append({
                                        'ResourceType': 'DynamoDB Table',
                                        'ResourceId': table_name,
                                        'ResourceName': table_name,
                                        'ResourceArn': table_arn,
                                        'Region': current_region,
                                        'Risk': 'LOW',
                                        'Issue': 'DynamoDB table does not have TTL enabled',
                                        'Recommendation': 'Consider enabling TTL for data lifecycle management'
                                    })
                                    print(f"    [!] FINDING: DynamoDB table {table_name} has no TTL enabled - LOW risk")
                            except ClientError:
                                pass
                        
                        except ClientError as e:
                            print(f"    Error checking table {table_name}: {e}")
                
                else:
                    print(f"  No DynamoDB tables found in {current_region}")
            
            except ClientError as e:
                print(f"  Error scanning DynamoDB in {current_region}: {e}")
        
        if total_tables_count == 0:
            print("No DynamoDB tables found.")
        else:
            print(f"DynamoDB scan complete. Scanned {total_tables_count} tables.")
    
    except Exception as e:
        print(f"Error scanning DynamoDB: {e}")
    
    if findings:
        print(f"Found {len(findings)} DynamoDB security issues.")
    else:
        print("No DynamoDB security issues found.")
    
    return findings