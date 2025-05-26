"""
AWS Secrets Scanner Module - Detects hardcoded secrets, API keys, and credentials in AWS resources
"""
import re
import boto3
from botocore.exceptions import ClientError
import base64
import json

# Regex patterns for detecting secrets
SECRET_PATTERNS = [
    # AWS Access Keys
    (r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])', 'Possible AWS Secret Key'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
    # API Keys
    (r'api[_-]?key[_-]?=\s*[\'\"][0-9a-zA-Z]{32,45}[\'\"]', 'API Key'),
    (r'key[_-]?=\s*[\'\"][0-9a-zA-Z]{32,45}[\'\"]', 'Possible API Key'),
    # Database connection strings
    (r'(?i)(?:password|passwd|pwd)[\s]*=[\s]*[\'\"][^\'\"]{8,}[\'\"]', 'Database Password'),
    (r'(?i)(?:user|username)[\s]*=[\s]*[\'\"][^\'\"]{3,}[\'\"][\s]*(?:password|passwd|pwd)[\s]*=[\s]*[\'\"][^\'\"]{8,}[\'\"]', 'Database Credentials'),
    # Connection strings
    (r'(?i)(?:mongodb|postgresql|mysql|oracle|jdbc|odbc):.*(?:password|passwd|pwd)[\s]*=[\s]*[^;]*', 'Database Connection String'),
    # JWT tokens
    (r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', 'JWT Token'),
    # Private keys
    (r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----[^-]*-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', 'Private Key'),
    # Generic secrets
    (r'(?i)secret[\s]*=[\s]*[\'\"][^\'\"]{8,}[\'\"]', 'Secret'),
    (r'(?i)token[\s]*=[\s]*[\'\"][^\'\"]{8,}[\'\"]', 'Token'),
]

def scan_s3_for_secrets(region=None):
    """
    Scan S3 buckets for files containing secrets
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing findings
    """
    findings = []
    
    print("Starting S3 secrets scan...")
    
    # S3 is a global service, but we can filter by region
    s3_client = boto3.client('s3')
    
    try:
        # Get all buckets
        response = s3_client.list_buckets()
        all_buckets = response['Buckets']
        
        # Filter buckets by region if specified
        if region:
            buckets = []
            for bucket in all_buckets:
                bucket_name = bucket['Name']
                try:
                    location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location_response.get('LocationConstraint') or 'us-east-1'
                    if bucket_region == region:
                        buckets.append(bucket)
                except Exception:
                    # Skip buckets we can't determine the region for
                    pass
            print(f"Found {len(buckets)} S3 buckets in region {region}")
        else:
            buckets = all_buckets
            print(f"Found {len(buckets)} S3 buckets across all regions")
        
        # Scan a sample of objects from each bucket
        for i, bucket in enumerate(buckets, 1):
            bucket_name = bucket['Name']
            print(f"[{i}/{len(buckets)}] Scanning bucket: {bucket_name} for secrets")
            
            try:
                # Get bucket location
                location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = location_response.get('LocationConstraint') or 'us-east-1'
                
                # List objects in the bucket (limit to 100 for performance)
                objects = []
                paginator = s3_client.get_paginator('list_objects_v2')
                pages = paginator.paginate(Bucket=bucket_name, MaxKeys=100)
                
                for page in pages:
                    if 'Contents' in page:
                        objects.extend(page['Contents'])
                        if len(objects) >= 100:  # Limit to 100 objects per bucket
                            break
                
                # Filter for text-based files that might contain secrets
                text_extensions = ['.txt', '.json', '.yaml', '.yml', '.xml', '.csv', '.ini', '.conf', '.config', 
                                  '.properties', '.env', '.js', '.py', '.sh', '.bat', '.ps1', '.php', '.java', 
                                  '.rb', '.pl', '.c', '.cpp', '.h', '.cs', '.go', '.ts', '.html', '.htm', '.css']
                
                text_objects = [obj for obj in objects if any(obj['Key'].lower().endswith(ext) for ext in text_extensions)]
                
                # Sample up to 20 text objects per bucket
                sample_objects = text_objects[:20]
                
                for obj in sample_objects:
                    key = obj['Key']
                    if obj['Size'] > 5 * 1024 * 1024:  # Skip files larger than 5MB
                        print(f"  Skipping large file: {key} ({obj['Size']/1024/1024:.2f} MB)")
                        continue
                    
                    try:
                        # Get the object content
                        response = s3_client.get_object(Bucket=bucket_name, Key=key)
                        content = response['Body'].read().decode('utf-8', errors='ignore')
                        
                        # Scan for secrets
                        for pattern, secret_type in SECRET_PATTERNS:
                            matches = re.findall(pattern, content)
                            if matches:
                                # Redact the actual secret value in the finding
                                findings.append({
                                    'ResourceType': 'S3 Object',
                                    'ResourceId': f"{bucket_name}/{key}",
                                    'ResourceName': key,
                                    'Region': bucket_region,
                                    'Risk': 'CRITICAL',
                                    'Issue': f'Found {secret_type} in S3 object',
                                    'Recommendation': 'Remove hardcoded secrets from files and use AWS Secrets Manager or Parameter Store instead'
                                })
                                print(f"    [!] FINDING: Found {secret_type} in {bucket_name}/{key}")
                                break  # Only report one finding per file to avoid duplicates
                    
                    except Exception as e:
                        print(f"    Error reading object {key}: {e}")
            
            except Exception as e:
                print(f"  Error scanning bucket {bucket_name}: {e}")
    
    except Exception as e:
        print(f"Error scanning S3 buckets for secrets: {e}")
    
    print(f"S3 secrets scan complete. Found {len(findings)} issues.")
    return findings

def scan_api_gateway_for_secrets(region=None):
    """
    Scan API Gateway configurations for hardcoded secrets
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing findings
    """
    findings = []
    
    print("Starting API Gateway secrets scan...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
        
        for current_region in regions:
            print(f"Scanning API Gateway in region: {current_region}")
            
            try:
                apigw_client = boto3.client('apigateway', region_name=current_region)
                
                # Get all REST APIs
                apis = apigw_client.get_rest_apis()['items']
                print(f"  Found {len(apis)} REST APIs in {current_region}")
                
                for api in apis:
                    api_id = api['id']
                    api_name = api['name']
                    
                    # Get API stages
                    stages = apigw_client.get_stages(restApiId=api_id)['item']
                    
                    for stage in stages:
                        stage_name = stage['stageName']
                        
                        # Check stage variables for secrets
                        if 'variables' in stage:
                            for var_name, var_value in stage['variables'].items():
                                for pattern, secret_type in SECRET_PATTERNS:
                                    if re.search(pattern, var_value):
                                        findings.append({
                                            'ResourceType': 'API Gateway Stage Variable',
                                            'ResourceId': f"{api_id}/{stage_name}/{var_name}",
                                            'ResourceName': f"{api_name} - {stage_name} - {var_name}",
                                            'Region': current_region,
                                            'Risk': 'CRITICAL',
                                            'Issue': f'Found {secret_type} in API Gateway stage variable',
                                            'Recommendation': 'Remove hardcoded secrets from API Gateway stage variables and use AWS Secrets Manager or Parameter Store instead'
                                        })
                                        print(f"    [!] FINDING: Found {secret_type} in API Gateway {api_name}/{stage_name} variable {var_name}")
                    
                    # Get resources and methods
                    resources = apigw_client.get_resources(restApiId=api_id)['items']
                    
                    for resource in resources:
                        if 'resourceMethods' in resource:
                            for method_name, method_data in resource['resourceMethods'].items():
                                # Get method integration
                                try:
                                    integration = apigw_client.get_integration(
                                        restApiId=api_id,
                                        resourceId=resource['id'],
                                        httpMethod=method_name
                                    )
                                    
                                    # Check URI for secrets
                                    if 'uri' in integration:
                                        uri = integration['uri']
                                        for pattern, secret_type in SECRET_PATTERNS:
                                            if re.search(pattern, uri):
                                                findings.append({
                                                    'ResourceType': 'API Gateway Integration',
                                                    'ResourceId': f"{api_id}/{resource['id']}/{method_name}",
                                                    'ResourceName': f"{api_name} - {resource.get('path', 'unknown')} - {method_name}",
                                                    'Region': current_region,
                                                    'Risk': 'CRITICAL',
                                                    'Issue': f'Found {secret_type} in API Gateway integration URI',
                                                    'Recommendation': 'Remove hardcoded secrets from API Gateway integration URIs and use AWS Secrets Manager or Parameter Store instead'
                                                })
                                                print(f"    [!] FINDING: Found {secret_type} in API Gateway {api_name} integration URI")
                                    
                                    # Check request templates for secrets
                                    if 'requestTemplates' in integration:
                                        for content_type, template in integration['requestTemplates'].items():
                                            for pattern, secret_type in SECRET_PATTERNS:
                                                if re.search(pattern, template):
                                                    findings.append({
                                                        'ResourceType': 'API Gateway Integration',
                                                        'ResourceId': f"{api_id}/{resource['id']}/{method_name}",
                                                        'ResourceName': f"{api_name} - {resource.get('path', 'unknown')} - {method_name}",
                                                        'Region': current_region,
                                                        'Risk': 'CRITICAL',
                                                        'Issue': f'Found {secret_type} in API Gateway request template',
                                                        'Recommendation': 'Remove hardcoded secrets from API Gateway request templates and use AWS Secrets Manager or Parameter Store instead'
                                                    })
                                                    print(f"    [!] FINDING: Found {secret_type} in API Gateway {api_name} request template")
                                
                                except ClientError:
                                    # Skip if we can't get the integration
                                    pass
            
            except Exception as e:
                print(f"  Error scanning API Gateway in {current_region}: {e}")
    
    except Exception as e:
        print(f"Error scanning API Gateway for secrets: {e}")
    
    print(f"API Gateway secrets scan complete. Found {len(findings)} issues.")
    return findings

def scan_rds_for_secrets(region=None):
    """
    Scan RDS parameter groups for hardcoded secrets
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing findings
    """
    findings = []
    
    print("Starting RDS parameter groups scan for secrets...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
        
        for current_region in regions:
            print(f"Scanning RDS parameter groups in region: {current_region}")
            
            try:
                rds_client = boto3.client('rds', region_name=current_region)
                
                # Get all parameter groups
                paginator = rds_client.get_paginator('describe_db_parameter_groups')
                parameter_groups = []
                
                for page in paginator.paginate():
                    parameter_groups.extend(page['DBParameterGroups'])
                
                print(f"  Found {len(parameter_groups)} parameter groups in {current_region}")
                
                for pg in parameter_groups:
                    pg_name = pg['DBParameterGroupName']
                    
                    # Get parameters for this group
                    try:
                        paginator = rds_client.get_paginator('describe_db_parameters')
                        parameters = []
                        
                        for page in paginator.paginate(DBParameterGroupName=pg_name):
                            parameters.extend(page['Parameters'])
                        
                        # Check parameters for secrets
                        for param in parameters:
                            if 'ParameterValue' in param and param['ParameterValue']:
                                param_value = param['ParameterValue']
                                param_name = param['ParameterName']
                                
                                # Skip parameters that are unlikely to contain secrets
                                if param_name.lower() in ['port', 'max_connections', 'max_user_connections', 'server_id']:
                                    continue
                                
                                for pattern, secret_type in SECRET_PATTERNS:
                                    if re.search(pattern, param_value):
                                        findings.append({
                                            'ResourceType': 'RDS Parameter Group',
                                            'ResourceId': f"{pg_name}/{param_name}",
                                            'ResourceName': f"{pg_name} - {param_name}",
                                            'Region': current_region,
                                            'Risk': 'CRITICAL',
                                            'Issue': f'Found {secret_type} in RDS parameter value',
                                            'Recommendation': 'Remove hardcoded secrets from RDS parameters and use AWS Secrets Manager instead'
                                        })
                                        print(f"    [!] FINDING: Found {secret_type} in RDS parameter group {pg_name}, parameter {param_name}")
                    
                    except Exception as e:
                        print(f"    Error getting parameters for group {pg_name}: {e}")
            
            except Exception as e:
                print(f"  Error scanning RDS in {current_region}: {e}")
    
    except Exception as e:
        print(f"Error scanning RDS for secrets: {e}")
    
    print(f"RDS secrets scan complete. Found {len(findings)} issues.")
    return findings

def scan_for_secrets(region=None):
    """
    Scan AWS resources for hardcoded secrets, API keys, and credentials
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing findings
    """
    findings = []
    
    print("Starting comprehensive secrets scan...")
    
    # Scan S3 buckets
    s3_findings = scan_s3_for_secrets(region)
    findings.extend(s3_findings)
    
    # Scan API Gateway
    api_findings = scan_api_gateway_for_secrets(region)
    findings.extend(api_findings)
    
    # Scan RDS parameter groups
    rds_findings = scan_rds_for_secrets(region)
    findings.extend(rds_findings)
    
    print(f"Secrets scan complete. Found {len(findings)} issues.")
    return findings