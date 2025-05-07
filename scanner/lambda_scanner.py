"""
Lambda Scanner Module - Detects publicly accessible Lambda functions
"""
import boto3
import json
from botocore.exceptions import ClientError


def scan_lambda_functions(region=None):
    """
    Scan Lambda functions for public access policies
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting Lambda function scan...")
    
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
        total_function_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            lambda_client = boto3.client('lambda', region_name=current_region)
            
            try:
                # Get all Lambda functions
                functions = []
                paginator = lambda_client.get_paginator('list_functions')
                
                for page in paginator.paginate():
                    functions.extend(page.get('Functions', []))
                
                function_count = len(functions)
                total_function_count += function_count
                
                if function_count > 0:
                    print(f"  Found {function_count} Lambda functions in {current_region}")
                    
                    for i, function in enumerate(functions, 1):
                        function_name = function.get('FunctionName')
                        function_arn = function.get('FunctionArn')
                        runtime = function.get('Runtime', 'Unknown')
                        
                        # Print progress every 10 functions or for the last one
                        if i % 10 == 0 or i == function_count:
                            print(f"  Progress: {i}/{function_count}")
                        
                        # Check function URL configuration
                        try:
                            url_config = lambda_client.get_function_url_config(FunctionName=function_name)
                            auth_type = url_config.get('AuthType')
                            
                            if auth_type == 'NONE':
                                findings.append({
                                    'ResourceType': 'Lambda Function URL',
                                    'ResourceId': function_name,
                                    'ResourceName': function_name,
                                    'ResourceArn': function_arn,
                                    'Runtime': runtime,
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': 'Lambda function URL has no authentication (AuthType: NONE)',
                                    'Recommendation': 'Change AuthType to AWS_IAM or implement custom authorization'
                                })
                                print(f"    [!] FINDING: Function {function_name} has public URL without authentication - HIGH risk")
                        except ClientError as e:
                            # Function URL not configured - this is normal
                            pass
                        
                        # Check function policy
                        try:
                            policy_response = lambda_client.get_policy(FunctionName=function_name)
                            if policy_response and 'Policy' in policy_response:
                                policy = json.loads(policy_response['Policy'])
                                
                                for statement in policy.get('Statement', []):
                                    principal = statement.get('Principal', {})
                                    
                                    # Check if policy allows public access
                                    if principal == '*' or principal == {"AWS": "*"} or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                                        findings.append({
                                            'ResourceType': 'Lambda Function',
                                            'ResourceId': function_name,
                                            'ResourceName': function_name,
                                            'ResourceArn': function_arn,
                                            'Runtime': runtime,
                                            'Region': current_region,
                                            'Risk': 'HIGH',
                                            'Issue': 'Lambda function policy allows public invocation',
                                            'Recommendation': 'Restrict the function policy to specific principals'
                                        })
                                        print(f"    [!] FINDING: Function {function_name} has public policy - HIGH risk")
                                        break
                        except ClientError as e:
                            # No resource policy - this is normal
                            pass
            
            except ClientError as e:
                print(f"  Error scanning Lambda functions in {current_region}: {e}")
        
        if total_function_count == 0:
            print("No Lambda functions found.")
        else:
            print(f"Lambda scan complete. Scanned {total_function_count} functions.")
    
    except Exception as e:
        print(f"Error scanning Lambda functions: {e}")
    
    if findings:
        print(f"Found {len(findings)} Lambda function issues.")
    else:
        print("No Lambda function issues found.")
    
    return findings