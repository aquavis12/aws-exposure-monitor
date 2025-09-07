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
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        region_count = 0
        total_function_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                pass
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
                                    action = statement.get('Action', '')
                                    
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
                                        break
                                    
                                    # Check for overly broad cross-account access
                                    elif isinstance(principal, dict) and 'AWS' in principal:
                                        aws_principal = principal['AWS']
                                        if isinstance(aws_principal, str) and 'arn:aws:iam::' in aws_principal and '*' in aws_principal:
                                            findings.append({
                                                'ResourceType': 'Lambda Function',
                                                'ResourceId': function_name,
                                                'ResourceName': function_name,
                                                'ResourceArn': function_arn,
                                                'Runtime': runtime,
                                                'Region': current_region,
                                                'Risk': 'MEDIUM',
                                                'Issue': 'Lambda function allows broad cross-account access',
                                                'Recommendation': 'Restrict cross-account access to specific accounts and add conditions'
                                            })
                        except ClientError as e:
                            # No resource policy - this is normal
                            pass
                        
                        # Check function configuration for security issues
                        try:
                            func_config = lambda_client.get_function_configuration(FunctionName=function_name)
                            
                            # Check if function has VPC configuration for sensitive workloads
                            vpc_config = func_config.get('VpcConfig', {})
                            if not vpc_config.get('VpcId') and 'prod' in function_name.lower():
                                findings.append({
                                    'ResourceType': 'Lambda Function',
                                    'ResourceId': function_name,
                                    'ResourceName': function_name,
                                    'ResourceArn': function_arn,
                                    'Runtime': runtime,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'Production Lambda function not in VPC',
                                    'Recommendation': 'Consider placing production functions in VPC for network isolation'
                                })
                            
                            # Check for environment variables that might contain secrets
                            env_vars = func_config.get('Environment', {}).get('Variables', {})
                            for var_name, var_value in env_vars.items():
                                if any(keyword in var_name.lower() for keyword in ['password', 'secret', 'key', 'token']) and len(var_value) > 10:
                                    findings.append({
                                        'ResourceType': 'Lambda Function',
                                        'ResourceId': function_name,
                                        'ResourceName': function_name,
                                        'ResourceArn': function_arn,
                                        'Runtime': runtime,
                                        'Region': current_region,
                                        'Risk': 'HIGH',
                                        'Issue': f'Lambda function has potential secret in environment variable: {var_name}',
                                        'Recommendation': 'Use AWS Secrets Manager or Parameter Store for sensitive values'
                                    })
                        except ClientError:
                            pass
            
            except ClientError as e:
                pass
    except Exception as e:
        pass
    
    return findings