"""
AWS SDK Scanner Module - Detects security issues in AWS SDK code
"""
import os
import re
import ast
from pathlib import Path


def scan_sdk_code(directory):
    """
    Scan AWS SDK code for security issues like:
    - Hardcoded credentials
    - Insecure configurations
    - Missing encryption
    - Overly permissive IAM policies
    
    Args:
        directory (str): Directory containing AWS SDK code to scan
    
    Returns:
        list: List of dictionaries containing vulnerable code
    """
    findings = []
    
    print("Starting AWS SDK code scan...")
    
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a valid directory")
        return findings
    
    # Scan Python files (boto3)
    python_findings = scan_python_sdk_files(directory)
    findings.extend(python_findings)
    
    # Scan JavaScript/TypeScript files (AWS SDK for JavaScript)
    js_findings = scan_js_sdk_files(directory)
    findings.extend(js_findings)
    
    if findings:
        print(f"Found {len(findings)} AWS SDK security issues.")
    else:
        print("No AWS SDK security issues found.")
    
    return findings


def scan_python_sdk_files(directory):
    """Scan Python files for AWS SDK (boto3) security issues"""
    findings = []
    
    print("Scanning Python files for AWS SDK (boto3) security issues...")
    
    python_files = list(Path(directory).rglob("*.py"))
    print(f"Found {len(python_files)} Python files")
    
    boto3_files = []
    for file_path in python_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Skip empty files
            if not content.strip():
                continue
            
            # Check if this file uses boto3
            if 'import boto3' in content or 'from boto3' in content:
                boto3_files.append((file_path, content))
        except Exception:
            pass
    
    print(f"Found {len(boto3_files)} files using boto3")
    
    for file_path, content in boto3_files:
        file_str = str(file_path)
        
        # Check for hardcoded AWS credentials
        check_hardcoded_aws_credentials(file_str, content, findings)
        
        # Check for insecure boto3 configurations
        check_insecure_boto3_config(file_str, content, findings)
        
        # Try to parse the file with AST for more detailed analysis
        try:
            tree = ast.parse(content)
            check_python_ast(file_str, tree, findings)
        except SyntaxError:
            # If we can't parse the file, continue with regex-based checks
            pass
    
    return findings


def check_hardcoded_aws_credentials(file_path, content, findings):
    """Check for hardcoded AWS credentials in code"""
    # Patterns for AWS credentials
    credential_patterns = [
        (r'(?i)aws_access_key_id\s*=\s*["\']([A-Z0-9]{20})["\']', 'AWS Access Key'),
        (r'(?i)aws_secret_access_key\s*=\s*["\']([A-Za-z0-9+/]{40})["\']', 'AWS Secret Key'),
        (r'(?i)aws_session_token\s*=\s*["\']([A-Za-z0-9+/=]{100,})["\']', 'AWS Session Token'),
        (r'(?i)accesskeyid\s*=\s*["\']([A-Z0-9]{20})["\']', 'AWS Access Key'),
        (r'(?i)secretaccesskey\s*=\s*["\']([A-Za-z0-9+/]{40})["\']', 'AWS Secret Key')
    ]
    
    for pattern, credential_type in credential_patterns:
        matches = re.findall(pattern, content)
        if matches:
            findings.append({
                'ResourceType': 'SDK Code File',
                'ResourceId': file_path,
                'ResourceName': os.path.basename(file_path),
                'Risk': 'CRITICAL',
                'Issue': f'Hardcoded {credential_type} found in code',
                'Recommendation': 'Use environment variables, AWS credential provider chain, or AWS Secrets Manager instead of hardcoding credentials'
            })
            print(f"    [!] FINDING: {os.path.basename(file_path)} contains hardcoded {credential_type} - CRITICAL risk")


def check_insecure_boto3_config(file_path, content, findings):
    """Check for insecure boto3 configurations"""
    # Check for disabled SSL verification
    if re.search(r'verify\s*=\s*False', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'SSL verification is disabled in AWS SDK calls',
            'Recommendation': 'Always enable SSL verification for AWS API calls'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} disables SSL verification - HIGH risk")
    
    # Check for public S3 bucket ACLs
    if re.search(r'ACL\s*=\s*["\']public-read["\']', content) or re.search(r'ACL\s*=\s*["\']public-read-write["\']', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'S3 bucket or object is configured with public ACL',
            'Recommendation': 'Avoid using public ACLs for S3 buckets and objects'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} sets public S3 ACL - HIGH risk")
    
    # Check for missing encryption in S3
    if re.search(r'\.put_object\(', content) and not re.search(r'ServerSideEncryption', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'S3 put_object call without server-side encryption',
            'Recommendation': 'Specify ServerSideEncryption parameter in S3 put_object calls'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} missing S3 encryption - MEDIUM risk")
    
    # Check for S3 bucket creation without encryption
    if re.search(r'\.create_bucket\(', content) and not re.search(r'BucketEncryption', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'S3 bucket created without encryption configuration',
            'Recommendation': 'Configure default encryption for S3 buckets'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates unencrypted S3 bucket - MEDIUM risk")
    
    # Check for S3 bucket creation without public access block
    if re.search(r'\.create_bucket\(', content) and not re.search(r'\.put_public_access_block\(', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'S3 bucket created without public access block configuration',
            'Recommendation': 'Use put_public_access_block to restrict public access'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates S3 bucket without public access block - HIGH risk")
    
    # Check for S3 bucket creation without versioning
    if re.search(r'\.create_bucket\(', content) and not re.search(r'\.put_bucket_versioning\(.*Status[\'"]?\s*:\s*[\'"]?Enabled', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'S3 bucket created without versioning',
            'Recommendation': 'Enable versioning for S3 buckets'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates S3 bucket without versioning - MEDIUM risk")
    
    # Check for RDS instance creation without encryption
    if re.search(r'\.create_db_instance\(', content) and not re.search(r'StorageEncrypted\s*=\s*True', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance created without encryption',
            'Recommendation': 'Set StorageEncrypted to True when creating RDS instances'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates unencrypted RDS instance - HIGH risk")
    
    # Check for RDS instance creation with public access
    if re.search(r'\.create_db_instance\(', content) and re.search(r'PubliclyAccessible\s*=\s*True', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance created with public accessibility',
            'Recommendation': 'Set PubliclyAccessible to False for RDS instances'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates public RDS instance - HIGH risk")
    
    # Check for EC2 instance creation without IMDSv2
    if re.search(r'\.run_instances\(', content) and not re.search(r'MetadataOptions.*HttpTokens[\'"]?\s*:\s*[\'"]?required', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'EC2 instance created without IMDSv2 requirement',
            'Recommendation': 'Set HttpTokens to required in MetadataOptions'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates EC2 without IMDSv2 - MEDIUM risk")
    
    # Check for security group rules with open access
    if re.search(r'\.authorize_security_group_ingress\(', content) and re.search(r'CidrIp[\'"]?\s*:\s*[\'"]?0\.0\.0\.0/0', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'Security group rule allows access from any IP (0.0.0.0/0)',
            'Recommendation': 'Restrict security group rules to specific IP ranges'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates open security group rule - HIGH risk")
    
    # Check for security group rules with open IPv6 access
    if re.search(r'\.authorize_security_group_ingress\(', content) and re.search(r'CidrIpv6[\'"]?\s*:\s*[\'"]?::/0', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'Security group rule allows access from any IPv6 address (::/0)',
            'Recommendation': 'Restrict security group rules to specific IPv6 ranges'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates open IPv6 security group rule - HIGH risk")
    
    # Check for Lambda function creation without VPC
    if re.search(r'\.create_function\(', content) and not re.search(r'VpcConfig', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'LOW',
            'Issue': 'Lambda function created without VPC configuration',
            'Recommendation': 'Consider placing Lambda functions in a VPC for better network isolation'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates Lambda without VPC - LOW risk")
    
    # Check for Lambda function creation without X-Ray tracing
    if re.search(r'\.create_function\(', content) and not re.search(r'TracingConfig[\'"]?\s*:\s*[\'"]?Active', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'LOW',
            'Issue': 'Lambda function created without X-Ray tracing',
            'Recommendation': 'Enable X-Ray tracing for better monitoring and debugging'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates Lambda without X-Ray - LOW risk")
    
    # Check for DynamoDB table creation without encryption
    if re.search(r'\.create_table\(', content) and not re.search(r'SSESpecification', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'DynamoDB table created without encryption',
            'Recommendation': 'Specify SSESpecification to enable encryption'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates unencrypted DynamoDB table - MEDIUM risk")
    
    # Check for DynamoDB table creation without point-in-time recovery
    if re.search(r'\.create_table\(', content) and not re.search(r'PointInTimeRecoverySpecification', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'DynamoDB table created without point-in-time recovery',
            'Recommendation': 'Enable point-in-time recovery for DynamoDB tables'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates DynamoDB without PITR - MEDIUM risk")
    
    # Check for public RDS instances
    if re.search(r'\.create_db_instance\(', content) and re.search(r'PubliclyAccessible\s*=\s*True', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance is created with public accessibility',
            'Recommendation': 'Set PubliclyAccessible to False for RDS instances'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates public RDS instance - HIGH risk")
    
    # Check for unencrypted RDS instances
    if re.search(r'\.create_db_instance\(', content) and not re.search(r'StorageEncrypted\s*=\s*True', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance is created without storage encryption',
            'Recommendation': 'Set StorageEncrypted to True for RDS instances'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates unencrypted RDS instance - HIGH risk")
    
    # Check for EC2 instances without IMDSv2
    if re.search(r'\.run_instances\(', content) and not re.search(r'MetadataOptions.*HttpTokens.*required', content, re.DOTALL):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'EC2 instance is created without IMDSv2 requirement',
            'Recommendation': 'Set HttpTokens to required in MetadataOptions'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates EC2 without IMDSv2 - MEDIUM risk")


def check_python_ast(file_path, tree, findings):
    """Analyze Python AST for security issues"""
    # Check for IAM policies with wildcards
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            # Try to identify IAM policy documents
            is_policy = False
            has_statement = False
            
            # Check if this dict has keys that might indicate it's a policy
            for i, key in enumerate(node.keys):
                if isinstance(key, ast.Str) and key.s in ['Version', 'Statement']:
                    if key.s == 'Statement':
                        has_statement = True
                    is_policy = True
            
            if is_policy and has_statement:
                # Look for wildcard permissions in the policy
                for i, key in enumerate(node.keys):
                    if isinstance(key, ast.Str) and key.s == 'Statement':
                        value = node.values[i]
                        if isinstance(value, ast.List):
                            for stmt in value.elts:
                                if isinstance(stmt, ast.Dict):
                                    check_statement_for_wildcards(file_path, stmt, findings)


def check_statement_for_wildcards(file_path, stmt_node, findings):
    """Check IAM policy statement for wildcard permissions"""
    effect = None
    action = None
    resource = None
    
    for i, key in enumerate(stmt_node.keys):
        if not isinstance(key, ast.Str):
            continue
        
        if key.s == 'Effect':
            if isinstance(stmt_node.values[i], ast.Str):
                effect = stmt_node.values[i].s
        
        elif key.s == 'Action':
            value = stmt_node.values[i]
            if isinstance(value, ast.Str):
                action = value.s
            elif isinstance(value, ast.List):
                for elt in value.elts:
                    if isinstance(elt, ast.Str) and (elt.s == '*' or elt.s.endswith('*')):
                        action = elt.s
                        break
        
        elif key.s == 'Resource':
            value = stmt_node.values[i]
            if isinstance(value, ast.Str):
                resource = value.s
            elif isinstance(value, ast.List):
                for elt in value.elts:
                    if isinstance(elt, ast.Str) and elt.s == '*':
                        resource = elt.s
                        break
    
    if effect == 'Allow' and (action == '*' or (action and action.endswith('*'))) and resource == '*':
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'IAM policy with wildcard permissions (Action: * and Resource: *)',
            'Recommendation': 'Follow the principle of least privilege by specifying only necessary actions and resources'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} contains wildcard IAM permissions - HIGH risk")


def scan_js_sdk_files(directory):
    """Scan JavaScript/TypeScript files for AWS SDK security issues"""
    findings = []
    
    print("Scanning JavaScript/TypeScript files for AWS SDK security issues...")
    
    js_files = list(Path(directory).rglob("*.js")) + list(Path(directory).rglob("*.ts"))
    print(f"Found {len(js_files)} JavaScript/TypeScript files")
    
    aws_sdk_files = []
    for file_path in js_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Skip empty files
            if not content.strip():
                continue
            
            # Check if this file uses AWS SDK
            if 'require("aws-sdk")' in content or 'from "aws-sdk"' in content or 'import AWS from' in content:
                aws_sdk_files.append((file_path, content))
        except Exception:
            pass
    
    print(f"Found {len(aws_sdk_files)} files using AWS SDK for JavaScript")
    
    for file_path, content in aws_sdk_files:
        file_str = str(file_path)
        
        # Check for hardcoded AWS credentials
        check_js_hardcoded_credentials(file_str, content, findings)
        
        # Check for insecure AWS SDK configurations
        check_js_insecure_config(file_str, content, findings)
    
    return findings


def check_js_hardcoded_credentials(file_path, content, findings):
    """Check for hardcoded credentials in JavaScript/TypeScript files"""
    # Patterns for AWS credentials
    credential_patterns = [
        (r'(?i)accessKeyId\s*:\s*["\']([A-Z0-9]{20})["\']', 'AWS Access Key'),
        (r'(?i)secretAccessKey\s*:\s*["\']([A-Za-z0-9+/]{40})["\']', 'AWS Secret Key'),
        (r'(?i)sessionToken\s*:\s*["\']([A-Za-z0-9+/=]{100,})["\']', 'AWS Session Token')
    ]
    
    for pattern, credential_type in credential_patterns:
        matches = re.findall(pattern, content)
        if matches:
            findings.append({
                'ResourceType': 'SDK Code File',
                'ResourceId': file_path,
                'ResourceName': os.path.basename(file_path),
                'Risk': 'CRITICAL',
                'Issue': f'Hardcoded {credential_type} found in code',
                'Recommendation': 'Use environment variables, AWS credential provider chain, or AWS Secrets Manager instead of hardcoding credentials'
            })
            print(f"    [!] FINDING: {os.path.basename(file_path)} contains hardcoded {credential_type} - CRITICAL risk")


def check_js_insecure_config(file_path, content, findings):
    """Check for insecure AWS SDK configurations in JavaScript/TypeScript"""
    # Check for disabled SSL verification
    if re.search(r'sslEnabled\s*:\s*false', content, re.IGNORECASE):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'SSL verification is disabled in AWS SDK calls',
            'Recommendation': 'Always enable SSL verification for AWS API calls'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} disables SSL verification - HIGH risk")
    
    # Check for public S3 bucket ACLs
    if re.search(r'ACL\s*:\s*["\']public-read["\']', content) or re.search(r'ACL\s*:\s*["\']public-read-write["\']', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'S3 bucket or object is configured with public ACL',
            'Recommendation': 'Avoid using public ACLs for S3 buckets and objects'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} sets public S3 ACL - HIGH risk")
    
    # Check for missing encryption in S3
    if re.search(r'\.putObject\(', content) and not re.search(r'ServerSideEncryption', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'S3 putObject call without server-side encryption',
            'Recommendation': 'Specify ServerSideEncryption parameter in S3 putObject calls'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} missing S3 encryption - MEDIUM risk")
    
    # Check for public RDS instances
    if re.search(r'\.createDBInstance\(', content) and re.search(r'PubliclyAccessible\s*:\s*true', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance is created with public accessibility',
            'Recommendation': 'Set PubliclyAccessible to false for RDS instances'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} creates public RDS instance - HIGH risk")
    
    # Check for IAM policies with wildcard permissions
    if re.search(r'"Effect"\s*:\s*"Allow"', content) and re.search(r'"Action"\s*:\s*["\[]?\s*"\*"', content) and re.search(r'"Resource"\s*:\s*["\[]?\s*"\*"', content):
        findings.append({
            'ResourceType': 'SDK Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'IAM policy with wildcard permissions (Action: * and Resource: *)',
            'Recommendation': 'Follow the principle of least privilege by specifying only necessary actions and resources'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} contains wildcard IAM permissions - HIGH risk")
    
    return findings