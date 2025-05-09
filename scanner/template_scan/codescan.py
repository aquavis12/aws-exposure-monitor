"""
AWS Code Scanner Module - Detects security issues in AWS SDK, CDK, and other AWS-related code
"""
import os
import re
import ast
import json
from pathlib import Path


def scan_aws_code(directory):
    """
    Scan AWS SDK, CDK, and other AWS-related code for security issues like:
    - Hardcoded credentials
    - Insecure configurations
    - Missing encryption
    - Overly permissive IAM policies
    - Insecure defaults
    
    Args:
        directory (str): Directory containing code to scan
    
    Returns:
        list: List of dictionaries containing vulnerable code
    """
    findings = []
    
    print("Starting AWS code scan...")
    
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a valid directory")
        return findings
    
    # Scan Python files
    python_findings = scan_python_files(directory)
    findings.extend(python_findings)
    
    # Scan JavaScript/TypeScript files
    js_findings = scan_js_files(directory)
    findings.extend(js_findings)
    
    # Scan CDK files specifically
    cdk_findings = scan_cdk_files(directory)
    findings.extend(cdk_findings)
    
    # Scan Terraform files
    tf_findings = scan_terraform_files(directory)
    findings.extend(tf_findings)
    
    if findings:
        print(f"Found {len(findings)} AWS code security issues.")
    else:
        print("No AWS code security issues found.")
    
    return findings


def scan_python_files(directory):
    """Scan Python files for AWS SDK security issues"""
    findings = []
    
    print("Scanning Python files for AWS SDK security issues...")
    
    python_files = list(Path(directory).rglob("*.py"))
    print(f"Found {len(python_files)} Python files")
    
    for file_path in python_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Skip empty files
            if not content.strip():
                continue
            
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
        
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
    
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
                'ResourceType': 'Code File',
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
            'ResourceType': 'Code File',
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
            'ResourceType': 'Code File',
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
            'ResourceType': 'Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'S3 put_object call without server-side encryption',
            'Recommendation': 'Specify ServerSideEncryption parameter in S3 put_object calls'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} missing S3 encryption - MEDIUM risk")


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
            'ResourceType': 'Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'IAM policy with wildcard permissions (Action: * and Resource: *)',
            'Recommendation': 'Follow the principle of least privilege by specifying only necessary actions and resources'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} contains wildcard IAM permissions - HIGH risk")


def scan_js_files(directory):
    """Scan JavaScript/TypeScript files for AWS SDK security issues"""
    findings = []
    
    print("Scanning JavaScript/TypeScript files for AWS SDK security issues...")
    
    js_files = list(Path(directory).rglob("*.js")) + list(Path(directory).rglob("*.ts"))
    print(f"Found {len(js_files)} JavaScript/TypeScript files")
    
    for file_path in js_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Skip empty files
            if not content.strip():
                continue
            
            file_str = str(file_path)
            
            # Check for hardcoded AWS credentials
            check_js_hardcoded_credentials(file_str, content, findings)
            
            # Check for insecure AWS SDK configurations
            check_js_insecure_config(file_str, content, findings)
        
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
    
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
                'ResourceType': 'Code File',
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
            'ResourceType': 'Code File',
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
            'ResourceType': 'Code File',
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
            'ResourceType': 'Code File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'S3 putObject call without server-side encryption',
            'Recommendation': 'Specify ServerSideEncryption parameter in S3 putObject calls'
        })
        print(f"    [!] FINDING: {os.path.basename(file_path)} missing S3 encryption - MEDIUM risk")


def scan_cdk_files(directory):
    """Scan AWS CDK files for security issues"""
    findings = []
    
    print("Scanning AWS CDK files for security issues...")
    
    # CDK files are typically TypeScript or JavaScript files with specific imports
    cdk_files = []
    js_ts_files = list(Path(directory).rglob("*.js")) + list(Path(directory).rglob("*.ts"))
    
    for file_path in js_ts_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check if this is a CDK file
            if 'aws-cdk-lib' in content or '@aws-cdk/' in content:
                cdk_files.append((file_path, content))
        except Exception:
            pass
    
    print(f"Found {len(cdk_files)} CDK files")
    
    for file_path, content in cdk_files:
        file_str = str(file_path)
        
        # Check for insecure CDK constructs
        check_cdk_insecure_constructs(file_str, content, findings)
    
    return findings


def check_cdk_insecure_constructs(file_path, content, findings):
    """Check for insecure CDK constructs"""
    # Check for S3 buckets with public access
    if re.search(r'publicReadAccess\s*:\s*true', content) or re.search(r'blockPublicAccess\s*:\s*BlockPublicAccess\.NONE', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'S3 bucket is configured with public access',
            'Recommendation': 'Disable public access for S3 buckets'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} configures public S3 bucket - HIGH risk")
    
    # Check for unencrypted S3 buckets
    if re.search(r'new\s+s3\.Bucket\(', content) and not re.search(r'encryption\s*:', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'S3 bucket is created without encryption configuration',
            'Recommendation': 'Enable encryption for S3 buckets'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} creates unencrypted S3 bucket - MEDIUM risk")
    
    # Check for IAM roles with wildcard permissions
    if re.search(r'\.addToPolicy\(new\s+iam\.PolicyStatement\(', content) and re.search(r'actions\s*:\s*\[\s*[\'"].*\*.*[\'"]\s*\]', content) and re.search(r'resources\s*:\s*\[\s*[\'"].*\*.*[\'"]\s*\]', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'IAM policy with wildcard permissions',
            'Recommendation': 'Follow the principle of least privilege by specifying only necessary actions and resources'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} has wildcard IAM permissions - HIGH risk")
    
    # Check for Lambda functions without VPC
    if re.search(r'new\s+lambda\.Function\(', content) and not re.search(r'vpc\s*:', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'LOW',
            'Issue': 'Lambda function is created without VPC configuration',
            'Recommendation': 'Consider placing Lambda functions in a VPC for better network isolation'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} creates Lambda without VPC - LOW risk")


def scan_terraform_files(directory):
    """Scan Terraform files for AWS security issues"""
    findings = []
    
    print("Scanning Terraform files for AWS security issues...")
    
    tf_files = list(Path(directory).rglob("*.tf"))
    print(f"Found {len(tf_files)} Terraform files")
    
    for file_path in tf_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Skip empty files
            if not content.strip():
                continue
            
            file_str = str(file_path)
            
            # Check for hardcoded AWS credentials
            check_tf_hardcoded_credentials(file_str, content, findings)
            
            # Check for insecure resource configurations
            check_tf_insecure_resources(file_str, content, findings)
        
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
    
    return findings


def check_tf_hardcoded_credentials(file_path, content, findings):
    """Check for hardcoded credentials in Terraform files"""
    # Patterns for AWS credentials
    credential_patterns = [
        (r'(?i)access_key\s*=\s*["\']([A-Z0-9]{20})["\']', 'AWS Access Key'),
        (r'(?i)secret_key\s*=\s*["\']([A-Za-z0-9+/]{40})["\']', 'AWS Secret Key')
    ]
    
    for pattern, credential_type in credential_patterns:
        matches = re.findall(pattern, content)
        if matches:
            findings.append({
                'ResourceType': 'Terraform File',
                'ResourceId': file_path,
                'ResourceName': os.path.basename(file_path),
                'Risk': 'CRITICAL',
                'Issue': f'Hardcoded {credential_type} found in Terraform file',
                'Recommendation': 'Use environment variables, AWS credential provider chain, or AWS Secrets Manager instead of hardcoding credentials'
            })
            print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} contains hardcoded {credential_type} - CRITICAL risk")


def check_tf_insecure_resources(file_path, content, findings):
    """Check for insecure resource configurations in Terraform files"""
    # Check for S3 buckets with public ACLs
    if re.search(r'resource\s+"aws_s3_bucket"', content) and re.search(r'acl\s*=\s*"public-read"', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'S3 bucket is configured with public ACL',
            'Recommendation': 'Avoid using public ACLs for S3 buckets'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} configures public S3 bucket - HIGH risk")
    
    # Check for unencrypted S3 buckets
    if re.search(r'resource\s+"aws_s3_bucket"', content) and not re.search(r'server_side_encryption_configuration', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'S3 bucket is created without encryption configuration',
            'Recommendation': 'Enable encryption for S3 buckets'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates unencrypted S3 bucket - MEDIUM risk")
    
    # Check for security groups with open access
    if re.search(r'resource\s+"aws_security_group"', content) and re.search(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'Security group allows access from any IP (0.0.0.0/0)',
            'Recommendation': 'Restrict security group rules to specific IP ranges'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} has open security group - HIGH risk")
    
    # Check for IAM policies with wildcard permissions
    if re.search(r'resource\s+"aws_iam_policy"', content) and re.search(r'"Action"\s*:\s*"\*"', content) and re.search(r'"Resource"\s*:\s*"\*"', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'IAM policy with wildcard permissions (Action: * and Resource: *)',
            'Recommendation': 'Follow the principle of least privilege by specifying only necessary actions and resources'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} has wildcard IAM permissions - HIGH risk")
    
    return findings