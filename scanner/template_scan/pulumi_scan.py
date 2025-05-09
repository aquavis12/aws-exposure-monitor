"""
Pulumi Scanner Module - Detects security issues in Pulumi code
"""
import os
import re
from pathlib import Path


def scan_pulumi_code(directory):
    """
    Scan Pulumi code for AWS security issues like:
    - Hardcoded credentials
    - Insecure resource configurations
    - Missing encryption
    - Public access configurations
    - Overly permissive IAM policies
    
    Args:
        directory (str): Directory containing Pulumi code to scan
    
    Returns:
        list: List of dictionaries containing vulnerable code
    """
    findings = []
    
    print("Starting Pulumi code scan...")
    
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a valid directory")
        return findings
    
    # Scan Python Pulumi files
    python_findings = scan_python_pulumi_files(directory)
    findings.extend(python_findings)
    
    # Scan TypeScript/JavaScript Pulumi files
    js_findings = scan_js_pulumi_files(directory)
    findings.extend(js_findings)
    
    if findings:
        print(f"Found {len(findings)} Pulumi security issues.")
    else:
        print("No Pulumi security issues found.")
    
    return findings


def scan_python_pulumi_files(directory):
    """Scan Python Pulumi files for security issues"""
    findings = []
    
    print("Scanning Python Pulumi files...")
    
    python_files = list(Path(directory).rglob("*.py"))
    pulumi_files = []
    
    for file_path in python_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check if this is a Pulumi file
            if 'import pulumi' in content or 'import pulumi_aws' in content:
                pulumi_files.append((file_path, content))
        except Exception:
            pass
    
    print(f"Found {len(pulumi_files)} Python Pulumi files")
    
    for file_path, content in pulumi_files:
        file_str = str(file_path)
        
        # Check for hardcoded AWS credentials
        check_hardcoded_credentials(file_str, content, findings)
        
        # Check for insecure S3 configurations
        check_insecure_s3_config(file_str, content, findings)
        
        # Check for insecure IAM configurations
        check_insecure_iam_config(file_str, content, findings)
        
        # Check for insecure security group configurations
        check_insecure_sg_config(file_str, content, findings)
        
        # Check for insecure RDS configurations
        check_insecure_rds_config(file_str, content, findings)
        
        # Check for insecure Lambda configurations
        check_insecure_lambda_config(file_str, content, findings)
        
        # Check for insecure API Gateway configurations
        check_insecure_api_gateway_config(file_str, content, findings)
    
    return findings


def scan_js_pulumi_files(directory):
    """Scan TypeScript/JavaScript Pulumi files for security issues"""
    findings = []
    
    print("Scanning TypeScript/JavaScript Pulumi files...")
    
    js_files = list(Path(directory).rglob("*.ts")) + list(Path(directory).rglob("*.js"))
    pulumi_files = []
    
    for file_path in js_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check if this is a Pulumi file
            if 'require("@pulumi/aws")' in content or 'from "@pulumi/aws"' in content:
                pulumi_files.append((file_path, content))
        except Exception:
            pass
    
    print(f"Found {len(pulumi_files)} TypeScript/JavaScript Pulumi files")
    
    for file_path, content in pulumi_files:
        file_str = str(file_path)
        
        # Check for hardcoded AWS credentials
        check_hardcoded_credentials(file_str, content, findings)
        
        # Check for insecure S3 configurations
        check_insecure_s3_config(file_str, content, findings)
        
        # Check for insecure IAM configurations
        check_insecure_iam_config(file_str, content, findings)
        
        # Check for insecure security group configurations
        check_insecure_sg_config(file_str, content, findings)
        
        # Check for insecure RDS configurations
        check_insecure_rds_config(file_str, content, findings)
        
        # Check for insecure Lambda configurations
        check_insecure_lambda_config(file_str, content, findings)
        
        # Check for insecure API Gateway configurations
        check_insecure_api_gateway_config(file_str, content, findings)
    
    return findings


def check_hardcoded_credentials(file_path, content, findings):
    """Check for hardcoded credentials in Pulumi code"""
    # Patterns for AWS credentials
    credential_patterns = [
        (r'(?i)accessKeyId\s*[=:]\s*["\']([A-Z0-9]{20})["\']', 'AWS Access Key'),
        (r'(?i)secretAccessKey\s*[=:]\s*["\']([A-Za-z0-9+/]{40})["\']', 'AWS Secret Key'),
        (r'(?i)sessionToken\s*[=:]\s*["\']([A-Za-z0-9+/=]{100,})["\']', 'AWS Session Token'),
        (r'(?i)password\s*[=:]\s*["\']([^"\'{}]+)["\']', 'Password'),
        (r'(?i)secret\s*[=:]\s*["\']([^"\'{}]+)["\']', 'Secret')
    ]
    
    for pattern, credential_type in credential_patterns:
        matches = re.findall(pattern, content)
        if matches:
            findings.append({
                'ResourceType': 'Pulumi File',
                'ResourceId': file_path,
                'ResourceName': os.path.basename(file_path),
                'Risk': 'CRITICAL',
                'Issue': f'Hardcoded {credential_type} found in Pulumi code',
                'Recommendation': 'Use Pulumi config secrets or environment variables instead of hardcoding credentials'
            })
            print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} contains hardcoded {credential_type} - CRITICAL risk")


def check_insecure_s3_config(file_path, content, findings):
    """Check for insecure S3 configurations in Pulumi code"""
    # Check for public S3 buckets
    if re.search(r'new\s+aws\.s3\.Bucket\(', content) and re.search(r'acl\s*[=:]\s*["\']public-read["\']', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'S3 bucket is configured with public ACL',
            'Recommendation': 'Avoid using public ACLs for S3 buckets'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} configures public S3 bucket - HIGH risk")
    
    # Check for unencrypted S3 buckets
    if re.search(r'new\s+aws\.s3\.Bucket\(', content) and not re.search(r'serverSideEncryptionConfiguration', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'S3 bucket is created without encryption configuration',
            'Recommendation': 'Enable encryption for S3 buckets'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} creates unencrypted S3 bucket - MEDIUM risk")
    
    # Check for S3 buckets without versioning
    if re.search(r'new\s+aws\.s3\.Bucket\(', content) and not re.search(r'versioning\s*[=:]\s*[{\[]', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'S3 bucket is created without versioning',
            'Recommendation': 'Enable versioning for S3 buckets to protect against accidental deletion'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} creates S3 bucket without versioning - MEDIUM risk")
    
    # Check for S3 buckets without public access block
    if re.search(r'new\s+aws\.s3\.Bucket\(', content) and not re.search(r'blockPublicAc[cl]s\s*[=:]\s*true', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'S3 bucket is created without public access block configuration',
            'Recommendation': 'Add public access block configuration to prevent public access'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} creates S3 bucket without public access block - HIGH risk")


def check_insecure_iam_config(file_path, content, findings):
    """Check for insecure IAM configurations in Pulumi code"""
    # Check for IAM policies with wildcard permissions
    if (re.search(r'new\s+aws\.iam\.(Policy|Role)', content) and 
        re.search(r'"Action"\s*[=:]\s*["\'](\*|[^"\']*\*[^"\']*)["\']', content) and 
        re.search(r'"Resource"\s*[=:]\s*["\'](\*|[^"\']*\*[^"\']*)["\']', content)):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'IAM policy with wildcard permissions',
            'Recommendation': 'Follow the principle of least privilege by specifying only necessary actions and resources'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} has wildcard IAM permissions - HIGH risk")
    
    # Check for IAM users with console access but no MFA requirement
    if re.search(r'new\s+aws\.iam\.User\(', content) and re.search(r'passwordLength', content) and not re.search(r'mfaEnabled', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'IAM user with console access but no MFA requirement',
            'Recommendation': 'Enforce MFA for IAM users with console access'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} creates IAM user without MFA - HIGH risk")


def check_insecure_sg_config(file_path, content, findings):
    """Check for insecure security group configurations in Pulumi code"""
    # Check for security groups with open access
    if re.search(r'new\s+aws\.ec2\.SecurityGroup', content) and re.search(r'cidrBlocks\s*[=:]\s*\[\s*["\']0\.0\.0\.0/0["\']\s*\]', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'Security group allows access from any IP (0.0.0.0/0)',
            'Recommendation': 'Restrict security group rules to specific IP ranges'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} has open security group - HIGH risk")
    
    # Check for security groups with open IPv6 access
    if re.search(r'new\s+aws\.ec2\.SecurityGroup', content) and re.search(r'ipv6CidrBlocks\s*[=:]\s*\[\s*["\']::/0["\']\s*\]', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'Security group allows access from any IPv6 address (::/0)',
            'Recommendation': 'Restrict security group rules to specific IPv6 ranges'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} has open IPv6 security group - HIGH risk")
    
    # Check for security groups with sensitive ports open
    sensitive_ports = [22, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 9300, 8080, 8443]
    for port in sensitive_ports:
        if (re.search(r'new\s+aws\.ec2\.SecurityGroup', content) and 
            re.search(f'fromPort\s*[=:]\s*{port}', content) and 
            re.search(r'cidrBlocks\s*[=:]\s*\[\s*["\']0\.0\.0\.0/0["\']\s*\]', content)):
            findings.append({
                'ResourceType': 'Pulumi File',
                'ResourceId': file_path,
                'ResourceName': os.path.basename(file_path),
                'Risk': 'HIGH',
                'Issue': f'Security group allows public access to sensitive port {port}',
                'Recommendation': 'Restrict access to specific IP ranges'
            })
            print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} exposes port {port} to public - HIGH risk")


def check_insecure_rds_config(file_path, content, findings):
    """Check for insecure RDS configurations in Pulumi code"""
    # Check for unencrypted RDS instances
    if re.search(r'new\s+aws\.rds\.(Instance|Cluster)', content) and not re.search(r'storageEncrypted\s*[=:]\s*true', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance/cluster is created without encryption',
            'Recommendation': 'Enable storage encryption for RDS instances/clusters'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} creates unencrypted RDS - HIGH risk")
    
    # Check for public RDS instances
    if re.search(r'new\s+aws\.rds\.Instance', content) and re.search(r'publiclyAccessible\s*[=:]\s*true', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance is configured with public access',
            'Recommendation': 'Disable public access for RDS instances'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} creates public RDS instance - HIGH risk")
    
    # Check for RDS instances without backup
    if re.search(r'new\s+aws\.rds\.Instance', content) and re.search(r'backupRetentionPeriod\s*[=:]\s*0', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance has backups disabled',
            'Recommendation': 'Enable backups for RDS instances'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} disables RDS backups - HIGH risk")


def check_insecure_lambda_config(file_path, content, findings):
    """Check for insecure Lambda configurations in Pulumi code"""
    # Check for Lambda functions without VPC
    if re.search(r'new\s+aws\.lambda\.Function', content) and not re.search(r'vpcConfig', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'LOW',
            'Issue': 'Lambda function is created without VPC configuration',
            'Recommendation': 'Consider placing Lambda functions in a VPC for better network isolation'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} creates Lambda without VPC - LOW risk")
    
    # Check for Lambda functions without X-Ray tracing
    if re.search(r'new\s+aws\.lambda\.Function', content) and not re.search(r'tracingConfig', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'LOW',
            'Issue': 'Lambda function is created without X-Ray tracing',
            'Recommendation': 'Enable X-Ray tracing for better monitoring and debugging'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} creates Lambda without X-Ray - LOW risk")
    
    # Check for Lambda functions with environment variables but no encryption
    if re.search(r'new\s+aws\.lambda\.Function', content) and re.search(r'environment', content) and not re.search(r'kmsKeyArn', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'Lambda function has environment variables without custom encryption',
            'Recommendation': 'Use KMS key for environment variable encryption'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} has Lambda with unencrypted env vars - MEDIUM risk")


def check_insecure_api_gateway_config(file_path, content, findings):
    """Check for insecure API Gateway configurations in Pulumi code"""
    # Check for API Gateway without authorization
    if re.search(r'new\s+aws\.apigateway\.(RestApi|Method)', content) and re.search(r'authorizationType\s*[=:]\s*["\']NONE["\']', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'API Gateway method is configured without authorization',
            'Recommendation': 'Configure authorization for API Gateway methods'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} creates API Gateway without auth - HIGH risk")
    
    # Check for API Gateway without WAF
    if re.search(r'new\s+aws\.apigateway\.RestApi', content) and not re.search(r'webAclId', content):
        findings.append({
            'ResourceType': 'Pulumi File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'API Gateway is created without WAF protection',
            'Recommendation': 'Associate a WAF Web ACL with API Gateway'
        })
        print(f"    [!] FINDING: Pulumi file {os.path.basename(file_path)} creates API Gateway without WAF - MEDIUM risk")