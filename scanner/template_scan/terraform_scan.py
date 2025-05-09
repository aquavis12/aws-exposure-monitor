"""
Terraform Scanner Module - Detects security issues in Terraform code
"""
import os
import re
from pathlib import Path


def scan_terraform_code(directory):
    """
    Scan Terraform code for AWS security issues like:
    - Hardcoded credentials
    - Insecure resource configurations
    - Missing encryption
    - Public access configurations
    - Overly permissive IAM policies
    
    Args:
        directory (str): Directory containing Terraform code to scan
    
    Returns:
        list: List of dictionaries containing vulnerable code
    """
    findings = []
    
    print("Starting Terraform code scan...")
    
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a valid directory")
        return findings
    
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
    
    if findings:
        print(f"Found {len(findings)} Terraform security issues.")
    else:
        print("No Terraform security issues found.")
    
    return findings


def check_tf_hardcoded_credentials(file_path, content, findings):
    """Check for hardcoded credentials in Terraform files"""
    # Patterns for AWS credentials
    credential_patterns = [
        (r'(?i)access_key\s*=\s*["\']([A-Z0-9]{20})["\']', 'AWS Access Key'),
        (r'(?i)secret_key\s*=\s*["\']([A-Za-z0-9+/]{40})["\']', 'AWS Secret Key'),
        (r'(?i)token\s*=\s*["\']([A-Za-z0-9+/=]{100,})["\']', 'AWS Session Token'),
        (r'(?i)password\s*=\s*["\']([^"\'{}]+)["\']', 'Password'),
        (r'(?i)secret\s*=\s*["\']([^"\'{}]+)["\']', 'Secret')
    ]
    
    for pattern, credential_type in credential_patterns:
        matches = re.findall(pattern, content)
        if matches:
            # Skip if the value is a variable reference
            if any(match.startswith('var.') or match.startswith('${var.') for match in matches):
                continue
                
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
    
    # Check for S3 buckets without versioning
    if re.search(r'resource\s+"aws_s3_bucket"', content) and not re.search(r'versioning\s*{[^}]*enabled\s*=\s*true', content, re.DOTALL):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'S3 bucket is created without versioning',
            'Recommendation': 'Enable versioning for S3 buckets to protect against accidental deletion'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates S3 bucket without versioning - MEDIUM risk")
    
    # Check for S3 buckets without public access block
    if re.search(r'resource\s+"aws_s3_bucket"', content) and not re.search(r'block_public_acls\s*=\s*true', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'S3 bucket is created without public access block configuration',
            'Recommendation': 'Add aws_s3_bucket_public_access_block resource to prevent public access'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates S3 bucket without public access block - HIGH risk")
    
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
    
    # Check for security groups with open IPv6 access
    if re.search(r'resource\s+"aws_security_group"', content) and re.search(r'ipv6_cidr_blocks\s*=\s*\[\s*"::/0"\s*\]', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'Security group allows access from any IPv6 address (::/0)',
            'Recommendation': 'Restrict security group rules to specific IPv6 ranges'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} has open IPv6 security group - HIGH risk")
    
    # Check for security groups with sensitive ports open
    sensitive_ports = [22, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 9300, 8080, 8443]
    for port in sensitive_ports:
        if re.search(r'resource\s+"aws_security_group_rule"', content) and re.search(r'type\s*=\s*"ingress"', content) and re.search(f'from_port\s*=\s*{port}', content) and re.search(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', content):
            findings.append({
                'ResourceType': 'Terraform File',
                'ResourceId': file_path,
                'ResourceName': os.path.basename(file_path),
                'Risk': 'HIGH',
                'Issue': f'Security group rule allows public access to sensitive port {port}',
                'Recommendation': 'Restrict access to specific IP ranges'
            })
            print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} exposes port {port} to public - HIGH risk")
    
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
    
    # Check for IAM users with console access but no MFA requirement
    if re.search(r'resource\s+"aws_iam_user_login_profile"', content) and not re.search(r'resource\s+"aws_iam_user_mfa"', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'IAM user with console access but no MFA requirement',
            'Recommendation': 'Enforce MFA for IAM users with console access'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates IAM user without MFA - HIGH risk")
    
    # Check for unencrypted RDS instances
    if re.search(r'resource\s+"aws_db_instance"', content) and re.search(r'storage_encrypted\s*=\s*false', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance is configured without encryption',
            'Recommendation': 'Enable storage encryption for RDS instances'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates unencrypted RDS - HIGH risk")
    
    # Check for RDS instances without encryption (default is false)
    if re.search(r'resource\s+"aws_db_instance"', content) and not re.search(r'storage_encrypted\s*=\s*true', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance is created without explicitly enabling encryption',
            'Recommendation': 'Explicitly enable storage encryption for RDS instances'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates RDS without explicit encryption - HIGH risk")
    
    # Check for public RDS instances
    if re.search(r'resource\s+"aws_db_instance"', content) and re.search(r'publicly_accessible\s*=\s*true', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance is configured with public access',
            'Recommendation': 'Disable public access for RDS instances'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates public RDS instance - HIGH risk")
    
    # Check for RDS instances without backup
    if re.search(r'resource\s+"aws_db_instance"', content) and re.search(r'backup_retention_period\s*=\s*0', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance has backups disabled',
            'Recommendation': 'Enable backups for RDS instances'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} disables RDS backups - HIGH risk")
    
    # Check for RDS instances with short backup retention
    if re.search(r'resource\s+"aws_db_instance"', content) and re.search(r'backup_retention_period\s*=\s*[1-6]', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'RDS instance has short backup retention period',
            'Recommendation': 'Set backup retention period to at least 7 days'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} has short RDS backup retention - MEDIUM risk")
    
    # Check for EC2 instances without IMDSv2
    if re.search(r'resource\s+"aws_instance"', content) and not re.search(r'metadata_options\s*{[^}]*http_tokens\s*=\s*"required"', content, re.DOTALL):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'EC2 instance is not configured to use IMDSv2',
            'Recommendation': 'Set http_tokens to required in metadata_options'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates EC2 without IMDSv2 - MEDIUM risk")
    
    # Check for unencrypted EBS volumes
    if re.search(r'resource\s+"aws_ebs_volume"', content) and not re.search(r'encrypted\s*=\s*true', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'EBS volume is created without encryption',
            'Recommendation': 'Enable encryption for EBS volumes'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates unencrypted EBS volume - HIGH risk")
    
    # Check for CloudTrail without log validation
    if re.search(r'resource\s+"aws_cloudtrail"', content) and re.search(r'enable_log_file_validation\s*=\s*false', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'CloudTrail is configured without log file validation',
            'Recommendation': 'Enable log file validation for CloudTrail'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} disables CloudTrail log validation - MEDIUM risk")
    
    # Check for CloudTrail without encryption
    if re.search(r'resource\s+"aws_cloudtrail"', content) and not re.search(r'kms_key_id\s*=', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'CloudTrail is configured without encryption',
            'Recommendation': 'Enable encryption for CloudTrail logs using KMS'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates CloudTrail without encryption - MEDIUM risk")
    
    # Check for API Gateway without authorization
    if re.search(r'resource\s+"aws_api_gateway_method"', content) and re.search(r'authorization\s*=\s*"NONE"', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'API Gateway method is configured without authorization',
            'Recommendation': 'Configure authorization for API Gateway methods'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates API Gateway without auth - HIGH risk")
    
    # Check for Lambda functions without VPC
    if re.search(r'resource\s+"aws_lambda_function"', content) and not re.search(r'vpc_config\s*{', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'LOW',
            'Issue': 'Lambda function is created without VPC configuration',
            'Recommendation': 'Consider placing Lambda functions in a VPC for better network isolation'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates Lambda without VPC - LOW risk")
    
    # Check for Lambda functions without X-Ray tracing
    if re.search(r'resource\s+"aws_lambda_function"', content) and not re.search(r'tracing_config\s*{[^}]*mode\s*=\s*"Active"', content, re.DOTALL):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'LOW',
            'Issue': 'Lambda function is created without X-Ray tracing',
            'Recommendation': 'Enable X-Ray tracing for better monitoring and debugging'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates Lambda without X-Ray - LOW risk")
    
    # Check for DynamoDB tables without encryption
    if re.search(r'resource\s+"aws_dynamodb_table"', content) and not re.search(r'server_side_encryption\s*{', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'DynamoDB table is created without encryption configuration',
            'Recommendation': 'Enable server-side encryption for DynamoDB tables'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates unencrypted DynamoDB table - MEDIUM risk")
    
    # Check for DynamoDB tables without point-in-time recovery
    if re.search(r'resource\s+"aws_dynamodb_table"', content) and not re.search(r'point_in_time_recovery\s*{[^}]*enabled\s*=\s*true', content, re.DOTALL):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'DynamoDB table is created without point-in-time recovery',
            'Recommendation': 'Enable point-in-time recovery for DynamoDB tables'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates DynamoDB without PITR - MEDIUM risk")
    
    # Check for missing VPC Flow Logs
    if re.search(r'resource\s+"aws_vpc"', content) and not re.search(r'resource\s+"aws_flow_log"', content):
        findings.append({
            'ResourceType': 'Terraform File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'VPC is created without Flow Logs',
            'Recommendation': 'Enable Flow Logs for VPCs to monitor network traffic'
        })
        print(f"    [!] FINDING: Terraform file {os.path.basename(file_path)} creates VPC without Flow Logs - MEDIUM risk")
    
    return findings