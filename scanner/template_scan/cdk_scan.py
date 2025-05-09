"""
AWS CDK Scanner Module - Detects security issues in AWS CDK code
"""
import os
import re
from pathlib import Path


def scan_cdk_code(directory):
    """
    Scan AWS CDK code for security issues like:
    - Insecure constructs
    - Missing encryption
    - Public access configurations
    - Overly permissive IAM policies
    
    Args:
        directory (str): Directory containing CDK code to scan
    
    Returns:
        list: List of dictionaries containing vulnerable code
    """
    findings = []
    
    print("Starting AWS CDK code scan...")
    
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a valid directory")
        return findings
    
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
    
    if findings:
        print(f"Found {len(findings)} CDK security issues.")
    else:
        print("No CDK security issues found.")
    
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
    
    # Check for S3 buckets without versioning
    if re.search(r'new\s+s3\.Bucket\(', content) and not re.search(r'versioned\s*:\s*true', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'S3 bucket is created without versioning',
            'Recommendation': 'Enable versioning for S3 buckets to protect against accidental deletion'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} creates S3 bucket without versioning - MEDIUM risk")
    
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
    
    # Check for Lambda functions without X-Ray tracing
    if re.search(r'new\s+lambda\.Function\(', content) and not re.search(r'tracing\s*:\s*lambda\.Tracing\.ACTIVE', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'LOW',
            'Issue': 'Lambda function is created without X-Ray tracing',
            'Recommendation': 'Enable X-Ray tracing for better monitoring and debugging'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} creates Lambda without X-Ray - LOW risk")
    
    # Check for Lambda functions with environment variables but no encryption
    if re.search(r'new\s+lambda\.Function\(', content) and re.search(r'environment\s*:', content) and not re.search(r'environmentEncryption\s*:', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'Lambda function has environment variables without custom encryption',
            'Recommendation': 'Use environmentEncryption to specify a KMS key for environment variable encryption'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} has Lambda with unencrypted env vars - MEDIUM risk")
    
    # Check for RDS instances without encryption
    if re.search(r'new\s+rds\.(Cluster|Instance)\(', content) and not re.search(r'storageEncrypted\s*:\s*true', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance/cluster is created without encryption',
            'Recommendation': 'Enable storage encryption for RDS instances/clusters'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} creates unencrypted RDS - HIGH risk")
    
    # Check for public RDS instances
    if re.search(r'new\s+rds\.Instance\(', content) and re.search(r'publiclyAccessible\s*:\s*true', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'RDS instance is configured with public access',
            'Recommendation': 'Disable public access for RDS instances'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} creates public RDS instance - HIGH risk")
    
    # Check for RDS instances without backup
    if re.search(r'new\s+rds\.Instance\(', content) and (re.search(r'backupRetention\s*:\s*cdk\.Duration\.days\(\s*[0-6]\s*\)', content) or not re.search(r'backupRetention\s*:', content)):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'RDS instance has insufficient backup retention period',
            'Recommendation': 'Set backup retention period to at least 7 days'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} has RDS with insufficient backup - MEDIUM risk")
    
    # Check for security groups with open access
    if re.search(r'addIngressRule\(', content) and re.search(r'Peer\.anyIpv4\(\)', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'Security group allows access from any IPv4 address (0.0.0.0/0)',
            'Recommendation': 'Restrict security group rules to specific IP ranges'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} has open security group - HIGH risk")
    
    # Check for security groups with open IPv6 access
    if re.search(r'addIngressRule\(', content) and re.search(r'Peer\.anyIpv6\(\)', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'Security group allows access from any IPv6 address (::/0)',
            'Recommendation': 'Restrict security group rules to specific IP ranges'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} has open IPv6 security group - HIGH risk")
    
    # Check for security groups with sensitive ports open
    sensitive_ports = [22, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 9300, 8080, 8443]
    for port in sensitive_ports:
        if re.search(r'addIngressRule\(', content) and re.search(f'Port\.tcp\({port}\)', content) and re.search(r'Peer\.anyIpv4\(\)', content):
            findings.append({
                'ResourceType': 'CDK File',
                'ResourceId': file_path,
                'ResourceName': os.path.basename(file_path),
                'Risk': 'HIGH',
                'Issue': f'Security group allows public access to sensitive port {port}',
                'Recommendation': 'Restrict access to specific IP ranges'
            })
            print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} exposes port {port} to public - HIGH risk")
    
    # Check for CloudFront without WAF
    if re.search(r'new\s+cloudfront\.Distribution\(', content) and not re.search(r'webAclId\s*:', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'CloudFront distribution is created without WAF',
            'Recommendation': 'Associate a WAF Web ACL with CloudFront distributions'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} creates CloudFront without WAF - MEDIUM risk")
    
    # Check for CloudFront with insecure SSL/TLS policy
    if re.search(r'new\s+cloudfront\.Distribution\(', content) and re.search(r'minimumProtocolVersion\s*:\s*cloudfront\.SecurityPolicyProtocol\.(SSL_V3|TLS_V1|TLS_V1_2016|TLS_V1_1_2016)', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'CloudFront distribution uses outdated SSL/TLS protocol',
            'Recommendation': 'Use at least TLS_V1_2_2018 or TLS_V1_2_2019'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} uses outdated TLS for CloudFront - HIGH risk")
    
    # Check for API Gateway without authorization
    if re.search(r'new\s+apigateway\.(RestApi|HttpApi)\(', content) and not re.search(r'authorizer\s*:', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'HIGH',
            'Issue': 'API Gateway is created without authorization',
            'Recommendation': 'Configure an authorizer for API Gateway'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} creates API Gateway without authorization - HIGH risk")
    
    # Check for DynamoDB tables without encryption
    if re.search(r'new\s+dynamodb\.Table\(', content) and not re.search(r'encryption\s*:\s*dynamodb\.TableEncryption\.(CUSTOMER_MANAGED|AWS_MANAGED)', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'DynamoDB table is created without explicit encryption configuration',
            'Recommendation': 'Specify encryption type for DynamoDB tables'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} creates DynamoDB without explicit encryption - MEDIUM risk")
    
    # Check for DynamoDB tables without point-in-time recovery
    if re.search(r'new\s+dynamodb\.Table\(', content) and not re.search(r'pointInTimeRecovery\s*:\s*true', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'DynamoDB table is created without point-in-time recovery',
            'Recommendation': 'Enable point-in-time recovery for DynamoDB tables'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} creates DynamoDB without PITR - MEDIUM risk")
    
    # Check for ECS tasks without logging
    if re.search(r'new\s+ecs\.(Ec2|Fargate)TaskDefinition\(', content) and not re.search(r'logging\s*:', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'ECS task definition is created without logging configuration',
            'Recommendation': 'Configure logging for ECS tasks'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} creates ECS task without logging - MEDIUM risk")
    
    # Check for missing VPC Flow Logs
    if re.search(r'new\s+ec2\.Vpc\(', content) and not re.search(r'flowLogs\s*:', content):
        findings.append({
            'ResourceType': 'CDK File',
            'ResourceId': file_path,
            'ResourceName': os.path.basename(file_path),
            'Risk': 'MEDIUM',
            'Issue': 'VPC is created without Flow Logs',
            'Recommendation': 'Enable Flow Logs for VPCs to monitor network traffic'
        })
        print(f"    [!] FINDING: CDK file {os.path.basename(file_path)} creates VPC without Flow Logs - MEDIUM risk")
    
    return findings