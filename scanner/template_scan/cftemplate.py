"""
CloudFormation Template Scanner Module - Detects security issues in CloudFormation templates
"""
import os
import json
import yaml
import re
import boto3
from botocore.exceptions import ClientError


def scan_cloudformation_templates(directory=None, region=None):
    """
    Scan CloudFormation templates for security issues like:
    - Hardcoded secrets
    - Insecure IAM permissions
    - Unencrypted resources
    - Public access configurations
    - Missing security controls
    
    Args:
        directory (str, optional): Directory containing CloudFormation templates. If None, scan deployed stacks.
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting CloudFormation template scan...")
    
    # Scan local templates if directory is provided
    if directory:
        findings.extend(scan_local_templates(directory))
    
    # Scan deployed stacks
    findings.extend(scan_deployed_stacks(region))
    
    if findings:
        print(f"Found {len(findings)} CloudFormation template security issues.")
    else:
        print("No CloudFormation template security issues found.")
    
    return findings


def scan_local_templates(directory):
    """Scan local CloudFormation templates for security issues"""
    findings = []
    
    print(f"Scanning local CloudFormation templates in {directory}...")
    
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a valid directory")
        return findings
    
    template_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.json', '.yaml', '.yml', '.template')):
                template_files.append(os.path.join(root, file))
    
    print(f"Found {len(template_files)} potential CloudFormation template files")
    
    for template_file in template_files:
        try:
            # Load template content
            with open(template_file, 'r') as f:
                content = f.read()
            
            # Parse template based on file extension
            template = None
            if template_file.endswith('.json'):
                template = json.loads(content)
            else:  # YAML files
                template = yaml.safe_load(content)
            
            # Check if it's a CloudFormation template
            if not isinstance(template, dict) or 'Resources' not in template:
                continue
            
            print(f"Scanning template: {template_file}")
            
            # Check for hardcoded secrets
            check_hardcoded_secrets(template_file, content, findings)
            
            # Check for insecure IAM permissions
            check_iam_permissions(template_file, template, findings)
            
            # Check for unencrypted resources
            check_unencrypted_resources(template_file, template, findings)
            
            # Check for public access configurations
            check_public_access(template_file, template, findings)
            
            # Check for missing security controls
            check_missing_security_controls(template_file, template, findings)
        
        except Exception as e:
            print(f"Error scanning template {template_file}: {e}")
    
    return findings


def scan_deployed_stacks(region=None):
    """Scan deployed CloudFormation stacks for security issues"""
    findings = []
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
            print(f"Scanning deployed stacks in region: {region}")
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
            print(f"Scanning deployed stacks in {len(regions)} regions")
        
        region_count = 0
        total_stack_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            cf_client = boto3.client('cloudformation', region_name=current_region)
            
            try:
                # Get all stacks
                stacks = []
                paginator = cf_client.get_paginator('list_stacks')
                
                for page in paginator.paginate(StackStatusFilter=[
                    'CREATE_COMPLETE', 'UPDATE_COMPLETE', 'ROLLBACK_COMPLETE', 
                    'UPDATE_ROLLBACK_COMPLETE'
                ]):
                    stacks.extend(page.get('StackSummaries', []))
                
                stack_count = len(stacks)
                
                if stack_count > 0:
                    total_stack_count += stack_count
                    print(f"  Found {stack_count} CloudFormation stacks in {current_region}")
                    
                    for i, stack in enumerate(stacks, 1):
                        stack_name = stack.get('StackName')
                        
                        # Print progress every 5 stacks or for the last one
                        if i % 5 == 0 or i == stack_count:
                            print(f"  Progress: {i}/{stack_count}")
                        
                        try:
                            # Get stack template
                            template_response = cf_client.get_template(
                                StackName=stack_name,
                                TemplateStage='Original'
                            )
                            
                            template_body = template_response.get('TemplateBody')
                            if isinstance(template_body, str):
                                if template_body.strip().startswith('{'):
                                    template = json.loads(template_body)
                                else:
                                    template = yaml.safe_load(template_body)
                            else:
                                template = template_body
                            
                            # Check for insecure IAM permissions
                            check_iam_permissions(stack_name, template, findings, current_region)
                            
                            # Check for unencrypted resources
                            check_unencrypted_resources(stack_name, template, findings, current_region)
                            
                            # Check for public access configurations
                            check_public_access(stack_name, template, findings, current_region)
                            
                            # Check for missing security controls
                            check_missing_security_controls(stack_name, template, findings, current_region)
                        
                        except ClientError as e:
                            print(f"    Error getting template for stack {stack_name}: {e}")
            
            except ClientError as e:
                print(f"  Error scanning CloudFormation stacks in {current_region}: {e}")
        
        if total_stack_count == 0:
            print("No CloudFormation stacks found.")
        else:
            print(f"CloudFormation stack scan complete. Scanned {total_stack_count} stacks.")
    
    except Exception as e:
        print(f"Error scanning CloudFormation stacks: {e}")
    
    return findings


def check_hardcoded_secrets(template_file, content, findings):
    """Check for hardcoded secrets in template content"""
    # Patterns for potential secrets
    secret_patterns = [
        (r'(?i)(password|passwd|pwd|secret|key|token|credential)["\']?\s*[:=]\s*["\']([^"\'{}]+)["\']', 'Password/Secret'),
        (r'(?i)aws_access_key_id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']', 'AWS Access Key'),
        (r'(?i)aws_secret_access_key["\']?\s*[:=]\s*["\']([A-Za-z0-9+/]{40})["\']', 'AWS Secret Key'),
        (r'(?i)api[_\-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9]{20,})["\']', 'API Key'),
        (r'(?i)token["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', 'Token'),
        (r'(?i)bearer["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', 'Bearer Token'),
        (r'(?i)private[_\-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9+/=]{20,})["\']', 'Private Key')
    ]
    
    for pattern, secret_type in secret_patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            # Skip if the value is a reference or parameter
            value = match[1] if isinstance(match, tuple) else match
            if '{{' in value or '${' in value or '!Ref' in value or '!GetAtt' in value or '!Sub' in value:
                continue
                
            findings.append({
                'ResourceType': 'CloudFormation Template',
                'ResourceId': template_file,
                'ResourceName': os.path.basename(template_file),
                'Region': 'local',
                'Risk': 'CRITICAL',
                'Issue': f'Potential hardcoded {secret_type} found in template',
                'Recommendation': 'Use AWS Secrets Manager, Parameter Store, or dynamic references instead of hardcoding secrets'
            })
            print(f"    [!] FINDING: Template {os.path.basename(template_file)} contains hardcoded {secret_type} - CRITICAL risk")
            break  # Only report once per secret type per file


def check_iam_permissions(template_id, template, findings, region='local'):
    """Check for insecure IAM permissions in template"""
    resources = template.get('Resources', {})
    
    for resource_id, resource in resources.items():
        resource_type = resource.get('Type', '')
        
        # Check IAM roles and policies
        if resource_type in ['AWS::IAM::Role', 'AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy']:
            properties = resource.get('Properties', {})
            
            # Check for wildcard actions with wildcard resources
            policy_document = properties.get('PolicyDocument', {})
            if not policy_document and 'Policies' in properties:
                for policy in properties.get('Policies', []):
                    policy_document = policy.get('PolicyDocument', {})
                    check_policy_document(template_id, resource_id, policy_document, findings, region)
            else:
                check_policy_document(template_id, resource_id, policy_document, findings, region)


def check_policy_document(template_id, resource_id, policy_document, findings, region):
    """Check IAM policy document for insecure permissions"""
    statements = policy_document.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    
    for statement in statements:
        effect = statement.get('Effect', '')
        if effect != 'Allow':
            continue
        
        actions = statement.get('Action', [])
        if not isinstance(actions, list):
            actions = [actions]
        
        resources = statement.get('Resource', [])
        if not isinstance(resources, list):
            resources = [resources]
        
        # Check for wildcard actions with wildcard resources
        has_wildcard_action = False
        for action in actions:
            if action == '*' or action.endswith('*'):
                has_wildcard_action = True
                break
        
        has_wildcard_resource = False
        for resource in resources:
            if resource == '*':
                has_wildcard_resource = True
                break
        
        if has_wildcard_action and has_wildcard_resource:
            findings.append({
                'ResourceType': 'IAM Policy',
                'ResourceId': resource_id,
                'ResourceName': resource_id,
                'Region': region,
                'Risk': 'HIGH',
                'Issue': 'IAM policy contains wildcard actions (*) with wildcard resources (*)',
                'Recommendation': 'Follow the principle of least privilege by specifying only necessary actions and resources'
            })
            print(f"    [!] FINDING: IAM policy {resource_id} in {template_id} has wildcard permissions - HIGH risk")


def check_unencrypted_resources(template_id, template, findings, region='local'):
    """Check for unencrypted resources in template"""
    resources = template.get('Resources', {})
    
    for resource_id, resource in resources.items():
        resource_type = resource.get('Type', '')
        properties = resource.get('Properties', {})
        
        # Check S3 buckets
        if resource_type == 'AWS::S3::Bucket':
            encryption = properties.get('BucketEncryption', {})
            if not encryption:
                findings.append({
                    'ResourceType': 'S3 Bucket',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'HIGH',
                    'Issue': 'S3 bucket is not configured with encryption',
                    'Recommendation': 'Enable default encryption for S3 buckets'
                })
                print(f"    [!] FINDING: S3 bucket {resource_id} in {template_id} is not encrypted - HIGH risk")
        
        # Check RDS instances
        elif resource_type in ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster']:
            storage_encrypted = properties.get('StorageEncrypted', False)
            if not storage_encrypted:
                findings.append({
                    'ResourceType': 'RDS Instance',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'HIGH',
                    'Issue': 'RDS instance/cluster is not configured with encryption',
                    'Recommendation': 'Enable storage encryption for RDS instances/clusters'
                })
                print(f"    [!] FINDING: RDS {resource_id} in {template_id} is not encrypted - HIGH risk")
        
        # Check EBS volumes
        elif resource_type == 'AWS::EC2::Volume':
            encrypted = properties.get('Encrypted', False)
            if not encrypted:
                findings.append({
                    'ResourceType': 'EBS Volume',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'HIGH',
                    'Issue': 'EBS volume is not configured with encryption',
                    'Recommendation': 'Enable encryption for EBS volumes'
                })
                print(f"    [!] FINDING: EBS volume {resource_id} in {template_id} is not encrypted - HIGH risk")
        
        # Check DynamoDB tables
        elif resource_type == 'AWS::DynamoDB::Table':
            sse_specification = properties.get('SSESpecification', {})
            if not sse_specification or not sse_specification.get('SSEEnabled', False):
                findings.append({
                    'ResourceType': 'DynamoDB Table',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'MEDIUM',
                    'Issue': 'DynamoDB table is not configured with encryption',
                    'Recommendation': 'Enable server-side encryption for DynamoDB tables'
                })
                print(f"    [!] FINDING: DynamoDB table {resource_id} in {template_id} is not encrypted - MEDIUM risk")
        
        # Check Lambda functions
        elif resource_type == 'AWS::Lambda::Function':
            # Check for environment variable encryption
            if properties.get('Environment') and not properties.get('KmsKeyArn'):
                findings.append({
                    'ResourceType': 'Lambda Function',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'MEDIUM',
                    'Issue': 'Lambda function environment variables are not encrypted with a customer-managed KMS key',
                    'Recommendation': 'Specify a KmsKeyArn to encrypt environment variables'
                })
                print(f"    [!] FINDING: Lambda function {resource_id} in {template_id} has unencrypted env vars - MEDIUM risk")
        
        # Check SQS queues
        elif resource_type == 'AWS::SQS::Queue':
            if not properties.get('KmsMasterKeyId'):
                findings.append({
                    'ResourceType': 'SQS Queue',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'MEDIUM',
                    'Issue': 'SQS queue is not configured with encryption',
                    'Recommendation': 'Specify KmsMasterKeyId to enable server-side encryption'
                })
                print(f"    [!] FINDING: SQS queue {resource_id} in {template_id} is not encrypted - MEDIUM risk")
        
        # Check SNS topics
        elif resource_type == 'AWS::SNS::Topic':
            if not properties.get('KmsMasterKeyId'):
                findings.append({
                    'ResourceType': 'SNS Topic',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'MEDIUM',
                    'Issue': 'SNS topic is not configured with encryption',
                    'Recommendation': 'Specify KmsMasterKeyId to enable server-side encryption'
                })
                print(f"    [!] FINDING: SNS topic {resource_id} in {template_id} is not encrypted - MEDIUM risk")
        
        # Check Elasticsearch domains
        elif resource_type == 'AWS::Elasticsearch::Domain':
            encryption_options = properties.get('EncryptionAtRestOptions', {})
            if not encryption_options.get('Enabled', False):
                findings.append({
                    'ResourceType': 'Elasticsearch Domain',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'HIGH',
                    'Issue': 'Elasticsearch domain is not configured with encryption at rest',
                    'Recommendation': 'Enable encryption at rest for Elasticsearch domains'
                })
                print(f"    [!] FINDING: Elasticsearch domain {resource_id} in {template_id} is not encrypted - HIGH risk")
        
        # Check Redshift clusters
        elif resource_type == 'AWS::Redshift::Cluster':
            if not properties.get('Encrypted', False):
                findings.append({
                    'ResourceType': 'Redshift Cluster',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'HIGH',
                    'Issue': 'Redshift cluster is not configured with encryption',
                    'Recommendation': 'Enable encryption for Redshift clusters'
                })
                print(f"    [!] FINDING: Redshift cluster {resource_id} in {template_id} is not encrypted - HIGH risk")
        
        # Check Neptune clusters
        elif resource_type == 'AWS::Neptune::DBCluster':
            if not properties.get('StorageEncrypted', False):
                findings.append({
                    'ResourceType': 'Neptune Cluster',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'HIGH',
                    'Issue': 'Neptune cluster is not configured with encryption',
                    'Recommendation': 'Enable storage encryption for Neptune clusters'
                })
                print(f"    [!] FINDING: Neptune cluster {resource_id} in {template_id} is not encrypted - HIGH risk")
        
        # Check DocumentDB clusters
        elif resource_type == 'AWS::DocDB::DBCluster':
            if not properties.get('StorageEncrypted', False):
                findings.append({
                    'ResourceType': 'DocumentDB Cluster',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'HIGH',
                    'Issue': 'DocumentDB cluster is not configured with encryption',
                    'Recommendation': 'Enable storage encryption for DocumentDB clusters'
                })
                print(f"    [!] FINDING: DocumentDB cluster {resource_id} in {template_id} is not encrypted - HIGH risk")
        
        # Check Kinesis streams
        elif resource_type == 'AWS::Kinesis::Stream':
            if not properties.get('StreamEncryption'):
                findings.append({
                    'ResourceType': 'Kinesis Stream',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'MEDIUM',
                    'Issue': 'Kinesis stream is not configured with encryption',
                    'Recommendation': 'Configure StreamEncryption for Kinesis streams'
                })
                print(f"    [!] FINDING: Kinesis stream {resource_id} in {template_id} is not encrypted - MEDIUM risk")
        
        # Check CloudWatch Logs
        elif resource_type == 'AWS::Logs::LogGroup':
            if not properties.get('KmsKeyId'):
                findings.append({
                    'ResourceType': 'CloudWatch Log Group',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'LOW',
                    'Issue': 'CloudWatch Log Group is not configured with encryption',
                    'Recommendation': 'Specify KmsKeyId to encrypt log data'
                })
                print(f"    [!] FINDING: CloudWatch Log Group {resource_id} in {template_id} is not encrypted - LOW risk")


def check_public_access(template_id, template, findings, region='local'):
    """Check for public access configurations in template"""
    resources = template.get('Resources', {})
    
    for resource_id, resource in resources.items():
        resource_type = resource.get('Type', '')
        properties = resource.get('Properties', {})
        
        # Check S3 buckets
        if resource_type == 'AWS::S3::Bucket':
            public_access_block = properties.get('PublicAccessBlockConfiguration', {})
            if not public_access_block:
                findings.append({
                    'ResourceType': 'S3 Bucket',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'HIGH',
                    'Issue': 'S3 bucket does not have public access block configuration',
                    'Recommendation': 'Add PublicAccessBlockConfiguration to prevent public access'
                })
                print(f"    [!] FINDING: S3 bucket {resource_id} in {template_id} has no public access block - HIGH risk")
            
            # Check for public ACL
            if properties.get('AccessControl') in ['PublicRead', 'PublicReadWrite']:
                findings.append({
                    'ResourceType': 'S3 Bucket',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'CRITICAL',
                    'Issue': f'S3 bucket has public ACL: {properties.get("AccessControl")}',
                    'Recommendation': 'Remove public ACL and use bucket policies for controlled access'
                })
                print(f"    [!] FINDING: S3 bucket {resource_id} in {template_id} has public ACL - CRITICAL risk")
            
            # Check for website configuration without proper security
            if properties.get('WebsiteConfiguration') and not public_access_block:
                findings.append({
                    'ResourceType': 'S3 Bucket',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'HIGH',
                    'Issue': 'S3 bucket is configured as a website without proper public access controls',
                    'Recommendation': 'Use CloudFront with OAI instead of direct S3 website access'
                })
                print(f"    [!] FINDING: S3 bucket {resource_id} in {template_id} is a website without proper controls - HIGH risk")
        
        # Check security groups
        elif resource_type == 'AWS::EC2::SecurityGroup':
            ingress_rules = properties.get('SecurityGroupIngress', [])
            for rule in ingress_rules:
                cidr_ip = rule.get('CidrIp', '')
                cidr_ipv6 = rule.get('CidrIpv6', '')
                
                if cidr_ip == '0.0.0.0/0' or cidr_ipv6 == '::/0':
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    
                    # Check for sensitive ports
                    sensitive_ports = [22, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 9300, 8080, 8443]
                    for port in sensitive_ports:
                        if from_port <= port <= to_port:
                            findings.append({
                                'ResourceType': 'Security Group',
                                'ResourceId': resource_id,
                                'ResourceName': resource_id,
                                'Region': region,
                                'Risk': 'HIGH',
                                'Issue': f'Security group allows public access ({cidr_ip or cidr_ipv6}) to sensitive port {port}',
                                'Recommendation': 'Restrict access to specific IP ranges'
                            })
                            print(f"    [!] FINDING: Security group {resource_id} in {template_id} allows public access to port {port} - HIGH risk")
                            break
                    
                    # Check for all ports open
                    if from_port == 0 and to_port == 65535:
                        findings.append({
                            'ResourceType': 'Security Group',
                            'ResourceId': resource_id,
                            'ResourceName': resource_id,
                            'Region': region,
                            'Risk': 'CRITICAL',
                            'Issue': f'Security group allows public access ({cidr_ip or cidr_ipv6}) to ALL ports',
                            'Recommendation': 'Restrict access to specific ports and IP ranges'
                        })
                        print(f"    [!] FINDING: Security group {resource_id} in {template_id} allows public access to ALL ports - CRITICAL risk")
        
        # Check RDS instances
        elif resource_type == 'AWS::RDS::DBInstance':
            publicly_accessible = properties.get('PubliclyAccessible', False)
            if publicly_accessible:
                findings.append({
                    'ResourceType': 'RDS Instance',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'HIGH',
                    'Issue': 'RDS instance is publicly accessible',
                    'Recommendation': 'Set PubliclyAccessible to false and use private subnets'
                })
                print(f"    [!] FINDING: RDS instance {resource_id} in {template_id} is publicly accessible - HIGH risk")
        
        # Check Elasticsearch domains
        elif resource_type == 'AWS::Elasticsearch::Domain':
            access_policies = properties.get('AccessPolicies', {})
            if isinstance(access_policies, dict):
                statements = access_policies.get('Statement', [])
                if isinstance(statements, list):
                    for statement in statements:
                        principal = statement.get('Principal', {})
                        if principal == '*' or principal.get('AWS') == '*':
                            findings.append({
                                'ResourceType': 'Elasticsearch Domain',
                                'ResourceId': resource_id,
                                'ResourceName': resource_id,
                                'Region': region,
                                'Risk': 'HIGH',
                                'Issue': 'Elasticsearch domain allows public access',
                                'Recommendation': 'Restrict access to specific principals'
                            })
                            print(f"    [!] FINDING: Elasticsearch domain {resource_id} in {template_id} allows public access - HIGH risk")
                            break
        
        # Check Lambda function URLs
        elif resource_type == 'AWS::Lambda::Url':
            auth_type = properties.get('AuthType', '')
            if auth_type == 'NONE':
                findings.append({
                    'ResourceType': 'Lambda Function URL',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'HIGH',
                    'Issue': 'Lambda function URL has no authentication',
                    'Recommendation': 'Set AuthType to AWS_IAM to require authentication'
                })
                print(f"    [!] FINDING: Lambda function URL {resource_id} in {template_id} has no auth - HIGH risk")
        
        # Check API Gateway methods
        elif resource_type == 'AWS::ApiGateway::Method':
            auth_type = properties.get('AuthorizationType', '')
            if auth_type == 'NONE':
                findings.append({
                    'ResourceType': 'API Gateway Method',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'HIGH',
                    'Issue': 'API Gateway method has no authorization',
                    'Recommendation': 'Configure authorization for API Gateway methods'
                })
                print(f"    [!] FINDING: API Gateway method {resource_id} in {template_id} has no auth - HIGH risk")
        
        # Check EFS file systems
        elif resource_type == 'AWS::EFS::FileSystem':
            policy = properties.get('FileSystemPolicy', {})
            if isinstance(policy, dict):
                statements = policy.get('Statement', [])
                if isinstance(statements, list):
                    for statement in statements:
                        principal = statement.get('Principal', {})
                        if principal == '*' or principal.get('AWS') == '*':
                            findings.append({
                                'ResourceType': 'EFS File System',
                                'ResourceId': resource_id,
                                'ResourceName': resource_id,
                                'Region': region,
                                'Risk': 'HIGH',
                                'Issue': 'EFS file system allows public access',
                                'Recommendation': 'Restrict access to specific principals'
                            })
                            print(f"    [!] FINDING: EFS file system {resource_id} in {template_id} allows public access - HIGH risk")
                            break
        
        # Check ECR repositories
        elif resource_type == 'AWS::ECR::Repository':
            policy = properties.get('RepositoryPolicyText', {})
            if isinstance(policy, dict):
                statements = policy.get('Statement', [])
                if isinstance(statements, list):
                    for statement in statements:
                        principal = statement.get('Principal', {})
                        if principal == '*' or principal.get('AWS') == '*':
                            findings.append({
                                'ResourceType': 'ECR Repository',
                                'ResourceId': resource_id,
                                'ResourceName': resource_id,
                                'Region': region,
                                'Risk': 'HIGH',
                                'Issue': 'ECR repository allows public access',
                                'Recommendation': 'Restrict access to specific principals'
                            })
                            print(f"    [!] FINDING: ECR repository {resource_id} in {template_id} allows public access - HIGH risk")
                            break
        
        # Check SQS queues
        elif resource_type == 'AWS::SQS::QueuePolicy':
            policy = properties.get('PolicyDocument', {})
            if isinstance(policy, dict):
                statements = policy.get('Statement', [])
                if isinstance(statements, list):
                    for statement in statements:
                        principal = statement.get('Principal', {})
                        if principal == '*' or principal.get('AWS') == '*':
                            findings.append({
                                'ResourceType': 'SQS Queue Policy',
                                'ResourceId': resource_id,
                                'ResourceName': resource_id,
                                'Region': region,
                                'Risk': 'HIGH',
                                'Issue': 'SQS queue policy allows public access',
                                'Recommendation': 'Restrict access to specific principals'
                            })
                            print(f"    [!] FINDING: SQS queue policy {resource_id} in {template_id} allows public access - HIGH risk")
                            break


def check_missing_security_controls(template_id, template, findings, region='local'):
    """Check for missing security controls in template"""
    resources = template.get('Resources', {})
    
    # Check for missing CloudTrail
    has_cloudtrail = False
    for resource in resources.values():
        if resource.get('Type') == 'AWS::CloudTrail::Trail':
            has_cloudtrail = True
            break
    
    if not has_cloudtrail and len(resources) > 10:  # Only suggest for non-trivial templates
        findings.append({
            'ResourceType': 'CloudFormation Template',
            'ResourceId': template_id,
            'ResourceName': os.path.basename(template_id) if isinstance(template_id, str) else template_id,
            'Region': region,
            'Risk': 'MEDIUM',
            'Issue': 'Template does not include CloudTrail configuration',
            'Recommendation': 'Consider adding CloudTrail for auditing and monitoring'
        })
        print(f"    [!] FINDING: Template {template_id} has no CloudTrail configuration - MEDIUM risk")
    
    # Check for EC2 instances without IMDSv2
    for resource_id, resource in resources.items():
        if resource.get('Type') == 'AWS::EC2::Instance' or resource.get('Type') == 'AWS::EC2::LaunchTemplate':
            properties = resource.get('Properties', {})
            metadata_options = properties.get('MetadataOptions', {})
            
            if not metadata_options or metadata_options.get('HttpTokens') != 'required':
                findings.append({
                    'ResourceType': 'EC2 Instance',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'MEDIUM',
                    'Issue': 'EC2 instance is not configured to use IMDSv2',
                    'Recommendation': 'Set HttpTokens to required in MetadataOptions'
                })
                print(f"    [!] FINDING: EC2 instance {resource_id} in {template_id} not using IMDSv2 - MEDIUM risk")
    
    # Check for missing VPC Flow Logs
    vpc_resources = [r for r_id, r in resources.items() if r.get('Type') == 'AWS::EC2::VPC']
    flow_log_resources = [r for r_id, r in resources.items() if r.get('Type') == 'AWS::EC2::FlowLog']
    
    if vpc_resources and not flow_log_resources:
        findings.append({
            'ResourceType': 'CloudFormation Template',
            'ResourceId': template_id,
            'ResourceName': os.path.basename(template_id) if isinstance(template_id, str) else template_id,
            'Region': region,
            'Risk': 'MEDIUM',
            'Issue': 'Template includes VPC but no Flow Logs',
            'Recommendation': 'Add VPC Flow Logs for network traffic monitoring'
        })
        print(f"    [!] FINDING: Template {template_id} has VPC without Flow Logs - MEDIUM risk")
    
    # Check for missing WAF on API Gateway or CloudFront
    api_gw_resources = [r for r_id, r in resources.items() if r.get('Type') in ['AWS::ApiGateway::RestApi', 'AWS::ApiGatewayV2::Api']]
    cloudfront_resources = [r for r_id, r in resources.items() if r.get('Type') == 'AWS::CloudFront::Distribution']
    waf_resources = [r for r_id, r in resources.items() if r.get('Type') in ['AWS::WAF::WebACL', 'AWS::WAFv2::WebACL']]
    
    if (api_gw_resources or cloudfront_resources) and not waf_resources:
        findings.append({
            'ResourceType': 'CloudFormation Template',
            'ResourceId': template_id,
            'ResourceName': os.path.basename(template_id) if isinstance(template_id, str) else template_id,
            'Region': region,
            'Risk': 'MEDIUM',
            'Issue': 'Template includes API Gateway or CloudFront but no WAF',
            'Recommendation': 'Add WAF for protection against common web exploits'
        })
        print(f"    [!] FINDING: Template {template_id} has API/CloudFront without WAF - MEDIUM risk")
    
    # Check for missing GuardDuty
    has_guardduty = False
    for resource in resources.values():
        if resource.get('Type') == 'AWS::GuardDuty::Detector':
            has_guardduty = True
            break
    
    if not has_guardduty and len(resources) > 15:  # Only suggest for larger templates
        findings.append({
            'ResourceType': 'CloudFormation Template',
            'ResourceId': template_id,
            'ResourceName': os.path.basename(template_id) if isinstance(template_id, str) else template_id,
            'Region': region,
            'Risk': 'LOW',
            'Issue': 'Template does not include GuardDuty configuration',
            'Recommendation': 'Consider adding GuardDuty for threat detection'
        })
        print(f"    [!] FINDING: Template {template_id} has no GuardDuty configuration - LOW risk")
    
    # Check for missing Config
    has_config = False
    for resource in resources.values():
        if resource.get('Type') in ['AWS::Config::ConfigurationRecorder', 'AWS::Config::DeliveryChannel']:
            has_config = True
            break
    
    if not has_config and len(resources) > 15:  # Only suggest for larger templates
        findings.append({
            'ResourceType': 'CloudFormation Template',
            'ResourceId': template_id,
            'ResourceName': os.path.basename(template_id) if isinstance(template_id, str) else template_id,
            'Region': region,
            'Risk': 'LOW',
            'Issue': 'Template does not include AWS Config configuration',
            'Recommendation': 'Consider adding AWS Config for resource compliance monitoring'
        })
        print(f"    [!] FINDING: Template {template_id} has no AWS Config configuration - LOW risk")
    
    # Check for S3 buckets without versioning
    for resource_id, resource in resources.items():
        if resource.get('Type') == 'AWS::S3::Bucket':
            properties = resource.get('Properties', {})
            versioning_config = properties.get('VersioningConfiguration', {})
            
            if not versioning_config or versioning_config.get('Status') != 'Enabled':
                findings.append({
                    'ResourceType': 'S3 Bucket',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'MEDIUM',
                    'Issue': 'S3 bucket does not have versioning enabled',
                    'Recommendation': 'Enable versioning for S3 buckets to protect against accidental deletion'
                })
                print(f"    [!] FINDING: S3 bucket {resource_id} in {template_id} has no versioning - MEDIUM risk")
    
    # Check for RDS instances without backup
    for resource_id, resource in resources.items():
        if resource.get('Type') == 'AWS::RDS::DBInstance':
            properties = resource.get('Properties', {})
            backup_retention = properties.get('BackupRetentionPeriod', 0)
            
            if backup_retention < 7:  # Less than 7 days
                findings.append({
                    'ResourceType': 'RDS Instance',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'MEDIUM',
                    'Issue': f'RDS instance has short backup retention period ({backup_retention} days)',
                    'Recommendation': 'Set backup retention period to at least 7 days'
                })
                print(f"    [!] FINDING: RDS instance {resource_id} in {template_id} has short backup retention - MEDIUM risk")
    
    # Check for Lambda functions without X-Ray tracing
    for resource_id, resource in resources.items():
        if resource.get('Type') == 'AWS::Lambda::Function':
            properties = resource.get('Properties', {})
            tracing_config = properties.get('TracingConfig', {})
            
            if not tracing_config or tracing_config.get('Mode') != 'Active':
                findings.append({
                    'ResourceType': 'Lambda Function',
                    'ResourceId': resource_id,
                    'ResourceName': resource_id,
                    'Region': region,
                    'Risk': 'LOW',
                    'Issue': 'Lambda function does not have X-Ray tracing enabled',
                    'Recommendation': 'Enable X-Ray tracing for better monitoring and debugging'
                })
                print(f"    [!] FINDING: Lambda function {resource_id} in {template_id} has no X-Ray tracing - LOW risk")
    
    # Check for missing CloudWatch alarms
    has_alarms = False
    for resource in resources.values():
        if resource.get('Type') == 'AWS::CloudWatch::Alarm':
            has_alarms = True
            break
    
    if not has_alarms and len(resources) > 10:  # Only suggest for non-trivial templates
        findings.append({
            'ResourceType': 'CloudFormation Template',
            'ResourceId': template_id,
            'ResourceName': os.path.basename(template_id) if isinstance(template_id, str) else template_id,
            'Region': region,
            'Risk': 'LOW',
            'Issue': 'Template does not include CloudWatch alarms',
            'Recommendation': 'Add CloudWatch alarms for monitoring critical resources'
        })
        print(f"    [!] FINDING: Template {template_id} has no CloudWatch alarms - LOW risk")
    
    return findings