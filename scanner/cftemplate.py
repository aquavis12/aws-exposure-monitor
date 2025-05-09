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
    
    return findings