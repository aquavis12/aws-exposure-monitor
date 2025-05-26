"""
Scanner Registry Module - Manages all available scanners
"""
import os
import importlib
import inspect
from typing import Dict, Callable, Optional, List, Any

# Define scanner registry type
ScannerRegistry = Dict[str, Dict[str, Any]]

def load_scanner(module_name: str, function_name: str) -> Optional[Callable]:
    """
    Dynamically load a scanner function from a module
    
    Args:
        module_name (str): Name of the module to import
        function_name (str): Name of the function to load
        
    Returns:
        Optional[Callable]: The scanner function if available, None otherwise
    """
    try:
        module = importlib.import_module(f"scanner.{module_name}")
        if hasattr(module, function_name):
            return getattr(module, function_name)
    except (ImportError, AttributeError):
        pass
    return None

def get_available_scanners() -> ScannerRegistry:
    """
    Get all available scanners
    
    Returns:
        ScannerRegistry: Dictionary of available scanners
    """
    # Define all scanners with their module and function names
    scanner_definitions = {
        # Compute Category
        'ec2': {
            'name': 'EC2 Instances',
            'module': 'ec2',
            'function': 'scan_ec2_instances',
            'description': 'Scans EC2 instances for IMDSv2, SSM agent, encryption, and public IP issues',
            'category': 'Compute'
        },
        'amis': {
            'name': 'AMIs',
            'module': 'amis',
            'function': 'scan_amis',
            'description': 'Scans AMIs for public sharing, launch permissions, and encryption issues',
            'category': 'Compute'
        },
        'ecr': {
            'name': 'ECR Repositories',
            'module': 'ecr',
            'function': 'scan_ecr_repositories',
            'description': 'Scans ECR repositories for public access policies and image scanning configuration',
            'category': 'Compute'
        },
        'lambda': {
            'name': 'Lambda Functions',
            'module': 'lambda_scanner',
            'function': 'scan_lambda_functions',
            'description': 'Scans Lambda functions for public access policies and function URL security',
            'category': 'Compute'
        },
        'lightsail': {
            'name': 'Lightsail Resources',
            'module': 'lightsail',
            'function': 'scan_lightsail',
            'description': 'Scans Lightsail instances, databases, and load balancers for security issues',
            'category': 'Compute'
        },
        
        # Security Category
        'iam': {
            'name': 'IAM Users and Access Keys',
            'module': 'iam',
            'function': 'scan_iam_users',
            'description': 'Scans IAM users for inactive accounts, old access keys, MFA, and privilege issues',
            'category': 'Security'
        },
        'sg': {
            'name': 'Security Groups',
            'module': 'sg',
            'function': 'scan_security_groups',
            'description': 'Scans security groups for overly permissive rules and sensitive port exposure',
            'category': 'Security'
        },
        'secrets': {
            'name': 'Secrets Manager and KMS',
            'module': 'secrets',
            'function': 'scan_secrets_and_keys',
            'description': 'Scans Secrets Manager secrets and KMS keys for rotation, usage, and policy issues',
            'category': 'Security'
        },
        'secrets_scanner': {
            'name': 'Hardcoded Secrets Scanner',
            'module': 'secrets_scanner',
            'function': 'scan_for_secrets',
            'description': 'Scans AWS resources for hardcoded secrets, API keys, and credentials',
            'category': 'Security'
        },
        'cloudwatch': {
            'name': 'CloudWatch Logs',
            'module': 'cw',
            'function': 'scan_cloudwatch_logs',
            'description': 'Scans CloudWatch Logs for encryption, retention, and security metric filters',
            'category': 'Security'
        },
        'config': {
            'name': 'AWS Config',
            'module': 'config',
            'function': 'scan_aws_config',
            'description': 'Scans AWS Config for proper configuration and recording of resources',
            'category': 'Security'
        },
        'cloudtrail': {
            'name': 'CloudTrail',
            'module': 'cloudtrail',
            'function': 'scan_cloudtrail',
            'description': 'Scans CloudTrail for proper logging, encryption, and file validation',
            'category': 'Security'
        },
        'guardduty': {
            'name': 'GuardDuty',
            'module': 'guardduty',
            'function': 'scan_guardduty',
            'description': 'Checks if GuardDuty is enabled and properly configured',
            'category': 'Security'
        },
        'waf': {
            'name': 'WAF Web ACLs',
            'module': 'waf',
            'function': 'scan_waf',
            'description': 'Scans WAF Web ACLs for rule configurations, logging, and resource associations',
            'category': 'Security'
        },
        
        # Database Category
        'rds': {
            'name': 'RDS Snapshots',
            'module': 'rds',
            'function': 'scan_rds_snapshots',
            'description': 'Scans RDS snapshots for public sharing and encryption issues',
            'category': 'Database'
        },
        'rds-instances': {
            'name': 'RDS Instances',
            'module': 'rds_instances',
            'function': 'scan_rds_instances',
            'description': 'Scans RDS instances for public accessibility, encryption, and monitoring issues',
            'category': 'Database'
        },
        'aurora': {
            'name': 'Aurora Clusters',
            'module': 'aurora',
            'function': 'scan_aurora_clusters',
            'description': 'Scans Aurora clusters for public accessibility, encryption, and backup configuration',
            'category': 'Database'
        },
        'elasticsearch': {
            'name': 'Elasticsearch Domains',
            'module': 'elasticsearch',
            'function': 'scan_elasticsearch_domains',
            'description': 'Scans Elasticsearch domains for public access, encryption, and security configuration',
            'category': 'Database'
        },
        'dynamodb': {
            'name': 'DynamoDB Tables',
            'module': 'dynamodb',
            'function': 'scan_dynamodb',
            'description': 'Scans DynamoDB tables for encryption, backups, and point-in-time recovery',
            'category': 'Database'
        },
        
        # Storage Category
        's3': {
            'name': 'S3 Buckets',
            'module': 's3',
            'function': 'scan_s3_buckets',
            'description': 'Scans S3 buckets for public access, encryption, versioning, and logging issues',
            'category': 'Storage'
        },
        'ebs': {
            'name': 'EBS Snapshots',
            'module': 'ebs',
            'function': 'scan_ebs_snapshots',
            'description': 'Scans EBS snapshots for public sharing and encryption issues',
            'category': 'Storage'
        },
        
        # Networking Category
        'api': {
            'name': 'API Gateway Endpoints',
            'module': 'api',
            'function': 'scan_api_gateways',
            'description': 'Scans API Gateway endpoints for authorization and authentication issues',
            'category': 'Networking'
        },
        'cloudfront': {
            'name': 'CloudFront Distributions',
            'module': 'cloudfront',
            'function': 'scan_cloudfront_distributions',
            'description': 'Scans CloudFront distributions for WAF, OAI, and security configuration issues',
            'category': 'Networking'
        },
        'eip': {
            'name': 'Elastic IPs',
            'module': 'eip',
            'function': 'scan_elastic_ips',
            'description': 'Scans Elastic IPs for unassociated IPs and security of attached instances',
            'category': 'Networking'
        },
        'elb': {
            'name': 'Elastic Load Balancers',
            'module': 'elb',
            'function': 'scan_load_balancers',
            'description': 'Scans load balancers for security configuration, TLS policies, and access logging',
            'category': 'Networking'
        },
        'vpc': {
            'name': 'VPC',
            'module': 'vpc',
            'function': 'scan_vpc',
            'description': 'Scans VPC for flow logs, network ACLs, and security best practices',
            'category': 'Networking'
        },
        'sns': {
            'name': 'SNS Topics',
            'module': 'sns',
            'function': 'scan_sns',
            'description': 'Scans SNS topics for encryption, access policies, and cross-account access',
            'category': 'Networking'
        },
        'sqs': {
            'name': 'SQS Queues',
            'module': 'sqs',
            'function': 'scan_sqs',
            'description': 'Scans SQS queues for encryption, access policies, and dead letter queue configuration',
            'category': 'Networking'
        },
        
        # Cost Category
        'cost': {
            'name': 'Cost Optimization',
            'module': 'cost_scanner',
            'function': 'scan_cost_optimization',
            'description': 'Scans AWS resources for cost optimization opportunities',
            'category': 'Cost'
        },
        
        # Template and code scanners
        'templates': {
            'name': 'Templates and Code',
            'module': 'template_scan.scanner',
            'function': 'scan_templates',
            'description': 'Scans CloudFormation templates, CDK, Terraform, Pulumi, OpenTofu, and AWS SDK code for security issues',
            'category': 'Security'
        },
        'cftemplate': {
            'name': 'CloudFormation Templates',
            'module': 'template_scan.cftemplate',
            'function': 'scan_cloudformation_templates',
            'description': 'Scans CloudFormation templates for security misconfigurations and best practices',
            'category': 'Security'
        },
        'cdk': {
            'name': 'CDK Code',
            'module': 'template_scan.cdk_scan',
            'function': 'scan_cdk_code',
            'description': 'Scans AWS CDK code for security issues and misconfigurations',
            'category': 'Security'
        },
        'terraform': {
            'name': 'Terraform Code',
            'module': 'template_scan.terraform_scan',
            'function': 'scan_terraform_code',
            'description': 'Scans Terraform code for AWS security issues and misconfigurations',
            'category': 'Security'
        },
        'sdk': {
            'name': 'AWS SDK Code',
            'module': 'template_scan.sdk_scan',
            'function': 'scan_sdk_code',
            'description': 'Scans AWS SDK code for security issues like hardcoded credentials and insecure configurations',
            'category': 'Security'
        },
        'pulumi': {
            'name': 'Pulumi Code',
            'module': 'template_scan.pulumi_scan',
            'function': 'scan_pulumi_code',
            'description': 'Scans Pulumi code for AWS security issues and misconfigurations',
            'category': 'Security'
        },
        'opentofu': {
            'name': 'OpenTofu Code',
            'module': 'template_scan.opentofu_scan',
            'function': 'scan_opentofu_code',
            'description': 'Scans OpenTofu code for AWS security issues and misconfigurations',
            'category': 'Security'
        }
    }
    
    # Load all scanner functions
    scanners = {}
    for key, scanner in scanner_definitions.items():
        scanner_function = load_scanner(scanner['module'], scanner['function'])
        scanners[key] = {
            'name': scanner['name'],
            'function': scanner_function,
            'available': scanner_function is not None,
            'description': scanner.get('description', ''),
            'category': scanner.get('category', 'Other')
        }
    
    return scanners

def get_scanner_function(scanner_id: str) -> Optional[Callable]:
    """
    Get a scanner function by its ID
    
    Args:
        scanner_id (str): ID of the scanner
        
    Returns:
        Optional[Callable]: The scanner function if available, None otherwise
    """
    scanners = get_available_scanners()
    if scanner_id in scanners and scanners[scanner_id]['available']:
        return scanners[scanner_id]['function']
    return None

def get_scanner_name(scanner_id: str) -> str:
    """
    Get a scanner name by its ID
    
    Args:
        scanner_id (str): ID of the scanner
        
    Returns:
        str: The name of the scanner
    """
    scanners = get_available_scanners()
    if scanner_id in scanners:
        return scanners[scanner_id]['name']
    return scanner_id

def get_scanner_description(scanner_id: str) -> str:
    """
    Get a scanner description by its ID
    
    Args:
        scanner_id (str): ID of the scanner
        
    Returns:
        str: The description of the scanner
    """
    scanners = get_available_scanners()
    if scanner_id in scanners:
        return scanners[scanner_id].get('description', '')
    return ''

def get_scanner_category(scanner_id: str) -> str:
    """
    Get a scanner category by its ID
    
    Args:
        scanner_id (str): ID of the scanner
        
    Returns:
        str: The category of the scanner
    """
    scanners = get_available_scanners()
    if scanner_id in scanners:
        return scanners[scanner_id].get('category', 'Other')
    return 'Other'

def get_scanner_ids() -> List[str]:
    """
    Get all scanner IDs
    
    Returns:
        List[str]: List of scanner IDs
    """
    return list(get_available_scanners().keys())

def get_scanner_ids_by_category(category: str) -> List[str]:
    """
    Get scanner IDs by category
    
    Args:
        category (str): Category name (Compute, Security, Database, Storage, Networking, Cost)
        
    Returns:
        List[str]: List of scanner IDs in the specified category
    """
    scanners = get_available_scanners()
    return [
        scanner_id for scanner_id, scanner in scanners.items()
        if scanner.get('category', 'Other').lower() == category.lower()
    ]

def is_scanner_available(scanner_id: str) -> bool:
    """
    Check if a scanner is available
    
    Args:
        scanner_id (str): ID of the scanner
        
    Returns:
        bool: True if the scanner is available, False otherwise
    """
    scanners = get_available_scanners()
    return scanner_id in scanners and scanners[scanner_id]['available']