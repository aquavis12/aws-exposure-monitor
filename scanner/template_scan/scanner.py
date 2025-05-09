"""
Template Scanner Module - Main entry point for all template scanning functionality
"""
import os
from scanner.template_scan.cftemplate import scan_cloudformation_templates
from scanner.template_scan.cdk_scan import scan_cdk_code
from scanner.template_scan.terraform_scan import scan_terraform_code
from scanner.template_scan.sdk_scan import scan_sdk_code
from scanner.template_scan.pulumi_scan import scan_pulumi_code
from scanner.template_scan.opentofu_scan import scan_opentofu_code


def scan_templates(directory, region=None):
    """
    Scan templates and code for security issues
    
    Args:
        directory (str): Directory containing templates and code to scan
        region (str, optional): AWS region to scan for deployed templates
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print(f"Starting template scan in directory: {directory}")
    
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a valid directory")
        return findings
    
    # Scan CloudFormation templates
    cf_findings = scan_cloudformation_templates(directory, region)
    findings.extend(cf_findings)
    
    # Scan CDK code
    cdk_findings = scan_cdk_code(directory)
    findings.extend(cdk_findings)
    
    # Scan Terraform code
    tf_findings = scan_terraform_code(directory)
    findings.extend(tf_findings)
    
    # Scan SDK code
    sdk_findings = scan_sdk_code(directory)
    findings.extend(sdk_findings)
    
    # Scan Pulumi code
    pulumi_findings = scan_pulumi_code(directory)
    findings.extend(pulumi_findings)
    
    # Scan OpenTofu code
    opentofu_findings = scan_opentofu_code(directory)
    findings.extend(opentofu_findings)
    
    if findings:
        print(f"Found {len(findings)} template and code security issues.")
    else:
        print("No template or code security issues found.")
    
    return findings