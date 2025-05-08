"""
AWS Public Resource Exposure Monitor

This tool scans AWS resources for public exposure and sends alerts.
"""
import argparse
import json
import os
import sys
from datetime import datetime

# Import scanner modules
from scanner.s3 import scan_s3_buckets
from scanner.ebs import scan_ebs_snapshots
from scanner.rds import scan_rds_snapshots
from scanner.amis import scan_amis
from scanner.sg import scan_security_groups
from scanner.ecr import scan_ecr_repositories
from scanner.api import scan_api_gateways

# Import additional scanner modules if available
try:
    from scanner.cloudfront import scan_cloudfront_distributions
except ImportError:
    scan_cloudfront_distributions = None

try:
    from scanner.lambda_scanner import scan_lambda_functions
except ImportError:
    scan_lambda_functions = None

try:
    from scanner.eip import scan_elastic_ips
except ImportError:
    scan_elastic_ips = None

try:
    from scanner.rds_instances import scan_rds_instances
except ImportError:
    scan_rds_instances = None

try:
    from scanner.elb import scan_load_balancers
except ImportError:
    scan_load_balancers = None

try:
    from scanner.elasticsearch import scan_elasticsearch_domains
except ImportError:
    scan_elasticsearch_domains = None

try:
    from scanner.iam import scan_iam_users
except ImportError:
    scan_iam_users = None

try:
    from scanner.ec2 import scan_ec2_instances
except ImportError:
    scan_ec2_instances = None

try:
    from scanner.secrets import scan_secrets_and_keys
except ImportError:
    scan_secrets_and_keys = None

try:
    from scanner.cw import scan_cloudwatch_logs
except ImportError:
    scan_cloudwatch_logs = None

# Import notifier modules
from notifier.slack import SlackNotifier
try:
    from notifier.teams import TeamsNotifier
except ImportError:
    from notifier.slack import TeamsNotifier

# Import remediator modules
from remediator.s3 import remediate_s3_findings
try:
    from remediator.ebs import remediate_ebs_findings
except ImportError:
    remediate_ebs_findings = None

# Import reporter modules
from reporter.console_reporter import print_header, print_subheader, print_finding, print_summary, colorize, ConsoleColors
try:
    from reporter.html_reporter import generate_html_report
except ImportError:
    def generate_html_report(findings, output_path=None):
        print("HTML report generation requires Jinja2. Install with: pip install jinja2")
        return None

# Define all available scanners
AVAILABLE_SCANNERS = {
    's3': {
        'name': 'S3 Buckets',
        'function': scan_s3_buckets
    },
    'ebs': {
        'name': 'EBS Snapshots',
        'function': scan_ebs_snapshots
    },
    'rds': {
        'name': 'RDS Snapshots',
        'function': scan_rds_snapshots
    },
    'amis': {
        'name': 'AMIs',
        'function': scan_amis
    },
    'sg': {
        'name': 'Security Groups',
        'function': scan_security_groups
    },
    'ecr': {
        'name': 'ECR Repositories',
        'function': scan_ecr_repositories
    },
    'api': {
        'name': 'API Gateway Endpoints',
        'function': scan_api_gateways
    },
    'cloudfront': {
        'name': 'CloudFront Distributions',
        'function': scan_cloudfront_distributions
    },
    'lambda': {
        'name': 'Lambda Functions',
        'function': scan_lambda_functions
    },
    'eip': {
        'name': 'Elastic IPs',
        'function': scan_elastic_ips
    },
    'rds-instances': {
        'name': 'RDS Instances',
        'function': scan_rds_instances
    },
    'elb': {
        'name': 'Elastic Load Balancers',
        'function': scan_load_balancers
    },
    'elasticsearch': {
        'name': 'Elasticsearch Domains',
        'function': scan_elasticsearch_domains
    },
    'iam': {
        'name': 'IAM Users and Access Keys',
        'function': scan_iam_users
    },
    'ec2': {
        'name': 'EC2 Instances',
        'function': scan_ec2_instances
    },
    'secrets': {
        'name': 'Secrets Manager and KMS',
        'function': scan_secrets_and_keys
    },
    'cloudwatch': {
        'name': 'CloudWatch Logs',
        'function': scan_cloudwatch_logs
    }
}


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='AWS Public Resource Exposure Monitor')
    
    parser.add_argument('--scan', 
                        help='Resource type(s) to scan (comma-separated list or "all")')
    
    parser.add_argument('--region', 
                        help='AWS region to scan (default: scan all regions)')
    
    parser.add_argument('--notify', action='store_true', 
                        help='Send notifications for findings')
    
    parser.add_argument('--slack-webhook', 
                        help='Slack webhook URL for notifications')
    
    parser.add_argument('--teams-webhook', 
                        help='Microsoft Teams webhook URL for notifications')
    
    parser.add_argument('--remediate', action='store_true', 
                        help='Automatically remediate issues (use with caution)')
    
    parser.add_argument('--output', 
                        help='Output file for findings (JSON format)')
    
    parser.add_argument('--html-report',
                        help='Generate HTML report and save to specified path')
    
    parser.add_argument('--verbose', action='store_true',
                        help='Show detailed progress information')
    
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    
    parser.add_argument('--risk-level', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'ALL'],
                        default='ALL', help='Minimum risk level to report')
    
    parser.add_argument('--list-scanners', action='store_true',
                        help='List all available scanners')
    
    args = parser.parse_args()
    
    # Handle --list-scanners option
    if args.list_scanners:
        print_header("Available Scanners")
        for key, scanner in sorted(AVAILABLE_SCANNERS.items()):
            status = "Available" if scanner['function'] else "Not Available"
            status_color = ConsoleColors.GREEN if scanner['function'] else ConsoleColors.RED
            print(f"{key.ljust(15)}: {scanner['name'].ljust(30)} [{colorize(status, status_color)}]")
        sys.exit(0)
    
    # Default to 'all' if no scan type is specified
    if not args.scan:
        args.scan = 'all'
    
    return args


def main():
    """Main function"""
    args = parse_args()
    
    # Disable colors if requested
    if args.no_color:
        for attr in dir(ConsoleColors):
            if not attr.startswith('__'):
                setattr(ConsoleColors, attr, '')
    
    print_header(f"AWS Public Resource Exposure Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Show region information
    if args.region:
        print(f"Scanning region: {colorize(args.region, ConsoleColors.BOLD_CYAN)}")
    else:
        print("Scanning all available regions")
    
    # Show risk level filter
    if args.risk_level != 'ALL':
        print(f"Filtering for {colorize(args.risk_level, ConsoleColors.BOLD_CYAN)} or higher risk findings")
    
    # Parse scan types
    scan_types = []
    if args.scan.lower() == 'all':
        scan_types = list(AVAILABLE_SCANNERS.keys())
    else:
        scan_types = [s.strip().lower() for s in args.scan.split(',')]
        
        # Validate scan types
        invalid_types = [s for s in scan_types if s not in AVAILABLE_SCANNERS]
        if invalid_types:
            print(f"Error: Invalid scan type(s): {', '.join(invalid_types)}")
            print(f"Available scan types: {', '.join(AVAILABLE_SCANNERS.keys())}")
            return 1
    
    # Collect findings
    all_findings = []
    
    # Scan resources based on arguments
    for scan_type in scan_types:
        scanner = AVAILABLE_SCANNERS.get(scan_type)
        if not scanner or not scanner['function']:
            print(f"Scanner for {scan_type} is not available, skipping...")
            continue
        
        print_subheader(f"[SCAN] {scanner['name']}")
        try:
            findings = scanner['function'](region=args.region)
            all_findings.extend(findings)
            if findings:
                print(f"Found {colorize(str(len(findings)), ConsoleColors.BOLD_WHITE)} {scanner['name']} issues")
        except Exception as e:
            print(f"Error scanning {scanner['name']}: {colorize(str(e), ConsoleColors.BOLD_RED)}")
    
    # Filter findings by risk level if specified
    if args.risk_level != 'ALL':
        risk_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_risk_index = risk_levels.index(args.risk_level)
        filtered_findings = [f for f in all_findings if f.get('Risk') in risk_levels[min_risk_index:]]
        
        if len(filtered_findings) != len(all_findings):
            print(f"\nFiltered {len(all_findings) - len(filtered_findings)} findings below {args.risk_level} risk level")
            all_findings = filtered_findings
    
    # Print summary
    print_summary(all_findings)
    
    # Save findings to file if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(all_findings, f, indent=2)
            print(f"\nFindings saved to {colorize(args.output, ConsoleColors.BOLD_GREEN)}")
        except Exception as e:
            print(f"Error saving findings to file: {colorize(str(e), ConsoleColors.BOLD_RED)}")
    
    # Generate HTML report if requested
    if args.html_report:
        try:
            report_path = generate_html_report(all_findings, args.html_report)
            if report_path:
                print(f"\nHTML report generated: {colorize(report_path, ConsoleColors.BOLD_GREEN)}")
        except Exception as e:
            print(f"Error generating HTML report: {colorize(str(e), ConsoleColors.BOLD_RED)}")
    
    # Send notifications if requested
    if args.notify:
        if args.slack_webhook:
            print_subheader("Sending Slack notifications...")
            slack_notifier = SlackNotifier(args.slack_webhook)
            sent_count = slack_notifier.send_alerts(all_findings)
            print(f"Sent {colorize(str(sent_count), ConsoleColors.BOLD_GREEN)} of {len(all_findings)} Slack alerts")
        
        if args.teams_webhook:
            print_subheader("Sending Microsoft Teams notifications...")
            teams_notifier = TeamsNotifier(args.teams_webhook)
            sent_count = teams_notifier.send_alerts(all_findings)
            print(f"Sent {colorize(str(sent_count), ConsoleColors.BOLD_GREEN)} of {len(all_findings)} Teams alerts")
    
    # Remediate issues if requested
    if args.remediate:
        print_subheader("Remediating issues...")
        
        # Remediate S3 issues
        s3_findings = [f for f in all_findings if f.get('ResourceType') == 'S3 Bucket']
        if s3_findings:
            print(f"Remediating {colorize(str(len(s3_findings)), ConsoleColors.BOLD_WHITE)} S3 bucket issues...")
            s3_results = remediate_s3_findings(s3_findings)
            
            success_count = sum(1 for r in s3_results if r.get('success', False))
            print(f"Successfully remediated {colorize(str(success_count), ConsoleColors.BOLD_GREEN)} of {len(s3_findings)} S3 bucket issues")
        
        # Remediate EBS issues if the module is available
        if remediate_ebs_findings:
            ebs_findings = [f for f in all_findings if f.get('ResourceType') == 'EBS Snapshot']
            if ebs_findings:
                print(f"Remediating {colorize(str(len(ebs_findings)), ConsoleColors.BOLD_WHITE)} EBS snapshot issues...")
                ebs_results = remediate_ebs_findings(ebs_findings)
                
                success_count = sum(1 for r in ebs_results if r.get('success', False))
                print(f"Successfully remediated {colorize(str(success_count), ConsoleColors.BOLD_GREEN)} of {len(ebs_findings)} EBS snapshot issues")
    
    print_header("Scan completed")
    
    # Return non-zero exit code if issues were found
    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())