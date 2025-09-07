"""
AWS Public Resource Exposure Monitor

This tool scans AWS resources for public exposure and security issues.
"""
import argparse
import json
import os
import sys
import boto3
from datetime import datetime
from textwrap import wrap
from pathlib import Path

# Import scanner registry
from scanner.registry import (
    get_available_scanners,
    get_scanner_function,
    get_scanner_name,
    get_scanner_ids,
    get_scanner_ids_by_category,
    get_scanner_description,
    get_scanner_category,
    is_scanner_available
)

# Import profile detector
from scanner.profile_detector import get_usable_profiles, create_session_for_profile

# Import notifier modules
try:
    from notifier.slack import SlackNotifier
except ImportError:
    SlackNotifier = None

try:
    from notifier.teams import TeamsNotifier
except ImportError:
    TeamsNotifier = None


# Import reporter modules
from reporter.console_reporter import print_header, print_subheader, print_finding, print_summary, colorize, ConsoleColors
try:
    from reporter.html_reporter import generate_html_report
except ImportError:
    def generate_html_report(findings, output_path=None):
        return None

# Import new reporter modules
try:
    from reporter.csv_reporter import generate_csv_report
except ImportError:
    def generate_csv_report(findings, output_path=None):
        return None

try:
    from reporter.json_reporter import generate_json_report
except ImportError:
    def generate_json_report(findings, output_path=None):
        return None


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='AWS Public Resource Exposure Monitor')
    
    parser.add_argument('--scan', 
                        help='Resource type(s) to scan (comma-separated list, category name, or "all")')
    
    parser.add_argument('--region', 
                        help='AWS region to scan (default: scan all regions)')
    
    parser.add_argument('--profile',
                        help='AWS profile to use (default: auto-detect available profiles)')
    
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
    
    parser.add_argument('--csv-report',
                        help='Generate CSV report and save to specified path')
    
    parser.add_argument('--json-report',
                        help='Generate JSON report and save to specified path')
    
    parser.add_argument('--cost-report',
                        help='Generate comprehensive cost analysis report')
    

    
    parser.add_argument('--terraform-dir',
                        help='Directory containing Terraform code to scan')
    
    parser.add_argument('--verbose', action='store_true',
                        help='Show detailed progress information')
    
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    
    parser.add_argument('--risk-level', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'ALL'],
                        default='ALL', help='Minimum risk level to report')
    
    parser.add_argument('--list-scanners', action='store_true',
                        help='List all available scanners')
    
    parser.add_argument('--category', choices=['exposure', 'compliance', 'cost', 'all'],
                        default='all', help='Category of issues to scan for')
    
    args = parser.parse_args()
    
    # Handle --list-scanners option
    if args.list_scanners:
        list_available_scanners()
        sys.exit(0)
    
    # Default to 'all' if no scan type is specified
    if not args.scan:
        args.scan = 'all'
    
    return args


def print_ascii_art():
    """Print ASCII art banner for the tool"""
    ascii_art = """
===============================================================================
                          AWS EXPOSURE MONITOR                                
                     Security & Cost Optimization Scanner                     
===============================================================================
    """
    
    print(colorize(ascii_art, ConsoleColors.BOLD_CYAN))
    print()


def list_available_scanners():
    """List all available scanners in a table format"""
    print_ascii_art()
    print_header("Available Scanners")
    
    scanners = get_available_scanners()
    
    # Calculate column widths
    if not scanners:
        print("No scanners available.")
        return
    
    id_width = max(len(key) for key in scanners.keys()) + 2
    name_width = max(len(scanner['name']) for scanner in scanners.values()) + 2
    category_width = 12  # Category name + padding
    status_width = 12  # "Available" or "Not Available" + padding
    
    # Calculate terminal width for description wrapping
    try:
        terminal_width = os.get_terminal_size().columns
    except (AttributeError, OSError):
        terminal_width = 100
    
    desc_width = max(20, terminal_width - id_width - name_width - category_width - status_width - 4)
    
    # Group scanners by category
    scanners_by_category = {}
    for key, scanner in scanners.items():
        category = scanner.get('category', 'Other')
        if category not in scanners_by_category:
            scanners_by_category[category] = []
        scanners_by_category[category].append((key, scanner))
    
    # Print scanners by category
    for category, category_scanners in sorted(scanners_by_category.items()):
        print_subheader(f"{category} Category")
        
        # Print table header
        header = (
            f"{'ID'.ljust(id_width)}"
            f"{'Name'.ljust(name_width)}"
            f"{'Status'.ljust(status_width)}"
            f"Description"
        )
        print(colorize(header, ConsoleColors.BOLD_WHITE))
        print(colorize("-" * terminal_width, ConsoleColors.BOLD_WHITE))
        
        # Print table rows
        for key, scanner in sorted(category_scanners):
            status = "Available" if scanner['available'] else "Not Available"
            status_color = ConsoleColors.GREEN if scanner['available'] else ConsoleColors.RED
            description = scanner.get('description', '')
            
            # Wrap description text
            if description:
                wrapped_desc = wrap(description, width=desc_width)
                first_line = wrapped_desc[0]
                rest_lines = wrapped_desc[1:] if len(wrapped_desc) > 1 else []
            else:
                first_line = ""
                rest_lines = []
            
            # Print first line with all columns
            print(
                f"{key.ljust(id_width)}"
                f"{scanner['name'].ljust(name_width)}"
                f"{colorize(status.ljust(status_width), status_color)}"
                f"{first_line}"
            )
            
            # Print remaining description lines with proper indentation
            for line in rest_lines:
                print(f"{' '.ljust(id_width + name_width + status_width)}{line}")
            
            # Add a blank line between entries for readability
            print()
        
        print()  # Add extra blank line between categories


def main():
    """Main function"""
    args = parse_args()
    
    # Disable colors if requested
    if args.no_color:
        for attr in dir(ConsoleColors):
            if not attr.startswith('__'):
                setattr(ConsoleColors, attr, '')
    
    print_ascii_art()
    print_header(f"Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Handle AWS profiles
    aws_profile = args.profile
    if not aws_profile:
        # Auto-detect profiles
        print("Auto-detecting AWS profiles...")
        try:
            usable_profiles = get_usable_profiles()
        except Exception as e:
            print(colorize(f"Error accessing AWS profiles: {e}", ConsoleColors.BOLD_RED))
            return 1
        
        if not usable_profiles:
            print(colorize("No usable AWS profiles found. Please configure AWS credentials.", ConsoleColors.BOLD_RED))
            return 1
        
        if len(usable_profiles) == 1:
            aws_profile = usable_profiles[0]['profile_name']
            print(f"Using AWS profile: {colorize(aws_profile, ConsoleColors.BOLD_CYAN)} (Account: {usable_profiles[0]['account_id']})")
        else:
            print(f"Found {len(usable_profiles)} AWS profiles:")
            for i, profile in enumerate(usable_profiles, 1):
                print(f"  {i}. {colorize(profile['profile_name'], ConsoleColors.BOLD_CYAN)} (Account: {profile['account_id']})")
            
            # Use default profile if available
            if any(p['profile_name'] == 'default' for p in usable_profiles):
                aws_profile = 'default'
                print(f"Using default AWS profile: {colorize(aws_profile, ConsoleColors.BOLD_CYAN)}")
            else:
                aws_profile = usable_profiles[0]['profile_name']
                print(f"Using AWS profile: {colorize(aws_profile, ConsoleColors.BOLD_CYAN)} (Account: {usable_profiles[0]['account_id']})")
    else:
        print(f"Using specified AWS profile: {colorize(aws_profile, ConsoleColors.BOLD_CYAN)}")
    
    # Create boto3 session with the selected profile
    boto3.setup_default_session(profile_name=aws_profile)
    
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
    if args.scan and args.scan.lower() == 'all':
        scan_types = get_scanner_ids()
    elif args.scan:
        # Check if the scan argument is a category name
        categories = ['compute', 'security', 'database', 'storage', 'networking', 'ai']
        if args.scan.lower() in categories:
            category = args.scan.lower()
            scan_types = get_scanner_ids_by_category(category)
            print(f"Scanning {colorize(category.upper(), ConsoleColors.BOLD_CYAN)} category resources")
        else:
            scan_types = [s.strip().lower() for s in args.scan.split(',')]
            
            # Validate scan types
            invalid_types = [s for s in scan_types if s not in get_scanner_ids()]
            if invalid_types:
                print(f"Error: Invalid scan type(s): {', '.join(invalid_types)}")
                print(f"Available scan types: {', '.join(get_scanner_ids())}")
                return 1
    else:
        # Default to a set of common scanners if none specified
        scan_types = ['s3', 'ec2', 'rds', 'iam', 'sg', 'secrets_scanner']
        print(f"No scan types specified, using default set: {colorize(', '.join(scan_types), ConsoleColors.BOLD_CYAN)}")
    
    # Collect findings
    all_findings = []
    
    # Group scanners by category for better organization
    scanners_by_category = {}
    for scan_type in scan_types:
        if not is_scanner_available(scan_type):
            print(f"Scanner for {scan_type} is not available, skipping...")
            continue
        
        category = get_scanner_category(scan_type)
        if category not in scanners_by_category:
            scanners_by_category[category] = []
        scanners_by_category[category].append(scan_type)
    
    # Print scan plan by category
    print_subheader("Scan Plan")
    for category, scanners in scanners_by_category.items():
        print(f"{colorize(category, ConsoleColors.BOLD_WHITE)}: {', '.join(get_scanner_name(s) for s in scanners)}")
    print()
    
    # Scan resources by category
    for category, scanners in scanners_by_category.items():
        category_findings = []
        print_subheader(f"Scanning {category} Resources")
        
        for scan_type in scanners:
            scanner_name = get_scanner_name(scan_type)
            scanner_function = get_scanner_function(scan_type)
            
            try:
                # Handle special cases for template scanners
                if scan_type == 'terraform' and args.terraform_dir:
                    findings = scanner_function(args.terraform_dir)
                else:
                    findings = scanner_function(region=args.region)
                
                if findings:
                    category_findings.extend(findings)
                    print(f"- {scanner_name}: {len(findings)} issues found")
            except Exception as e:
                print(f"- Error scanning {scanner_name}: {colorize(str(e), ConsoleColors.BOLD_RED)}")
        
        # Add category findings to all findings
        all_findings.extend(category_findings)
        
        # Print category summary
        if category_findings:
            print(f"Found {colorize(str(len(category_findings)), ConsoleColors.BOLD_WHITE)} {category} issues")
        else:
            print(f"No {category} issues found")
    
    # Filter findings by risk level if specified
    if args.risk_level != 'ALL':
        risk_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_risk_index = risk_levels.index(args.risk_level)
        filtered_findings = [f for f in all_findings if f.get('Risk') in risk_levels[min_risk_index:]]
        
        if len(filtered_findings) != len(all_findings):
            print(f"\nFiltered {len(all_findings) - len(filtered_findings)} findings below {args.risk_level} risk level")
            all_findings = filtered_findings
    
    # Group findings by category
    findings_by_category = {}
    for finding in all_findings:
        resource_type = finding.get('ResourceType', 'Unknown')
        
        # Determine category based on resource type
        if resource_type in ['EC2 Instance', 'Lambda Function', 'ECS Cluster', 'EKS Cluster', 'Lightsail Instance']:
            category = 'Compute'
        elif resource_type in ['IAM User', 'IAM Role', 'IAM Policy', 'Security Group', 'KMS Key', 'CloudTrail', 'GuardDuty', 'WAF Web ACL']:
            category = 'Security'
        elif resource_type in ['RDS Instance', 'RDS Snapshot', 'DynamoDB Table', 'Aurora Cluster', 'ElastiCache Cluster', 'RDS Parameter Group']:
            category = 'Database'
        elif resource_type in ['S3 Bucket', 'S3 Object', 'EBS Volume', 'EBS Snapshot', 'EFS File System']:
            category = 'Storage'
        elif resource_type in ['VPC', 'Subnet', 'Internet Gateway', 'Route Table', 'Network ACL', 'Elastic IP', 'API Gateway', 'CloudFront Distribution']:
            category = 'Networking'
        elif resource_type in ['SageMaker Notebook', 'SageMaker Endpoint', 'Bedrock Model Job', 'Bedrock Configuration', 'Q Business Application', 'Q Business Data Source']:
            category = 'AI'
        else:
            category = 'Other'
        
        if category not in findings_by_category:
            findings_by_category[category] = []
        findings_by_category[category].append(finding)
    
    # Print summary by category
    print_subheader("Findings Summary by Category")
    for category, findings in findings_by_category.items():
        print(f"{colorize(category, ConsoleColors.BOLD_WHITE)}: {len(findings)} findings")
    print()
    
    # Print overall summary
    print_summary(all_findings)
    
    # Save findings to file if requested
    if args.output:
        try:
            output_path = Path(args.output).resolve()
            if not output_path.parent.exists():
                output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump(all_findings, f, indent=2)
            print(f"\nFindings saved to {colorize(str(output_path), ConsoleColors.BOLD_GREEN)}")
        except Exception as e:
            print(f"Error saving findings to file: {colorize(str(e), ConsoleColors.BOLD_RED)}")
    
    # Generate HTML report if requested
    if args.html_report:
        try:
            html_path = Path(args.html_report).resolve()
            if not html_path.parent.exists():
                html_path.parent.mkdir(parents=True, exist_ok=True)
            report_path = generate_html_report(all_findings, str(html_path))
            if report_path:
                print(f"\nHTML report generated: {colorize(report_path, ConsoleColors.BOLD_GREEN)}")
        except Exception as e:
            print(f"Error generating HTML report: {colorize(str(e), ConsoleColors.BOLD_RED)}")
    
    # Generate CSV report if requested
    if args.csv_report:
        try:
            csv_path = Path(args.csv_report).resolve()
            if not csv_path.parent.exists():
                csv_path.parent.mkdir(parents=True, exist_ok=True)
            report_path = generate_csv_report(all_findings, str(csv_path))
            if report_path:
                print(f"\nCSV report generated: {colorize(report_path, ConsoleColors.BOLD_GREEN)}")
        except Exception as e:
            print(f"Error generating CSV report: {colorize(str(e), ConsoleColors.BOLD_RED)}")
    
    # Generate JSON report if requested
    if args.json_report:
        try:
            json_path = Path(args.json_report).resolve()
            if not json_path.parent.exists():
                json_path.parent.mkdir(parents=True, exist_ok=True)
            report_path = generate_json_report(all_findings, str(json_path))
            if report_path:
                print(f"\nJSON report generated: {colorize(report_path, ConsoleColors.BOLD_GREEN)}")
        except Exception as e:
            print(f"Error generating JSON report: {colorize(str(e), ConsoleColors.BOLD_RED)}")
    
    # Generate cost report if requested
    if args.cost_report:
        try:
            from reporter.cost_reporter import generate_cost_report
            cost_path = Path(args.cost_report).resolve()
            if not cost_path.parent.exists():
                cost_path.parent.mkdir(parents=True, exist_ok=True)
            report_path = generate_cost_report(str(cost_path))
            if report_path:
                print(f"\nCost analysis report generated: {colorize(report_path, ConsoleColors.BOLD_GREEN)}")
        except Exception as e:
            print(f"Error generating cost report: {colorize(str(e), ConsoleColors.BOLD_RED)}")
    

    
    # Send notifications if requested
    if args.notify:
        if args.slack_webhook and SlackNotifier:
            print_subheader("Sending Slack notifications...")
            slack_notifier = SlackNotifier(args.slack_webhook)
            sent_count = slack_notifier.send_alerts(all_findings)
            print(f"Sent {colorize(str(sent_count), ConsoleColors.BOLD_GREEN)} of {len(all_findings)} Slack alerts")
        elif args.slack_webhook:
            print("Slack notifier module not available")
        
        if args.teams_webhook and TeamsNotifier:
            print_subheader("Sending Microsoft Teams notifications...")
            teams_notifier = TeamsNotifier(args.teams_webhook)
            sent_count = teams_notifier.send_alerts(all_findings)
            print(f"Sent {colorize(str(sent_count), ConsoleColors.BOLD_GREEN)} of {len(all_findings)} Teams alerts")
        elif args.teams_webhook:
            print("Teams notifier module not available")
    

    print_header("Scan completed")
    
    # Return non-zero exit code if issues were found
    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())