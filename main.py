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


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='AWS Public Resource Exposure Monitor')
    
    parser.add_argument('--scan', choices=['all', 's3', 'ebs', 'rds', 'amis', 'sg'], 
                        default='all', help='Resource type to scan')
    
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
    
    return parser.parse_args()


def main():
    """Main function"""
    args = parse_args()
    
    # Disable colors if requested
    if args.no_color:
        for attr in dir(ConsoleColors):
            if not attr.startswith('__'):
                setattr(ConsoleColors, attr, '')
    
    print_header(f"AWS Public Resource Exposure Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Collect findings
    all_findings = []
    
    # Scan resources based on arguments
    if args.scan in ['all', 's3']:
        print_subheader("[SCAN] S3 Buckets")
        s3_findings = scan_s3_buckets()
        all_findings.extend(s3_findings)
        if s3_findings:
            print(f"Found {colorize(str(len(s3_findings)), ConsoleColors.BOLD_WHITE)} S3 bucket issues")
    
    if args.scan in ['all', 'ebs']:
        print_subheader("[SCAN] EBS Snapshots")
        ebs_findings = scan_ebs_snapshots()
        all_findings.extend(ebs_findings)
        if ebs_findings:
            print(f"Found {colorize(str(len(ebs_findings)), ConsoleColors.BOLD_WHITE)} EBS snapshot issues")
    
    if args.scan in ['all', 'rds']:
        print_subheader("[SCAN] RDS Snapshots")
        rds_findings = scan_rds_snapshots()
        all_findings.extend(rds_findings)
        if rds_findings:
            print(f"Found {colorize(str(len(rds_findings)), ConsoleColors.BOLD_WHITE)} RDS snapshot issues")
    
    if args.scan in ['all', 'amis']:
        print_subheader("[SCAN] AMIs")
        ami_findings = scan_amis()
        all_findings.extend(ami_findings)
        if ami_findings:
            print(f"Found {colorize(str(len(ami_findings)), ConsoleColors.BOLD_WHITE)} AMI issues")
    
    if args.scan in ['all', 'sg']:
        print_subheader("[SCAN] Security Groups")
        sg_findings = scan_security_groups()
        all_findings.extend(sg_findings)
        if sg_findings:
            print(f"Found {colorize(str(len(sg_findings)), ConsoleColors.BOLD_WHITE)} security group issues")
    
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