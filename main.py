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
from notifier.slack import SlackNotifier, TeamsNotifier

# Import remediator modules
from remediator.s3 import remediate_s3_findings


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
    
    return parser.parse_args()


def main():
    """Main function"""
    args = parse_args()
    
    print(f"AWS Public Resource Exposure Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Collect findings
    all_findings = []
    
    # Scan resources based on arguments
    if args.scan in ['all', 's3']:
        print("Scanning S3 buckets...")
        s3_findings = scan_s3_buckets()
        all_findings.extend(s3_findings)
        print(f"Found {len(s3_findings)} S3 bucket issues")
    
    if args.scan in ['all', 'ebs']:
        print("Scanning EBS snapshots...")
        ebs_findings = scan_ebs_snapshots()
        all_findings.extend(ebs_findings)
        print(f"Found {len(ebs_findings)} EBS snapshot issues")
    
    if args.scan in ['all', 'rds']:
        print("Scanning RDS snapshots...")
        rds_findings = scan_rds_snapshots()
        all_findings.extend(rds_findings)
        print(f"Found {len(rds_findings)} RDS snapshot issues")
    
    if args.scan in ['all', 'amis']:
        print("Scanning AMIs...")
        ami_findings = scan_amis()
        all_findings.extend(ami_findings)
        print(f"Found {len(ami_findings)} AMI issues")
    
    if args.scan in ['all', 'sg']:
        print("Scanning security groups...")
        sg_findings = scan_security_groups()
        all_findings.extend(sg_findings)
        print(f"Found {len(sg_findings)} security group issues")
    
    # Print summary
    print("\nScan Summary:")
    print(f"Total findings: {len(all_findings)}")
    
    # Group findings by risk level
    risk_counts = {}
    for finding in all_findings:
        risk = finding.get('Risk', 'UNKNOWN')
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
    
    for risk, count in risk_counts.items():
        print(f"- {risk}: {count}")
    
    # Save findings to file if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(all_findings, f, indent=2)
            print(f"\nFindings saved to {args.output}")
        except Exception as e:
            print(f"Error saving findings to file: {e}")
    
    # Send notifications if requested
    if args.notify:
        if args.slack_webhook:
            print("\nSending Slack notifications...")
            slack_notifier = SlackNotifier(args.slack_webhook)
            sent_count = slack_notifier.send_alerts(all_findings)
            print(f"Sent {sent_count} of {len(all_findings)} Slack alerts")
        
        if args.teams_webhook:
            print("\nSending Microsoft Teams notifications...")
            teams_notifier = TeamsNotifier(args.teams_webhook)
            sent_count = teams_notifier.send_alerts(all_findings)
            print(f"Sent {sent_count} of {len(all_findings)} Teams alerts")
    
    # Remediate issues if requested
    if args.remediate:
        print("\nRemediating issues...")
        
        # Remediate S3 issues
        s3_findings = [f for f in all_findings if f.get('ResourceType') == 'S3 Bucket']
        if s3_findings:
            print(f"Remediating {len(s3_findings)} S3 bucket issues...")
            s3_results = remediate_s3_findings(s3_findings)
            
            success_count = sum(1 for r in s3_results if r.get('success', False))
            print(f"Successfully remediated {success_count} of {len(s3_findings)} S3 bucket issues")
    
    print("\nScan completed.")
    
    # Return non-zero exit code if issues were found
    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())