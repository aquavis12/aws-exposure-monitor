"""
AWS Public Resource Exposure Monitor

This tool scans AWS resources for public exposure and security issues.
"""
import argparse
import json
import os
import sys
from datetime import datetime
from textwrap import wrap

# Import scanner registry
from scanner.registry import (
    get_available_scanners,
    get_scanner_function,
    get_scanner_name,
    get_scanner_ids,
    get_scanner_description,
    is_scanner_available
)

# Import notifier modules
try:
    from notifier.slack import SlackNotifier
except ImportError:
    SlackNotifier = None

try:
    from notifier.teams import TeamsNotifier
except ImportError:
    TeamsNotifier = None

# Import remediator modules
try:
    from remediator.s3 import remediate_s3_findings
except ImportError:
    remediate_s3_findings = None

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
  █████╗ ██╗    ██╗███████╗    ██████╗ ██╗   ██╗██████╗ ██╗     ██╗ ██████╗    ██████╗ ███████╗███████╗ ██████╗ ██╗   ██╗██████╗  ██████╗███████╗
 ██╔══██╗██║    ██║██╔════╝    ██╔══██╗██║   ██║██╔══██╗██║     ██║██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔════╝
 ███████║██║ █╗ ██║███████╗    ██████╔╝██║   ██║██████╔╝██║     ██║██║         ██████╔╝█████╗  ███████╗██║   ██║██║   ██║██████╔╝██║     █████╗  
 ██╔══██║██║███╗██║╚════██║    ██╔═══╝ ██║   ██║██╔══██╗██║     ██║██║         ██╔══██╗██╔══╝  ╚════██║██║   ██║██║   ██║██╔══██╗██║     ██╔══╝  
 ██║  ██║╚███╔███╔╝███████║    ██║     ╚██████╔╝██████╔╝███████╗██║╚██████╗    ██║  ██║███████╗███████║╚██████╔╝╚██████╔╝██║  ██║╚██████╗███████╗
 ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝    ╚═╝      ╚═════╝ ╚═════╝ ╚══════╝╚═╝ ╚═════╝    ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝
                                                                                                                                                  
 ███████╗██╗  ██╗██████╗  ██████╗ ███████╗██╗   ██╗██████╗ ███████╗    ███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗ 
 ██╔════╝╚██╗██╔╝██╔══██╗██╔═══██╗██╔════╝██║   ██║██╔══██╗██╔════╝    ████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗
 █████╗   ╚███╔╝ ██████╔╝██║   ██║███████╗██║   ██║██████╔╝█████╗      ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝
 ██╔══╝   ██╔██╗ ██╔═══╝ ██║   ██║╚════██║██║   ██║██╔══██╗██╔══╝      ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗
 ███████╗██╔╝ ██╗██║     ╚██████╔╝███████║╚██████╔╝██║  ██║███████╗    ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║
 ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝

    """
    
    print(colorize(ascii_art, ConsoleColors.BOLD_CYAN))
    print(colorize("  Comprehensive AWS Security Scanner and Exposure Monitor", ConsoleColors.BOLD_WHITE))
    print()


def list_available_scanners():
    """List all available scanners in a table format"""
    print_ascii_art()
    print_header("Available Scanners")
    
    scanners = get_available_scanners()
    
    # Calculate column widths
    id_width = max(len(key) for key in scanners.keys()) + 2
    name_width = max(len(scanner['name']) for scanner in scanners.values()) + 2
    status_width = 12  # "Available" or "Not Available" + padding
    
    # Calculate terminal width for description wrapping
    try:
        terminal_width = os.get_terminal_size().columns
    except (AttributeError, OSError):
        terminal_width = 100
    
    desc_width = terminal_width - id_width - name_width - status_width - 4
    
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
    for key, scanner in sorted(scanners.items()):
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
        scan_types = get_scanner_ids()
    else:
        scan_types = [s.strip().lower() for s in args.scan.split(',')]
        
        # Validate scan types
        invalid_types = [s for s in scan_types if s not in get_scanner_ids()]
        if invalid_types:
            print(f"Error: Invalid scan type(s): {', '.join(invalid_types)}")
            print(f"Available scan types: {', '.join(get_scanner_ids())}")
            return 1
    
    # Collect findings
    all_findings = []
    
    # Scan resources based on arguments
    for scan_type in scan_types:
        if not is_scanner_available(scan_type):
            print(f"Scanner for {scan_type} is not available, skipping...")
            continue
        
        scanner_name = get_scanner_name(scan_type)
        scanner_function = get_scanner_function(scan_type)
        
        print_subheader(f"[SCAN] {scanner_name}")
        try:
            findings = scanner_function(region=args.region)
            all_findings.extend(findings)
            if findings:
                print(f"Found {colorize(str(len(findings)), ConsoleColors.BOLD_WHITE)} {scanner_name} issues")
        except Exception as e:
            print(f"Error scanning {scanner_name}: {colorize(str(e), ConsoleColors.BOLD_RED)}")
    
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
    
    # Remediate issues if requested
    if args.remediate:
        print_subheader("Remediating issues...")
        
        # Remediate S3 issues
        s3_findings = [f for f in all_findings if f.get('ResourceType') == 'S3 Bucket']
        if s3_findings and remediate_s3_findings:
            print(f"Remediating {colorize(str(len(s3_findings)), ConsoleColors.BOLD_WHITE)} S3 bucket issues...")
            s3_results = remediate_s3_findings(s3_findings)
            
            success_count = sum(1 for r in s3_results if r.get('success', False))
            print(f"Successfully remediated {colorize(str(success_count), ConsoleColors.BOLD_GREEN)} of {len(s3_findings)} S3 bucket issues")
        elif s3_findings:
            print("S3 remediation module not available")
        
        # Remediate EBS issues if the module is available
        ebs_findings = [f for f in all_findings if f.get('ResourceType') == 'EBS Snapshot']
        if ebs_findings and remediate_ebs_findings:
            print(f"Remediating {colorize(str(len(ebs_findings)), ConsoleColors.BOLD_WHITE)} EBS snapshot issues...")
            ebs_results = remediate_ebs_findings(ebs_findings)
            
            success_count = sum(1 for r in ebs_results if r.get('success', False))
            print(f"Successfully remediated {colorize(str(success_count), ConsoleColors.BOLD_GREEN)} of {len(ebs_findings)} EBS snapshot issues")
        elif ebs_findings:
            print("EBS remediation module not available")
    
    print_header("Scan completed")
    
    # Return non-zero exit code if issues were found
    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())