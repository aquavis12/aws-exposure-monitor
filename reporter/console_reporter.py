"""
Console Reporter Module - Provides colored console output for findings
"""
import sys
import platform


class ConsoleColors:
    """ANSI color codes for console output"""
    # Reset
    RESET = '\033[0m'
    
    # Regular colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bold colors
    BOLD_BLACK = '\033[1;30m'
    BOLD_RED = '\033[1;31m'
    BOLD_GREEN = '\033[1;32m'
    BOLD_YELLOW = '\033[1;33m'
    BOLD_BLUE = '\033[1;34m'
    BOLD_MAGENTA = '\033[1;35m'
    BOLD_CYAN = '\033[1;36m'
    BOLD_WHITE = '\033[1;37m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'


# Check if we're on Windows and enable ANSI colors
if platform.system() == 'Windows':
    import os
    os.system('color')


def colorize(text, color):
    """
    Add color to text if supported by the terminal
    
    Args:
        text (str): Text to colorize
        color (str): ANSI color code
    
    Returns:
        str: Colorized text
    """
    return f"{color}{text}{ConsoleColors.RESET}"


def print_header(text):
    """Print a header with blue background"""
    print(colorize(f"\n{text}", ConsoleColors.BOLD_BLUE))
    print(colorize("=" * 60, ConsoleColors.BLUE))


def print_subheader(text):
    """Print a subheader with cyan color"""
    print(colorize(f"\n{text}", ConsoleColors.BOLD_CYAN))
    print(colorize("-" * 60, ConsoleColors.CYAN))


def print_finding(finding):
    """
    Print a finding with appropriate colors based on risk level
    
    Args:
        finding (dict): Finding to print
    """
    risk = finding.get('Risk', 'UNKNOWN')
    resource_type = finding.get('ResourceType', 'Unknown')
    resource_id = finding.get('ResourceId', 'Unknown')
    resource_name = finding.get('ResourceName', resource_id)
    region = finding.get('Region', 'Unknown')
    issue = finding.get('Issue', 'Unknown issue')
    
    # Choose color based on risk level
    if risk == 'CRITICAL':
        risk_color = ConsoleColors.BOLD_RED
    elif risk == 'HIGH':
        risk_color = ConsoleColors.BOLD_YELLOW
    elif risk == 'MEDIUM':
        risk_color = ConsoleColors.BOLD_MAGENTA
    elif risk == 'LOW':
        risk_color = ConsoleColors.BOLD_GREEN
    else:
        risk_color = ConsoleColors.BOLD_WHITE
    
    # Print finding details
    print(f"{colorize(f'[{risk}]', risk_color)} {colorize(resource_type, ConsoleColors.BOLD_CYAN)}: {resource_name} ({resource_id}) - {region}")
    print(f"  {colorize('Issue:', ConsoleColors.BOLD_WHITE)} {issue}")
    print(f"  {colorize('Recommendation:', ConsoleColors.BOLD_WHITE)} {finding.get('Recommendation', 'No recommendation provided')}")


def print_summary(findings):
    """
    Print a summary of findings with colors
    
    Args:
        findings (list): List of findings to summarize
    """
    # Group findings by risk level
    risk_counts = {}
    for finding in findings:
        risk = finding.get('Risk', 'UNKNOWN')
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
    
    # Group findings by resource type
    resource_counts = {}
    for finding in findings:
        resource_type = finding.get('ResourceType', 'UNKNOWN')
        resource_counts[resource_type] = resource_counts.get(resource_type, 0) + 1
    
    # Print summary
    print_header("Scan Summary")
    print(f"Total findings: {colorize(str(len(findings)), ConsoleColors.BOLD_WHITE)}")
    
    # Print risk level counts
    print(colorize("\nFindings by risk level:", ConsoleColors.BOLD_WHITE))
    risk_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
    for risk in risk_order:
        if risk in risk_counts:
            if risk == 'CRITICAL':
                color = ConsoleColors.BOLD_RED
            elif risk == 'HIGH':
                color = ConsoleColors.BOLD_YELLOW
            elif risk == 'MEDIUM':
                color = ConsoleColors.BOLD_MAGENTA
            elif risk == 'LOW':
                color = ConsoleColors.BOLD_GREEN
            else:
                color = ConsoleColors.BOLD_WHITE
            
            print(f"- {colorize(risk, color)}: {risk_counts[risk]}")
    
    # Print resource type counts
    print(colorize("\nFindings by resource type:", ConsoleColors.BOLD_WHITE))
    for resource_type, count in sorted(resource_counts.items()):
        print(f"- {colorize(resource_type, ConsoleColors.BOLD_CYAN)}: {count}")


def print_progress(current, total, message="Processing"):
    """
    Print a progress bar
    
    Args:
        current (int): Current progress
        total (int): Total items
        message (str): Message to display
    """
    bar_length = 40
    progress = min(1.0, current / total if total > 0 else 1.0)
    filled_length = int(bar_length * progress)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    percent = int(100 * progress)
    
    sys.stdout.write(f"\r{message}: [{colorize(bar, ConsoleColors.BOLD_BLUE)}] {percent}% ({current}/{total})")
    sys.stdout.flush()
    
    if current >= total:
        sys.stdout.write('\n')
        sys.stdout.flush()