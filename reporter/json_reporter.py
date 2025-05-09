"""
JSON Reporter Module - Generates JSON reports from findings
"""
import json
import os
from datetime import datetime


def generate_json_report(findings, output_path=None):
    """
    Generate a JSON report from findings
    
    Args:
        findings (list): List of findings to include in the report
        output_path (str): Path to save the JSON report (if None, a default path is used)
    
    Returns:
        str: Path to the generated JSON report
    """
    if not findings:
        print("No findings to generate JSON report")
        return None
    
    # Default output path if none provided
    if not output_path:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f"aws_exposure_report_{timestamp}.json"
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    
    # Prepare report data
    report_data = {
        'generated_at': datetime.now().isoformat(),
        'total_findings': len(findings),
        'findings': findings
    }
    
    # Count findings by risk level
    risk_counts = {}
    for finding in findings:
        risk = finding.get('Risk', 'UNKNOWN')
        if risk not in risk_counts:
            risk_counts[risk] = 0
        risk_counts[risk] += 1
    
    report_data['risk_summary'] = risk_counts
    
    # Count findings by resource type
    resource_counts = {}
    for finding in findings:
        resource_type = finding.get('ResourceType', 'Unknown')
        if resource_type not in resource_counts:
            resource_counts[resource_type] = 0
        resource_counts[resource_type] += 1
    
    report_data['resource_summary'] = resource_counts
    
    # Write report to file
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, default=str)
    
    print(f"JSON report generated successfully: {output_path}")
    return output_path