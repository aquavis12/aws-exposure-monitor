"""
CSV Reporter Module - Generates CSV reports from findings
"""
import csv
import os
from datetime import datetime


def generate_csv_report(findings, output_path=None):
    """
    Generate a CSV report from findings
    
    Args:
        findings (list): List of findings to include in the report
        output_path (str): Path to save the CSV report (if None, a default path is used)
    
    Returns:
        str: Path to the generated CSV report
    """
    if not findings:
        print("No findings to generate CSV report")
        return None
    
    # Default output path if none provided
    if not output_path:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f"aws_exposure_report_{timestamp}.csv"
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    
    # Define CSV headers based on finding fields
    # Use a set of all possible keys from all findings
    all_keys = set()
    for finding in findings:
        all_keys.update(finding.keys())
    
    # Ensure essential fields are included and ordered first
    essential_fields = ['ResourceType', 'ResourceId', 'ResourceName', 'Region', 'Risk', 'Issue', 'Recommendation']
    headers = [field for field in essential_fields if field in all_keys]
    
    # Add any remaining fields
    headers.extend([key for key in all_keys if key not in essential_fields])
    
    # Write findings to CSV
    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        
        for finding in findings:
            # Ensure all fields have a value (even if empty)
            row = {header: finding.get(header, '') for header in headers}
            writer.writerow(row)
    
    print(f"CSV report generated successfully: {output_path}")
    return output_path