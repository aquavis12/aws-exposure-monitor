"""
HTML Reporter Module - Generates HTML reports from findings
"""
import os
import json
from datetime import datetime
from jinja2 import Template


def generate_html_report(findings, output_path=None):
    """
    Generate an HTML report from findings
    
    Args:
        findings (list): List of findings to include in the report
        output_path (str): Path to save the HTML report (if None, a default path is used)
    
    Returns:
        str: Path to the generated HTML report
    """
    if not findings:
        return None
    
    # Default output path if none provided
    if not output_path:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f"aws_exposure_report_{timestamp}.html"
    
    # Group findings by resource type
    resource_types = {}
    for finding in findings:
        resource_type = finding.get('ResourceType', 'Unknown')
        if resource_type not in resource_types:
            resource_types[resource_type] = []
        resource_types[resource_type].append(finding)
    
    # Group findings by risk level
    risk_levels = {}
    for finding in findings:
        risk = finding.get('Risk', 'UNKNOWN')
        if risk not in risk_levels:
            risk_levels[risk] = []
        risk_levels[risk].append(finding)
    
    # Sort risk levels by severity
    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
    sorted_risk_levels = sorted(risk_levels.items(), key=lambda x: risk_order.get(x[0], 5))
    
    # Count findings by region
    regions = {}
    for finding in findings:
        region = finding.get('Region', 'Unknown')
        if region not in regions:
            regions[region] = 0
        regions[region] += 1
    
    # Prepare data for the template
    template_data = {
        'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_findings': len(findings),
        'resource_types': resource_types,
        'risk_levels': dict(sorted_risk_levels),
        'regions': regions,
        'findings': findings
    }
    
    # Load HTML template
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Exposure Monitor Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #0066cc;
        }
        .header {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 5px solid #0066cc;
        }
        .summary {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            flex: 1;
            min-width: 200px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .risk-critical {
            background-color: #ffebee;
            border-left: 5px solid #d32f2f;
        }
        .risk-high {
            background-color: #fff8e1;
            border-left: 5px solid #ff9800;
        }
        .risk-medium {
            background-color: #e8f5e9;
            border-left: 5px solid #4caf50;
        }
        .risk-low {
            background-color: #e3f2fd;
            border-left: 5px solid #2196f3;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .resource-section {
            margin-bottom: 40px;
        }
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }
        .badge-critical {
            background-color: #d32f2f;
        }
        .badge-high {
            background-color: #ff9800;
        }
        .badge-medium {
            background-color: #4caf50;
        }
        .badge-low {
            background-color: #2196f3;
        }
        .badge-unknown {
            background-color: #9e9e9e;
        }
        .chart-container {
            display: flex;
            gap: 20px;
            margin-bottom: 30px;
        }
        .chart {
            flex: 1;
            min-width: 300px;
            height: 300px;
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .footer {
            margin-top: 50px;
            text-align: center;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>AWS Exposure Monitor Report</h1>
        <p>Generated on: {{ report_date }}</p>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <h3>Total Findings</h3>
            <p style="font-size: 24px; font-weight: bold;">{{ total_findings }}</p>
        </div>
        {% for risk, items in risk_levels.items() %}
        <div class="summary-card risk-{{ risk.lower() }}">
            <h3>{{ risk }}</h3>
            <p style="font-size: 24px; font-weight: bold;">{{ items|length }}</p>
        </div>
        {% endfor %}
    </div>
    
    <h2>Findings by Resource Type</h2>
    <div class="chart-container">
        <div class="chart">
            <canvas id="resourceTypeChart"></canvas>
        </div>
        <div class="chart">
            <canvas id="riskLevelChart"></canvas>
        </div>
    </div>
    
    <h2>Findings by Region</h2>
    <div class="chart">
        <canvas id="regionChart"></canvas>
    </div>
    
    {% for resource_type, items in resource_types.items() %}
    <div class="resource-section">
        <h2>{{ resource_type }} ({{ items|length }})</h2>
        <table>
            <thead>
                <tr>
                    <th>Resource ID</th>
                    <th>Resource Name</th>
                    <th>Region</th>
                    <th>Risk</th>
                    <th>Issue</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {% for finding in items %}
                <tr>
                    <td>{{ finding.ResourceId }}</td>
                    <td>{{ finding.ResourceName if finding.ResourceName else finding.ResourceId }}</td>
                    <td>{{ finding.Region }}</td>
                    <td>
                        <span class="badge badge-{{ finding.Risk|lower }}">{{ finding.Risk }}</span>
                    </td>
                    <td>{{ finding.Issue }}</td>
                    <td>{{ finding.Recommendation }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endfor %}
    
    <div class="footer">
        <p>AWS Exposure Monitor - Scan completed on {{ report_date }}</p>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // Resource Type Chart
        const resourceTypeCtx = document.getElementById('resourceTypeChart').getContext('2d');
        const resourceTypeChart = new Chart(resourceTypeCtx, {
            type: 'pie',
            data: {
                labels: [{% for resource_type, items in resource_types.items() %}'{{ resource_type }}',{% endfor %}],
                datasets: [{
                    data: [{% for resource_type, items in resource_types.items() %}{{ items|length }},{% endfor %}],
                    backgroundColor: [
                        '#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b',
                        '#6f42c1', '#fd7e14', '#20c9a6', '#858796', '#5a5c69'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    title: {
                        display: true,
                        text: 'Findings by Resource Type'
                    }
                }
            }
        });
        
        // Risk Level Chart
        const riskLevelCtx = document.getElementById('riskLevelChart').getContext('2d');
        const riskLevelChart = new Chart(riskLevelCtx, {
            type: 'pie',
            data: {
                labels: [{% for risk, items in risk_levels.items() %}'{{ risk }}',{% endfor %}],
                datasets: [{
                    data: [{% for risk, items in risk_levels.items() %}{{ items|length }},{% endfor %}],
                    backgroundColor: [
                        '#d32f2f', '#ff9800', '#4caf50', '#2196f3', '#9e9e9e'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    title: {
                        display: true,
                        text: 'Findings by Risk Level'
                    }
                }
            }
        });
        
        // Region Chart
        const regionCtx = document.getElementById('regionChart').getContext('2d');
        const regionChart = new Chart(regionCtx, {
            type: 'bar',
            data: {
                labels: [{% for region, count in regions.items() %}'{{ region }}',{% endfor %}],
                datasets: [{
                    label: 'Findings',
                    data: [{% for region, count in regions.items() %}{{ count }},{% endfor %}],
                    backgroundColor: '#4e73df'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'Findings by Region'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>
    """
    
    # Render template
    template = Template(html_template)
    html_content = template.render(**template_data)
    
    # Write to file
    with open(output_path, 'w') as f:
        f.write(html_content)
    
    return output_path