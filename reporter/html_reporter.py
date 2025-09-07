"""
HTML Reporter Module - Generates beautiful HTML reports from findings
"""
import os
import json
from datetime import datetime
from jinja2 import Template



def generate_html_report(findings, output_path=None):
    """
    Generate a visually appealing HTML report from findings
    
    Args:
        findings (list): List of findings to include in the report
        output_path (str): Path to save the HTML report (if None, a default path is used)
    
    Returns:
        str: Path to the generated HTML report
    """
    if not findings:
        print("No findings to generate report")
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
    
    # Group findings by category
    categories = {
        'Compute': [],
        'Security': [],
        'Database': [],
        'Storage': [],
        'Networking': [],
        'Cost': [],
        'Other': []
    }
    
    # Categorize findings based on resource type
    for finding in findings:
        resource_type = finding.get('ResourceType', 'Unknown')
        
        if resource_type in ['EC2 Instance', 'Lambda Function', 'ECS Cluster', 'EKS Cluster', 'Lightsail Instance']:
            categories['Compute'].append(finding)
        elif resource_type in ['IAM User', 'IAM Role', 'IAM Policy', 'Security Group', 'KMS Key', 'CloudTrail', 'GuardDuty', 'WAF Web ACL']:
            categories['Security'].append(finding)
        elif resource_type in ['RDS Instance', 'RDS Snapshot', 'DynamoDB Table', 'Aurora Cluster', 'ElastiCache Cluster', 'RDS Parameter Group']:
            categories['Database'].append(finding)
        elif resource_type in ['S3 Bucket', 'S3 Object', 'EBS Volume', 'EBS Snapshot', 'EFS File System']:
            categories['Storage'].append(finding)
        elif resource_type in ['VPC', 'Subnet', 'Internet Gateway', 'Route Table', 'Network ACL', 'Elastic IP', 'API Gateway', 'CloudFront Distribution']:
            categories['Networking'].append(finding)
        elif 'Cost' in finding.get('Issue', '') or resource_type == 'Cost Optimization':
            categories['Cost'].append(finding)
        else:
            categories['Other'].append(finding)
    
    # Remove empty categories
    categories = {k: v for k, v in categories.items() if v}
    
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
    
    # Security scoring removed for cleaner UI
    
    # Prepare data for the template
    template_data = {
        'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_findings': len(findings),
        'resource_types': resource_types,
        'risk_levels': dict(sorted_risk_levels),
        'regions': regions,
        'findings': findings,

        'categories': categories
    }
    
    # Load HTML template
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Public Resource Exposure Monitor</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #0f1419;
            --secondary-color: #ff6b35;
            --accent-color: #00d4ff;
            --critical-color: #ff1744;
            --high-color: #ff6d00;
            --medium-color: #00acc1;
            --low-color: #00c853;
            --info-color: #ffc107;
            --unknown-color: #9e9e9e;
            --bg-dark: #0a0e13;
            --bg-light: #f8fafc;
            --bg-white: #ffffff;
            --bg-card: #ffffff;
            --text-dark: #1a202c;
            --text-light: #718096;
            --text-muted: #a0aec0;
            --border-color: #e2e8f0;
            --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.1);
            --shadow-md: 0 4px 6px rgba(0, 0, 0, 0.07);
            --shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.1);
            --shadow-xl: 0 20px 25px rgba(0, 0, 0, 0.1);
            --radius-sm: 6px;
            --radius-md: 12px;
            --radius-lg: 16px;
            --gradient-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-secondary: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            --gradient-success: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            line-height: 1.6;
            color: var(--text-dark);
            background: #f8fafc;
            padding: 0;
            margin: 0;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        

        
        header {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: white;
            padding: 20px 0;
            margin-bottom: 30px;
            box-shadow: var(--shadow-lg);
        }
        
        header .container {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .logo svg {
            width: 40px;
            height: 40px;
            fill: var(--secondary-color);
            filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.1));
        }
        
        h1, h2, h3, h4 {
            margin-bottom: 15px;
            font-weight: 500;
        }
        
        h1 {
            font-size: 28px;
            color: white;
            font-weight: 700;
        }
        
        h2 {
            font-size: 24px;
            color: var(--primary-color);
            border-bottom: 2px solid var(--secondary-color);
            padding-bottom: 10px;
            margin-top: 40px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .summary-card {
            background: white;
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 24px;
            box-shadow: var(--shadow-md);
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        
        .summary-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--gradient-primary);
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }
        
        .summary-card::after {
            content: '';
            position: absolute;
            top: 20px;
            right: 20px;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent-color);
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-8px) scale(1.02);
            box-shadow: var(--shadow-xl);
        }
        
        .summary-card:hover::before {
            transform: scaleX(1);
        }
        
        .summary-card:hover::after {
            opacity: 1;
            animation: pulse 1.5s infinite;
        }
        
        .summary-card h3 {
            font-size: 18px;
            margin-bottom: 10px;
        }
        
        .summary-card .count {
            font-size: 42px;
            font-weight: 800;
            margin-bottom: 10px;
            color: var(--primary-color);
            line-height: 1;
        }
        
        .card-critical {
            border-top: 4px solid var(--critical-color);
        }
        
        .card-high {
            border-top: 4px solid var(--high-color);
        }
        
        .card-medium {
            border-top: 4px solid var(--medium-color);
        }
        
        .card-low {
            border-top: 4px solid var(--low-color);
        }
        
        .card-info {
            border-top: 4px solid var(--info-color);
        }
        
        .card-total {
            border-top: 4px solid var(--secondary-color);
        }
        
        .charts-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .chart-card {
            background: white;
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 24px;
            box-shadow: var(--shadow-md);
            transition: all 0.3s ease;
        }
        
        .chart-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-lg);
        }
        
        .risk-dots-container {
            display: flex;
            flex-direction: column;
            gap: 20px;
            padding: 20px 0;
        }
        
        .risk-dot-group {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 12px 0;
            border-bottom: 1px solid rgba(226, 232, 240, 0.3);
        }
        
        .risk-dot-group:last-child {
            border-bottom: none;
        }
        
        .risk-dot {
            width: 16px;
            height: 16px;
            border-radius: 50%;
            position: relative;
            animation: pulse 2s infinite;
        }
        
        .risk-dot::after {
            content: '';
            position: absolute;
            top: -4px;
            left: -4px;
            right: -4px;
            bottom: -4px;
            border-radius: 50%;
            border: 2px solid currentColor;
            opacity: 0;
            animation: ripple 2s infinite;
        }
        
        .risk-dot.risk-critical {
            background: var(--critical-color);
            color: var(--critical-color);
        }
        
        .risk-dot.risk-high {
            background: var(--high-color);
            color: var(--high-color);
        }
        
        .risk-dot.risk-medium {
            background: var(--medium-color);
            color: var(--medium-color);
        }
        
        .risk-dot.risk-low {
            background: var(--low-color);
            color: var(--low-color);
        }
        
        .risk-dot.risk-unknown {
            background: var(--unknown-color);
            color: var(--unknown-color);
        }
        
        .risk-dot.risk-info {
            background: var(--info-color);
            color: var(--info-color);
        }
        
        .risk-label {
            font-weight: 600;
            font-size: 14px;
            min-width: 80px;
        }
        
        .risk-count {
            font-weight: 700;
            font-size: 18px;
            color: var(--text-dark);
            margin-left: auto;
        }
        
        .status-grid {
            display: flex;
            flex-direction: column;
            gap: 20px;
            padding: 20px 0;
        }
        
        .status-item {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 15px;
            background: #f1f5f9;
            border-radius: var(--radius-md);
            transition: all 0.3s ease;
        }
        
        .status-item:hover {
            background: #e2e8f0;
            transform: translateX(5px);
        }
        
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            position: relative;
        }
        
        .status-dot::before {
            content: '';
            position: absolute;
            top: -2px;
            left: -2px;
            right: -2px;
            bottom: -2px;
            border-radius: 50%;
            background: currentColor;
            opacity: 0.3;
            animation: pulse 2s infinite;
        }
        
        .status-active {
            background: var(--low-color);
            color: var(--low-color);
        }
        
        .status-warning {
            background: var(--high-color);
            color: var(--high-color);
        }
        
        .status-critical {
            background: var(--critical-color);
            color: var(--critical-color);
        }
        
        .status-info {
            flex: 1;
        }
        
        .status-label {
            font-size: 13px;
            color: var(--text-light);
            margin-bottom: 4px;
        }
        
        .status-value {
            font-size: 20px;
            font-weight: 700;
            color: var(--text-dark);
        }
        
        @keyframes pulse {
            0%, 100% {
                transform: scale(1);
                opacity: 1;
            }
            50% {
                transform: scale(1.1);
                opacity: 0.8;
            }
        }
        
        @keyframes ripple {
            0% {
                transform: scale(0.8);
                opacity: 1;
            }
            100% {
                transform: scale(2);
                opacity: 0;
            }
        }
        
        .chart-title {
            font-size: 18px;
            margin-bottom: 15px;
            color: var(--primary-color);
            text-align: center;
        }
        
        .table-container {
            background: white;
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            padding: 0;
            box-shadow: var(--shadow-md);
            margin-bottom: 30px;
            overflow: hidden;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: white;
            padding: 16px 20px;
            text-align: left;
            font-weight: 600;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        th:first-child {
            border-top-left-radius: 6px;
        }
        
        th:last-child {
            border-top-right-radius: 6px;
        }
        
        td {
            padding: 16px 20px;
            border-bottom: 1px solid rgba(226, 232, 240, 0.5);
            font-size: 14px;
        }
        
        tr:nth-child(even) {
            background-color: rgba(0, 0, 0, 0.02);
        }
        
        tr:hover {
            background-color: #f1f5f9;
        }
        
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            color: white;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            box-shadow: var(--shadow-sm);
            position: relative;
            overflow: hidden;
        }
        
        .badge::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s;
        }
        
        .badge:hover::before {
            left: 100%;
        }
        
        .badge-critical {
            background-color: var(--critical-color);
        }
        
        .badge-high {
            background-color: var(--high-color);
        }
        
        .badge-medium {
            background-color: var(--medium-color);
        }
        
        .badge-low {
            background-color: var(--low-color);
        }
        
        .badge-unknown {
            background-color: var(--unknown-color);
        }
        
        .badge-info {
            background-color: var(--info-color);
        }
        
        .resource-section {
            margin-bottom: 40px;
        }
        
        .resource-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .resource-count {
            background-color: var(--secondary-color);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 500;
        }
        
        .footer {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: white;
            padding: 30px 0;
            text-align: center;
            margin-top: 50px;
        }
        
        .footer p {
            margin: 5px 0;
            font-size: 14px;
        }
        
        .footer a {
            color: var(--secondary-color);
            text-decoration: none;
        }
        
        .footer a:hover {
            text-decoration: underline;
        }
        
        .filters {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .filter-button {
            background: white;
            border: 1px solid var(--border-color);
            border-radius: 25px;
            padding: 10px 18px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.3s ease;
            color: var(--text-dark);
        }
        
        .filter-button:hover, .filter-button.active {
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .recommendation {
            background: #fef3c7;
            border-left: 3px solid #f59e0b;
            padding: 12px 16px;
            border-radius: 0 8px 8px 0;
            font-size: 13px;
            line-height: 1.5;
        }
        
        .no-findings {
            padding: 20px;
            text-align: center;
            background-color: var(--bg-white);
            border-radius: var(--radius);
            margin-bottom: 30px;
            box-shadow: var(--shadow);
            color: var(--text-light);
            font-style: italic;
        }
        
        .security-score-container {
            background-color: var(--bg-white);
            border-radius: var(--radius);
            padding: 20px;
            box-shadow: var(--shadow);
            margin-bottom: 30px;
            text-align: center;
        }
        
        .security-score-title {
            font-size: 24px;
            margin-bottom: 15px;
            color: var(--primary-color);
        }
        
        .security-score {
            font-size: 72px;
            font-weight: 700;
            margin: 20px 0;
        }
        
        .score-excellent {
            color: var(--score-excellent);
        }
        
        .score-good {
            color: var(--score-good);
        }
        
        .score-fair {
            color: var(--score-fair);
        }
        
        .score-poor {
            color: var(--score-poor);
        }
        
        .score-critical {
            color: var(--score-critical);
        }
        
        .score-label {
            font-size: 24px;
            font-weight: 500;
            margin-bottom: 10px;
        }
        
        .score-description {
            font-size: 16px;
            color: var(--text-light);
            max-width: 600px;
            margin: 0 auto;
        }
        
        .score-meter {
            width: 100%;
            height: 20px;
            background-color: #e0e0e0;
            border-radius: 10px;
            margin: 20px 0;
            overflow: hidden;
            position: relative;
        }
        
        .score-meter-fill {
            height: 100%;
            border-radius: 10px;
            background: linear-gradient(90deg, var(--score-critical) 0%, var(--score-poor) 25%, var(--score-fair) 50%, var(--score-good) 75%, var(--score-excellent) 100%);
            transition: width 1s ease-in-out;
        }
        
        .score-marker {
            position: absolute;
            top: -10px;
            width: 4px;
            height: 40px;
            background-color: var(--primary-color);
            transform: translateX(-50%);
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .summary-card, .chart-card, .table-container {
            animation: fadeInUp 0.6s ease-out;
        }
        
        .summary-card:nth-child(1) { animation-delay: 0.1s; }
        .summary-card:nth-child(2) { animation-delay: 0.2s; }
        .summary-card:nth-child(3) { animation-delay: 0.3s; }
        .summary-card:nth-child(4) { animation-delay: 0.4s; }
        .summary-card:nth-child(5) { animation-delay: 0.5s; }
        
        @media (max-width: 768px) {
            .charts-container {
                grid-template-columns: 1fr;
            }
            
            .summary-grid {
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }
            
            header .container {
                flex-direction: column;
                text-align: center;
            }
            
            .logo {
                margin-bottom: 15px;
                justify-content: center;
            }
            
            .container {
                padding: 15px;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div class="logo">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13h2v6h-2zm0 8h2v2h-2z"/>
                </svg>
                <h1>AWS Public Resource Exposure Monitor</h1>
            </div>
            <div class="report-date">
                Generated on: {{ report_date }}
            </div>
        </div>
    </header>
    
    <div class="container">

        
        <div class="summary-grid">
            <div class="summary-card card-total">
                <h3>Total Findings</h3>
                <div class="count">{{ total_findings }}</div>
            </div>
            {% for risk, items in risk_levels.items() %}
            <div class="summary-card card-{{ risk.lower() }}">
                <h3>{{ risk }} Risk</h3>
                <div class="count">{{ items|length }}</div>
            </div>
            {% endfor %}
        </div>
        
        <h2>Security Findings Overview</h2>
        
        <div class="charts-container">
            <div class="chart-card">
                <div class="chart-title">Findings by Resource Type</div>
                <canvas id="resourceTypeChart"></canvas>
            </div>
            <div class="chart-card">
                <div class="chart-title">Risk Distribution</div>
                <div class="risk-dots-container">
                    {% for risk, items in risk_levels.items() %}
                    <div class="risk-dot-group">
                        <div class="risk-dot risk-{{ risk.lower() }}"></div>
                        <span class="risk-label">{{ risk }}</span>
                        <span class="risk-count">{{ items|length }}</span>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
        
        <div class="charts-container">
            <div class="chart-card">
                <div class="chart-title">Regional Distribution</div>
                <canvas id="regionChart"></canvas>
            </div>
            <div class="chart-card">
                <div class="chart-title">Security Status Overview</div>
                <div class="status-grid">
                    <div class="status-item">
                        <div class="status-dot status-active"></div>
                        <div class="status-info">
                            <div class="status-label">Total Resources Scanned</div>
                            <div class="status-value">{{ resource_types|length }}</div>
                        </div>
                    </div>
                    <div class="status-item">
                        <div class="status-dot status-warning"></div>
                        <div class="status-info">
                            <div class="status-label">Regions Analyzed</div>
                            <div class="status-value">{{ regions|length }}</div>
                        </div>
                    </div>
                    <div class="status-item">
                        <div class="status-dot status-critical"></div>
                        <div class="status-info">
                            <div class="status-label">Critical Issues</div>
                            <div class="status-value">{{ risk_levels.get('CRITICAL', [])|length }}</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <h2>Findings by Category</h2>
        
        <div class="filters">
            <button class="filter-button active" data-filter="all">All</button>
            {% for risk in risk_levels.keys() %}
            <button class="filter-button" data-filter="{{ risk.lower() }}">{{ risk }}</button>
            {% endfor %}
            {% for category_name, items in categories.items() %}
            <button class="filter-button" data-filter="category-{{ category_name.lower() }}">{{ category_name }}</button>
            {% endfor %}
        </div>
        
        <div id="category-sections">
            {% for category_name, items in categories.items() %}
            <div class="category-section" data-category="{{ category_name.lower() }}">
                <div class="resource-header">
                    <h2>{{ category_name }}</h2>
                    <span class="resource-count">{{ items|length }} findings</span>
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Resource Type</th>
                                <th>Resource ID</th>
                                <th>Region</th>
                                <th>Risk</th>
                                <th>Issue</th>
                                <th>Recommendation</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for finding in items %}
                            <tr class="finding-row risk-{{ finding.Risk|lower }} category-{{ category_name.lower() }}">
                                <td>{{ finding.ResourceType }}</td>
                                <td>{{ finding.ResourceName if finding.ResourceName else finding.ResourceId }}</td>
                                <td>{{ finding.Region }}</td>
                                <td>
                                    <span class="badge badge-{{ finding.Risk|lower }}">{{ finding.Risk }}</span>
                                </td>
                                <td>{{ finding.Issue }}</td>
                                <td class="recommendation">{{ finding.Recommendation }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% endfor %}
        </div>
        
        <h2>Detailed Findings by Resource Type</h2>
        
        <div id="resource-sections">
            {% for resource_type, items in resource_types.items() %}
            <div class="resource-section" data-resource-type="{{ resource_type }}">
                <div class="resource-header">
                    <h2>{{ resource_type }}</h2>
                    <span class="resource-count">{{ items|length }} findings</span>
                </div>
                
                <div class="table-container">
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
                            <tr class="finding-row risk-{{ finding.Risk|lower }}">
                                <td>{{ finding.ResourceId }}</td>
                                <td>{{ finding.ResourceName if finding.ResourceName else finding.ResourceId }}</td>
                                <td>{{ finding.Region }}</td>
                                <td>
                                    <span class="badge badge-{{ finding.Risk|lower }}">{{ finding.Risk }}</span>
                                </td>
                                <td>{{ finding.Issue }}</td>
                                <td class="recommendation">{{ finding.Recommendation }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
    
    <footer class="footer">
        <div class="container">
            <p>AWS Public Resource Exposure Monitor - Security Scan Report</p>
            <p>Scan completed on {{ report_date }}</p>
        </div>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // Set up color scheme
        const colors = {
            resourceTypes: [
                '#FF9900', '#232F3E', '#1E88E5', '#00A1B0', '#EB5F07', 
                '#7AA116', '#8C4FFF', '#FF5252', '#00C853', '#AA00FF',
                '#0097A7', '#FF6D00', '#6200EA', '#2962FF', '#00BFA5'
            ],
            riskLevels: {
                'CRITICAL': '#d13212',
                'HIGH': '#ff9900',
                'MEDIUM': '#2b7489',
                'LOW': '#1e88e5',
                'INFO': '#ffc107',
                'UNKNOWN': '#757575'
            }
        };

        // Resource Type Chart
        const resourceTypeCtx = document.getElementById('resourceTypeChart').getContext('2d');
        const resourceTypeLabels = [{% for resource_type, items in resource_types.items() %}'{{ resource_type }}',{% endfor %}];
        const resourceTypeData = [{% for resource_type, items in resource_types.items() %}{{ items|length }},{% endfor %}];
        
        new Chart(resourceTypeCtx, {
            type: 'doughnut',
            data: {
                labels: resourceTypeLabels,
                datasets: [{
                    data: resourceTypeData,
                    backgroundColor: colors.resourceTypes.slice(0, resourceTypeLabels.length),
                    borderWidth: 1,
                    borderColor: '#ffffff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            boxWidth: 15,
                            padding: 15
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
        
        // Risk Level Chart
        const riskLevelCtx = document.getElementById('riskLevelChart').getContext('2d');
        const riskLevelLabels = [{% for risk, items in risk_levels.items() %}'{{ risk }}',{% endfor %}];
        const riskLevelData = [{% for risk, items in risk_levels.items() %}{{ items|length }},{% endfor %}];
        const riskLevelColors = riskLevelLabels.map(label => colors.riskLevels[label] || '#757575');
        
        new Chart(riskLevelCtx, {
            type: 'pie',
            data: {
                labels: riskLevelLabels,
                datasets: [{
                    data: riskLevelData,
                    backgroundColor: riskLevelColors,
                    borderWidth: 1,
                    borderColor: '#ffffff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            boxWidth: 15,
                            padding: 15
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
        
        // Region Chart
        const regionCtx = document.getElementById('regionChart').getContext('2d');
        const regionLabels = [{% for region, count in regions.items() %}{% if count > 0 %}'{{ region }}',{% endif %}{% endfor %}];
        const regionData = [{% for region, count in regions.items() %}{% if count > 0 %}{{ count }},{% endif %}{% endfor %}];
        
        new Chart(regionCtx, {
            type: 'bar',
            data: {
                labels: regionLabels,
                datasets: [{
                    label: 'Findings',
                    data: regionData,
                    backgroundColor: '#FF9900',
                    borderColor: '#232F3E',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
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
        
        // Filter functionality
        document.addEventListener('DOMContentLoaded', function() {
            const filterButtons = document.querySelectorAll('.filter-button');
            const findingRows = document.querySelectorAll('.finding-row');
            const resourceSections = document.querySelectorAll('.resource-section');
            const categorySections = document.querySelectorAll('.category-section');
            
            filterButtons.forEach(button => {
                button.addEventListener('click', function() {
                    const filter = this.getAttribute('data-filter');
                    
                    // Update active button
                    filterButtons.forEach(btn => btn.classList.remove('active'));
                    this.classList.add('active');
                    
                    // Filter rows
                    findingRows.forEach(row => {
                        if (filter === 'all') {
                            row.style.display = '';
                        } else if (filter.startsWith('category-')) {
                            // Category filter
                            const category = filter.replace('category-', '');
                            if (row.classList.contains(filter)) {
                                row.style.display = '';
                            } else {
                                row.style.display = 'none';
                            }
                        } else {
                            // Risk level filter
                            if (row.classList.contains(`risk-${filter}`)) {
                                row.style.display = '';
                            } else {
                                row.style.display = 'none';
                            }
                        }
                    });
                    
                    // Hide empty resource sections
                    resourceSections.forEach(section => {
                        const visibleRows = section.querySelectorAll('.finding-row[style="display: none;"]').length;
                        const totalRows = section.querySelectorAll('.finding-row').length;
                        
                        if (visibleRows === totalRows) {
                            section.style.display = 'none';
                        } else {
                            section.style.display = '';
                            
                            // Update the count in the resource header
                            const visibleCount = totalRows - visibleRows;
                            const countElement = section.querySelector('.resource-count');
                            if (countElement) {
                                countElement.textContent = `${visibleCount} findings`;
                            }
                        }
                    });
                    
                    // Hide empty category sections
                    categorySections.forEach(section => {
                        const visibleRows = section.querySelectorAll('.finding-row[style="display: none;"]').length;
                        const totalRows = section.querySelectorAll('.finding-row').length;
                        
                        if (visibleRows === totalRows) {
                            section.style.display = 'none';
                        } else {
                            section.style.display = '';
                            
                            // Update the count in the category header
                            const visibleCount = totalRows - visibleRows;
                            const countElement = section.querySelector('.resource-count');
                            if (countElement) {
                                countElement.textContent = `${visibleCount} findings`;
                            }
                        }
                    });
                    
                    // Check if all sections are hidden
                    const allResourceSectionsHidden = Array.from(resourceSections).every(section => 
                        section.style.display === 'none'
                    );
                    
                    const allCategorySectionsHidden = Array.from(categorySections).every(section => 
                        section.style.display === 'none'
                    );
                    
                    // Show a message if no findings match the filter
                    let noFindingsMessage = document.getElementById('no-findings-message');
                    if (allResourceSectionsHidden && allCategorySectionsHidden) {
                        if (!noFindingsMessage) {
                            noFindingsMessage = document.createElement('div');
                            noFindingsMessage.id = 'no-findings-message';
                            noFindingsMessage.className = 'no-findings';
                            
                            if (filter.startsWith('category-')) {
                                const category = filter.replace('category-', '');
                                noFindingsMessage.textContent = `No findings in ${category.toUpperCase()} category to display`;
                            } else {
                                noFindingsMessage.textContent = `No ${filter.toUpperCase()} risk findings to display`;
                            }
                            
                            document.getElementById('resource-sections').appendChild(noFindingsMessage);
                        }
                    } else if (noFindingsMessage) {
                        noFindingsMessage.remove();
                    }
                });
            });
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
    
    print(f"HTML report generated successfully: {output_path}")
    return output_path