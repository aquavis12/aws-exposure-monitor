"""
HTML Reporter Module - Generates clean HTML reports from findings
"""
import os
from datetime import datetime
from jinja2 import Template


def generate_html_report(findings, output_path=None):
    """Generate a clean HTML report from findings"""
    if not findings:
        print("No findings to generate report")
        return None
    
    if not output_path:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f"aws_exposure_report_{timestamp}.html"
    
    # Category mappings
    category_mappings = {
        'Compute': ['EC2 Instance', 'Lambda Function', 'ECS Cluster', 'EKS Cluster', 'Lightsail Instance', 'AMI', 'ECR Repository'],
        'Security': ['IAM User', 'IAM Role', 'IAM Policy', 'IAM Access Key', 'Security Group', 'KMS Key', 'CloudTrail', 'GuardDuty', 'WAF Web ACL', 'Inspector', 'Inspector Configuration', 'Security Hub', 'Security Hub Configuration', 'Secrets Manager Secret', 'Tagging Compliance', 'CloudWatch Log Group', 'CloudWatch Logs'],
        'Database': ['RDS Instance', 'RDS Snapshot', 'DynamoDB Table', 'Aurora Cluster', 'ElastiCache Cluster', 'RDS Parameter Group', 'Elasticsearch Domain', 'OpenSearch Domain', 'Redshift Cluster'],
        'Storage': ['S3 Bucket', 'S3 Object', 'EBS Volume', 'EBS Snapshot', 'EFS File System'],
        'Networking': ['VPC', 'Subnet', 'Internet Gateway', 'Route Table', 'Network ACL', 'Elastic IP', 'API Gateway', 'CloudFront Distribution', 'Load Balancer', 'SNS Topic', 'SQS Queue', 'AppSync API'],
        'AI': ['SageMaker Notebook', 'SageMaker Endpoint', 'Bedrock Model', 'Q Business Application']
    }
    
    # Determine categories present in findings
    categories_found = set()
    for finding in findings:
        resource_type = finding.get('ResourceType', 'Unknown')
        for cat_name, cat_types in category_mappings.items():
            if resource_type in cat_types:
                categories_found.add(cat_name)
                break
    
    # If only one category found, group all findings there
    if len(categories_found) == 1:
        single_category = list(categories_found)[0]
        categories = {single_category: findings}
    else:
        # Multiple categories - organize normally
        categories = {}
        for finding in findings:
            resource_type = finding.get('ResourceType', 'Unknown')
            assigned = False
            for cat_name, cat_types in category_mappings.items():
                if resource_type in cat_types:
                    if cat_name not in categories:
                        categories[cat_name] = []
                    categories[cat_name].append(finding)
                    assigned = True
                    break
            if not assigned:
                if 'Other' not in categories:
                    categories['Other'] = []
                categories['Other'].append(finding)
    
    # Risk level counts
    risk_counts = {}
    for finding in findings:
        risk = finding.get('Risk', 'UNKNOWN')
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
    
    # Resource type counts
    resource_counts = {}
    for finding in findings:
        resource_type = finding.get('ResourceType', 'Unknown')
        resource_counts[resource_type] = resource_counts.get(resource_type, 0) + 1
    
    # Region counts
    region_counts = {}
    for finding in findings:
        region = finding.get('Region', 'Unknown')
        region_counts[region] = region_counts.get(region, 0) + 1
    
    # Template data
    template_data = {
        'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_findings': len(findings),
        'categories': categories,
        'risk_counts': risk_counts,
        'resource_counts': resource_counts,
        'region_counts': region_counts,
        'findings': findings
    }
    
    # HTML template
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            line-height: 1.6;
            color: #2d3748;
            background: #f7fafc;
        }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        
        header {
            background: linear-gradient(135deg, #2d3748 0%, #4a5568 100%);
            color: white;
            padding: 30px 0;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        h1 { font-size: 28px; font-weight: 700; margin-bottom: 10px; }
        .subtitle { font-size: 16px; opacity: 0.9; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .stat-card {
            background: white;
            padding: 24px;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            border-left: 4px solid #3182ce;
            transition: transform 0.2s;
        }
        
        .stat-card:hover { transform: translateY(-2px); }
        
        .stat-number {
            font-size: 32px;
            font-weight: 800;
            color: #2d3748;
            margin-bottom: 8px;
        }
        
        .stat-label {
            font-size: 14px;
            color: #718096;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .risk-critical { border-left-color: #e53e3e; }
        .risk-high { border-left-color: #dd6b20; }
        .risk-medium { border-left-color: #3182ce; }
        .risk-low { border-left-color: #38a169; }
        .risk-info { border-left-color: #d69e2e; }
        
        .section {
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
            overflow: hidden;
        }
        
        .section-header {
            background: #f7fafc;
            padding: 20px 24px;
            border-bottom: 1px solid #e2e8f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .section-title {
            font-size: 20px;
            font-weight: 600;
            color: #2d3748;
        }
        
        .section-count {
            background: #3182ce;
            color: white;
            padding: 4px 12px;
            border-radius: 16px;
            font-size: 14px;
            font-weight: 500;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: #2d3748;
            color: white;
            padding: 16px 20px;
            text-align: left;
            font-weight: 600;
            font-size: 14px;
        }
        
        td {
            padding: 16px 20px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 14px;
        }
        
        tr:hover { background: #f7fafc; }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }
        
        .badge-critical { background: #e53e3e; }
        .badge-high { background: #dd6b20; }
        .badge-medium { background: #3182ce; }
        .badge-low { background: #38a169; }
        .badge-info { background: #d69e2e; }
        .badge-unknown { background: #718096; }
        
        .recommendation {
            background: #fef5e7;
            border-left: 3px solid #d69e2e;
            padding: 12px;
            border-radius: 0 6px 6px 0;
            font-size: 13px;
        }
        
        .filters {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            background: white;
            border: 1px solid #e2e8f0;
            padding: 8px 16px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }
        
        .filter-btn:hover, .filter-btn.active {
            background: #3182ce;
            color: white;
            border-color: #3182ce;
        }
        
        footer {
            background: #2d3748;
            color: white;
            text-align: center;
            padding: 20px 0;
            margin-top: 40px;
        }
        
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: 1fr; }
            .container { padding: 15px; }
            table { font-size: 12px; }
            th, td { padding: 12px 16px; }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>AWS Security Report</h1>
            <div class="subtitle">Generated on {{ report_date }}</div>
        </div>
    </header>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{{ total_findings }}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ region_counts|length }}</div>
                <div class="stat-label">Regions Scanned</div>
            </div>
            {% for risk, count in risk_counts.items() %}
            <div class="stat-card risk-{{ risk.lower() }}">
                <div class="stat-number">{{ count }}</div>
                <div class="stat-label">{{ risk }} Risk</div>
            </div>
            {% endfor %}
        </div>
        
        <div class="filters">
            <button class="filter-btn active" data-filter="all">All</button>
            {% for risk in risk_counts.keys() %}
            <button class="filter-btn" data-filter="risk-{{ risk.lower() }}">{{ risk }}</button>
            {% endfor %}
            {% for category in categories.keys() %}
            <button class="filter-btn" data-filter="category-{{ category.lower() }}">{{ category }}</button>
            {% endfor %}
        </div>
        
        {% for category_name, category_findings in categories.items() %}
        <div class="section category-{{ category_name.lower() }}">
            <div class="section-header">
                <div class="section-title">{{ category_name }}</div>
                <div class="section-count">{{ category_findings|length }} findings</div>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>Resource</th>
                        <th>Name</th>
                        <th>Region</th>
                        <th>Risk</th>
                        <th>Issue</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {% for finding in category_findings %}
                    <tr class="finding-row risk-{{ finding.Risk.lower() }} category-{{ category_name.lower() }}">
                        <td>{{ finding.ResourceType }}</td>
                        <td>{{ finding.ResourceName or finding.ResourceId }}</td>
                        <td>{{ finding.Region }}</td>
                        <td><span class="badge badge-{{ finding.Risk.lower() }}">{{ finding.Risk }}</span></td>
                        <td>{{ finding.Issue }}</td>
                        <td><div class="recommendation">{{ finding.Recommendation }}</div></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endfor %}
    </div>
    
    <footer>
        <div class="container">
            <p>AWS Security Report - Generated {{ report_date }}</p>
        </div>
    </footer>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const filterBtns = document.querySelectorAll('.filter-btn');
            const sections = document.querySelectorAll('.section');
            const rows = document.querySelectorAll('.finding-row');
            
            filterBtns.forEach(btn => {
                btn.addEventListener('click', function() {
                    const filter = this.dataset.filter;
                    
                    // Update active button
                    filterBtns.forEach(b => b.classList.remove('active'));
                    this.classList.add('active');
                    
                    // Filter content
                    if (filter === 'all') {
                        sections.forEach(s => s.style.display = 'block');
                        rows.forEach(r => r.style.display = '');
                    } else if (filter.startsWith('category-')) {
                        sections.forEach(s => {
                            s.style.display = s.classList.contains(filter) ? 'block' : 'none';
                        });
                        rows.forEach(r => r.style.display = '');
                    } else if (filter.startsWith('risk-')) {
                        sections.forEach(s => s.style.display = 'block');
                        rows.forEach(r => {
                            r.style.display = r.classList.contains(filter) ? '' : 'none';
                        });
                        
                        // Hide empty sections
                        sections.forEach(s => {
                            const visibleRows = s.querySelectorAll('.finding-row:not([style*="display: none"])');
                            s.style.display = visibleRows.length > 0 ? 'block' : 'none';
                        });
                    }
                });
            });
        });
    </script>
</body>
</html>
    """
    
    # Render and save
    template = Template(html_template)
    html_content = template.render(**template_data)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"HTML report generated: {output_path}")
    return output_path