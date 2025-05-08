"""
HTML Reporter Module - Generates beautiful HTML reports from findings
"""
import os
import json
from datetime import datetime
from jinja2 import Template
from reporter.security_score import calculate_security_score


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
    
    # Calculate security score
    security_score = calculate_security_score(findings)
    
    # Prepare data for the template
    template_data = {
        'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_findings': len(findings),
        'resource_types': resource_types,
        'risk_levels': dict(sorted_risk_levels),
        'regions': regions,
        'findings': findings,
        'security_score': security_score
    }
    
    # Load HTML template
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Public Resource Exposure Monitor</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #232f3e;
            --secondary-color: #ff9900;
            --critical-color: #d13212;
            --high-color: #ff9900;
            --medium-color: #2b7489;
            --low-color: #1e88e5;
            --unknown-color: #757575;
            --bg-light: #f9f9f9;
            --bg-white: #ffffff;
            --text-dark: #232f3e;
            --text-light: #666666;
            --border-color: #e0e0e0;
            --shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            --radius: 8px;
            --score-excellent: #4caf50;
            --score-good: #8bc34a;
            --score-fair: #ffeb3b;
            --score-poor: #ff9800;
            --score-critical: #f44336;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Roboto', sans-serif;
            line-height: 1.6;
            color: var(--text-dark);
            background-color: var(--bg-light);
            padding: 0;
            margin: 0;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(135deg, var(--primary-color) 0%, #37475a 100%);
            color: white;
            padding: 30px 0;
            margin-bottom: 30px;
            box-shadow: var(--shadow);
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
        }
        
        h1, h2, h3, h4 {
            margin-bottom: 15px;
            font-weight: 500;
        }
        
        h1 {
            font-size: 28px;
            color: white;
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
            background-color: var(--bg-white);
            border-radius: var(--radius);
            padding: 20px;
            box-shadow: var(--shadow);
            transition: transform 0.3s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
        }
        
        .summary-card h3 {
            font-size: 18px;
            margin-bottom: 10px;
        }
        
        .summary-card .count {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 10px;
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
            background-color: var(--bg-white);
            border-radius: var(--radius);
            padding: 20px;
            box-shadow: var(--shadow);
        }
        
        .chart-title {
            font-size: 18px;
            margin-bottom: 15px;
            color: var(--primary-color);
            text-align: center;
        }
        
        .table-container {
            background-color: var(--bg-white);
            border-radius: var(--radius);
            padding: 20px;
            box-shadow: var(--shadow);
            margin-bottom: 30px;
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background-color: var(--primary-color);
            color: white;
            padding: 12px 15px;
            text-align: left;
            font-weight: 500;
        }
        
        th:first-child {
            border-top-left-radius: 6px;
        }
        
        th:last-child {
            border-top-right-radius: 6px;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
        }
        
        tr:nth-child(even) {
            background-color: rgba(0, 0, 0, 0.02);
        }
        
        tr:hover {
            background-color: rgba(255, 153, 0, 0.05);
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 500;
            color: white;
            text-transform: uppercase;
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
            background-color: var(--primary-color);
            color: white;
            padding: 20px 0;
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
            background-color: var(--bg-white);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 8px 15px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s ease;
        }
        
        .filter-button:hover, .filter-button.active {
            background-color: var(--secondary-color);
            color: white;
            border-color: var(--secondary-color);
        }
        
        .recommendation {
            background-color: rgba(255, 153, 0, 0.1);
            border-left: 3px solid var(--secondary-color);
            padding: 10px 15px;
            border-radius: 0 4px 4px 0;
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
        <!-- Security Score Section -->
        <div class="security-score-container">
            <div class="security-score-title">Security Score</div>
            <div class="security-score {{ security_score.css_class }}">{{ security_score.score }}</div>
            <div class="score-label">{{ security_score.label }}</div>
            <div class="score-description">{{ security_score.description }}</div>
            <div class="score-meter">
                <div class="score-meter-fill" style="width: {{ security_score.score }}%"></div>
                <div class="score-marker" style="left: {{ security_score.score }}%"></div>
            </div>
        </div>
        
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
                <div class="chart-title">Findings by Risk Level</div>
                <canvas id="riskLevelChart"></canvas>
            </div>
        </div>
        
        <div class="chart-card">
            <div class="chart-title">Findings by AWS Region</div>
            <canvas id="regionChart"></canvas>
        </div>
        
        <h2>Detailed Findings</h2>
        
        <div class="filters">
            <button class="filter-button active" data-filter="all">All</button>
            {% for risk in risk_levels.keys() %}
            <button class="filter-button" data-filter="{{ risk.lower() }}">{{ risk }}</button>
            {% endfor %}
        </div>
        
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
        const regionLabels = [{% for region, count in regions.items() %}'{{ region }}',{% endfor %}];
        const regionData = [{% for region, count in regions.items() %}{{ count }},{% endfor %}];
        
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
                        } else {
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
                    
                    // Check if all sections are hidden
                    const allSectionsHidden = Array.from(resourceSections).every(section => 
                        section.style.display === 'none'
                    );
                    
                    // Show a message if no findings match the filter
                    let noFindingsMessage = document.getElementById('no-findings-message');
                    if (allSectionsHidden) {
                        if (!noFindingsMessage) {
                            noFindingsMessage = document.createElement('div');
                            noFindingsMessage.id = 'no-findings-message';
                            noFindingsMessage.className = 'no-findings';
                            noFindingsMessage.textContent = `No ${filter.toUpperCase()} risk findings to display`;
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