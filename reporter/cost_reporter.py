"""
Cost Reporter Module - Generates comprehensive cost analysis reports
"""
import boto3
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

def generate_cost_report(output_path: str) -> Optional[str]:
    """Generate comprehensive 6-month cost analysis report
    
    Args:
        output_path: Path where the report should be saved
        
    Returns:
        Optional[str]: Path to the generated report or None if generation failed
        
    Raises:
        ValueError: If output_path is invalid
        boto3.exceptions.Boto3Error: If AWS API calls fail
    """
    if not output_path:
        raise ValueError("output_path cannot be empty")
        
    try:
        ce_client = boto3.client('ce', region_name=os.getenv('AWS_CE_REGION', 'us-east-1'))
        budgets_client = boto3.client('budgets', region_name=os.getenv('AWS_CE_REGION', 'us-east-1'))
        budgets_client = boto3.client('budgets', region_name='us-east-1')
def generate_cost_report(output_path, region=None):
    """Generate comprehensive 6-month cost analysis report"""
    try:
        ce_client = boto3.client('ce', region_name=region or 'us-east-1')
        budgets_client = boto3.client('budgets', region_name=region or 'us-east-1')
        six_months_ago = today - timedelta(days=180)
        
        # Get 6-month cost trends by service
        cost_trends = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': six_months_ago.strftime('%Y-%m-%d'),
                'End': today.strftime('%Y-%m-%d')
            },
            Granularity='MONTHLY',
            Metrics=['BlendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        )
        
        # Get daily costs for last 30 days
        thirty_days_ago = today - timedelta(days=30)
        daily_costs = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': thirty_days_ago.strftime('%Y-%m-%d'),
                'End': today.strftime('%Y-%m-%d')
            },
            Granularity='DAILY',
            Metrics=['BlendedCost']
        )
        
        # Get top cost resources
        top_resources = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': thirty_days_ago.strftime('%Y-%m-%d'),
                'End': today.strftime('%Y-%m-%d')
            },
            Granularity='MONTHLY',
            Metrics=['BlendedCost'],
            GroupBy=[
                {'Type': 'DIMENSION', 'Key': 'SERVICE'},
                {'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'}
            ]
        )
        
        # Process data
        monthly_trends = {}
        service_costs = {}
        
        for result in cost_trends.get('ResultsByTime', []):
            month = result['TimePeriod']['Start']
            for group in result.get('Groups', []):
                service = group['Keys'][0]
                cost = float(group['Metrics']['BlendedCost']['Amount'])
                
                if month not in monthly_trends:
                    monthly_trends[month] = {}
                monthly_trends[month][service] = cost
                
                if service not in service_costs:
                    service_costs[service] = []
                service_costs[service].append({'month': month, 'cost': cost})
        
        # Calculate trends
        trend_analysis = {}
        for service, costs in service_costs.items():
            if len(costs) >= 2:
                recent_cost = costs[-1]['cost']
                previous_cost = costs[-2]['cost'] if len(costs) > 1 else 0
                if previous_cost > 0:
                    trend_pct = ((recent_cost - previous_cost) / previous_cost) * 100
                    trend_analysis[service] = {
                        'current': recent_cost,
                        'previous': previous_cost,
                        'trend': trend_pct
                    }
        
        # Get budget information
        account_id = boto3.client('sts').get_caller_identity()['Account']
        budget_status = []
        
        try:
            budgets = budgets_client.describe_budgets(AccountId=account_id)
            for budget in budgets.get('Budgets', []):
                budget_name = budget.get('BudgetName')
                budget_limit = float(budget.get('BudgetLimit', {}).get('Amount', 0))
                
                try:
                    performance = budgets_client.describe_budget_performance(
                        AccountId=account_id,
                        BudgetName=budget_name
                    )
                    
                    history = performance.get('BudgetPerformanceHistory', {}).get('BudgetedAndActualAmountsList', [])
                    if history:
                        actual = float(history[-1].get('ActualAmount', {}).get('Amount', 0))
                        utilization = (actual / budget_limit * 100) if budget_limit > 0 else 0
                        
                        budget_status.append({
                            'name': budget_name,
                            'limit': budget_limit,
                            'actual': actual,
                            'utilization': utilization,
                            'threshold_met': utilization > 80
                        })
                except ClientError:
                    pass
        except ClientError:
            pass
        
        # Generate HTML report
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AWS Cost Analysis Report - 6 Month Trends</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #232f3e 0%, #37475a 100%); color: white; padding: 30px; text-align: center; border-radius: 10px; margin-bottom: 30px; }}
        .section {{ background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .section h2 {{ color: #232f3e; border-bottom: 2px solid #ff9900; padding-bottom: 10px; }}
        .trend-up {{ color: #dc3545; font-weight: bold; }}
        .trend-down {{ color: #28a745; font-weight: bold; }}
        .threshold-exceeded {{ background-color: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; }}
        .threshold-ok {{ background-color: #d4edda; color: #155724; padding: 10px; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #232f3e; color: white; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .cost-high {{ color: #dc3545; font-weight: bold; }}
        .cost-medium {{ color: #ffc107; font-weight: bold; }}
        .cost-low {{ color: #28a745; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>AWS Cost Analysis Report</h1>
        <p>6-Month Trend Analysis</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h2>Monthly Cost Trends (Last 6 Months)</h2>
        <table>
            <tr><th>Month</th><th>Total Cost</th><th>Top Services</th></tr>"""
        
        # Add monthly data
        for month in sorted(monthly_trends.keys()):
            total_cost = sum(monthly_trends[month].values())
            top_services = sorted(monthly_trends[month].items(), key=lambda x: x[1], reverse=True)[:3]
            top_services_str = ", ".join([f"{svc}: ${cost:.2f}" for svc, cost in top_services])
            
            cost_class = "cost-high" if total_cost > 1000 else "cost-medium" if total_cost > 100 else "cost-low"
            html_content += f"""
            <tr>
                <td>{month}</td>
                <td class="{cost_class}">${total_cost:.2f}</td>
                <td>{top_services_str}</td>
            </tr>"""
        
        html_content += """
        </table>
    </div>
    
    <div class="section">
        <h2>Service Cost Trends</h2>
        <table>
            <tr><th>Service</th><th>Current Month</th><th>Previous Month</th><th>Trend</th></tr>"""
        
        # Add trend analysis
        for service, data in sorted(trend_analysis.items(), key=lambda x: x[1]['current'], reverse=True)[:10]:
            trend_class = "trend-up" if data['trend'] > 0 else "trend-down"
            trend_symbol = "↑" if data['trend'] > 0 else "↓"
            
            html_content += f"""
            <tr>
                <td>{service}</td>
                <td>${data['current']:.2f}</td>
                <td>${data['previous']:.2f}</td>
                <td class="{trend_class}">{trend_symbol} {abs(data['trend']):.1f}%</td>
            </tr>"""
        
        html_content += """
        </table>
    </div>
    
    <div class="section">
        <h2>Budget Status & Thresholds</h2>"""
        
        if budget_status:
            html_content += """
            <table>
                <tr><th>Budget Name</th><th>Limit</th><th>Actual Spend</th><th>Utilization</th><th>Status</th></tr>"""
            
            for budget in budget_status:
                status_class = "threshold-exceeded" if budget['threshold_met'] else "threshold-ok"
                status_text = "THRESHOLD EXCEEDED" if budget['threshold_met'] else "Within Limits"
                
                html_content += f"""
                <tr>
                    <td>{budget['name']}</td>
                    <td>${budget['limit']:.2f}</td>
                    <td>${budget['actual']:.2f}</td>
                    <td>{budget['utilization']:.1f}%</td>
                    <td class="{status_class}">{status_text}</td>
                </tr>"""
            
            html_content += "</table>"
        else:
            html_content += "<p>No budgets configured. Consider setting up AWS budgets for cost monitoring.</p>"
        
        html_content += """
    </div>
    
    <div class="section">
        <h2>Cost Optimization Recommendations</h2>
        <ul>
            <li>Review services with upward trends for optimization opportunities</li>
            <li>Consider Reserved Instances for consistent workloads</li>
            <li>Set up budget alerts if not already configured</li>
            <li>Monitor daily spending patterns for anomalies</li>
            <li>Review and terminate unused resources regularly</li>
        </ul>
    </div>
</body>
</html>"""
        
        # Save report
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return output_path
        
    except Exception as e:
        return None