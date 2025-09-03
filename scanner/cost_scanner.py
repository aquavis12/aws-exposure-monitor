"""
Cost Scanner Module - Analyzes AWS costs using Cost Explorer and Budgets APIs
"""
import boto3
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

def scan_cost_optimization(region=None):
    """
    Scan AWS costs for optimization opportunities
    
    Returns:
        list: List of cost-related findings
    """
    findings = []
    
    try:
        # Cost Explorer is only available in us-east-1
        ce_client = boto3.client('ce', region_name='us-east-1')
        budgets_client = boto3.client('budgets', region_name='us-east-1')
        
        # Get current and last month dates
        today = datetime.now().date()
        current_month_start = today.replace(day=1)
        last_month_end = current_month_start - timedelta(days=1)
        last_month_start = last_month_end.replace(day=1)
        
        # Get current month costs by service
        current_costs = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': current_month_start.strftime('%Y-%m-%d'),
                'End': today.strftime('%Y-%m-%d')
            },
            Granularity='MONTHLY',
            Metrics=['BlendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        )
        
        # Get last month costs for comparison
        last_month_costs = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': last_month_start.strftime('%Y-%m-%d'),
                'End': last_month_end.strftime('%Y-%m-%d')
            },
            Granularity='MONTHLY',
            Metrics=['BlendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        )
        
        # Analyze cost trends
        current_total = 0
        last_total = 0
        service_costs = {}
        
        for result in current_costs.get('ResultsByTime', []):
            for group in result.get('Groups', []):
                service = group['Keys'][0]
                cost = float(group['Metrics']['BlendedCost']['Amount'])
                current_total += cost
                service_costs[service] = {'current': cost, 'last': 0}
        
        for result in last_month_costs.get('ResultsByTime', []):
            for group in result.get('Groups', []):
                service = group['Keys'][0]
                cost = float(group['Metrics']['BlendedCost']['Amount'])
                last_total += cost
                if service in service_costs:
                    service_costs[service]['last'] = cost
                else:
                    service_costs[service] = {'current': 0, 'last': cost}
        
        # Check for significant cost increases
        for service, costs in service_costs.items():
            if costs['last'] > 0 and costs['current'] > costs['last'] * 1.5:
                increase_pct = ((costs['current'] - costs['last']) / costs['last']) * 100
                findings.append({
                    'ResourceType': 'Cost Analysis',
                    'ResourceId': f'cost-increase-{service}',
                    'ResourceName': f'{service} Cost Increase',
                    'Region': 'global',
                    'Risk': 'HIGH' if increase_pct > 100 else 'MEDIUM',
                    'Issue': f'{service} costs increased by {increase_pct:.1f}% (${costs["current"]:.2f} vs ${costs["last"]:.2f})',
                    'Recommendation': f'Review {service} usage and optimize resources'
                })
        
        # Get unused/underutilized resources from Cost Explorer
        try:
            unused_resources = ce_client.get_rightsizing_recommendation(
                Service='EC2-Instance'
            )
            
            for recommendation in unused_resources.get('RightsizingRecommendations', []):
                if recommendation.get('RightsizingType') == 'Terminate':
                    instance_id = recommendation.get('CurrentInstance', {}).get('ResourceId', 'Unknown')
                    monthly_cost = float(recommendation.get('CurrentInstance', {}).get('MonthlyCost', 0))
                    findings.append({
                        'ResourceType': 'EC2 Instance',
                        'ResourceId': instance_id,
                        'ResourceName': f'Unused EC2 Instance',
                        'Region': 'global',
                        'Risk': 'MEDIUM',
                        'Issue': f'EC2 instance appears unused, costing ${monthly_cost:.2f}/month',
                        'Recommendation': 'Consider terminating unused EC2 instances'
                    })
        except ClientError:
            pass
        
        # Get cost anomaly detection
        try:
            anomalies = ce_client.get_anomalies(
                DateInterval={
                    'StartDate': (today - timedelta(days=30)).strftime('%Y-%m-%d'),
                    'EndDate': today.strftime('%Y-%m-%d')
                }
            )
            
            for anomaly in anomalies.get('Anomalies', []):
                impact = float(anomaly.get('Impact', {}).get('MaxImpact', 0))
                if impact > 100:  # Only report significant anomalies
                    service = anomaly.get('DimensionKey', 'Unknown Service')
                    findings.append({
                        'ResourceType': 'Cost Anomaly',
                        'ResourceId': f'anomaly-{service}',
                        'ResourceName': f'Cost Anomaly: {service}',
                        'Region': 'global',
                        'Risk': 'HIGH' if impact > 500 else 'MEDIUM',
                        'Issue': f'Cost anomaly detected with ${impact:.2f} impact in {service}',
                        'Recommendation': f'Investigate unusual spending in {service}'
                    })
        except ClientError:
            pass
        
        # Get usage reports for top services
        try:
            usage_report = ce_client.get_usage_forecast(
                TimePeriod={
                    'Start': today.strftime('%Y-%m-%d'),
                    'End': (today + timedelta(days=30)).strftime('%Y-%m-%d')
                },
                Metric='USAGE_QUANTITY',
                Granularity='MONTHLY'
            )
            
            forecast_amount = float(usage_report.get('Total', {}).get('Amount', 0))
            if forecast_amount > current_total * 1.2:  # 20% increase forecast
                findings.append({
                    'ResourceType': 'Cost Forecast',
                    'ResourceId': 'usage-forecast',
                    'ResourceName': 'Usage Forecast Alert',
                    'Region': 'global',
                    'Risk': 'MEDIUM',
                    'Issue': f'Usage forecast shows potential 20%+ increase next month',
                    'Recommendation': 'Review planned resource usage and optimize before scaling'
                })
        except ClientError:
            pass
        
        # Check budgets
        try:
            budgets_response = budgets_client.describe_budgets(
                AccountId=boto3.client('sts').get_caller_identity()['Account']
            )
            
            if not budgets_response.get('Budgets'):
                findings.append({
                    'ResourceType': 'Budget Configuration',
                    'ResourceId': 'no-budgets',
                    'ResourceName': 'Missing Budgets',
                    'Region': 'global',
                    'Risk': 'MEDIUM',
                    'Issue': 'No AWS budgets configured for cost monitoring',
                    'Recommendation': 'Set up AWS budgets to monitor and control costs'
                })
            
            for budget in budgets_response.get('Budgets', []):
                budget_name = budget.get('BudgetName')
                budget_limit = float(budget.get('BudgetLimit', {}).get('Amount', 0))
                
                # Get budget performance
                try:
                    performance = budgets_client.describe_budget_performance(
                        AccountId=boto3.client('sts').get_caller_identity()['Account'],
                        BudgetName=budget_name
                    )
                    
                    actual_spend = float(performance.get('BudgetPerformanceHistory', {}).get('BudgetedAndActualAmountsList', [{}])[-1].get('ActualAmount', {}).get('Amount', 0))
                    
                    if actual_spend > budget_limit * 0.8:
                        findings.append({
                            'ResourceType': 'Budget Alert',
                            'ResourceId': budget_name,
                            'ResourceName': f'Budget: {budget_name}',
                            'Region': 'global',
                            'Risk': 'HIGH' if actual_spend > budget_limit else 'MEDIUM',
                            'Issue': f'Budget {budget_name} at {(actual_spend/budget_limit)*100:.1f}% of limit (${actual_spend:.2f}/${budget_limit:.2f})',
                            'Recommendation': 'Review spending and consider cost optimization measures'
                        })
                except ClientError:
                    pass
                    
        except ClientError:
            pass
        
        # Get Reserved Instance recommendations
        try:
            ri_recommendations = ce_client.get_reservation_purchase_recommendation(
                Service='EC2-Instance'
            )
            
            for recommendation in ri_recommendations.get('Recommendations', []):
                details = recommendation.get('RecommendationDetails', {})
                monthly_savings = float(details.get('EstimatedMonthlySavingsAmount', 0))
                
                if monthly_savings > 50:  # Only report significant savings
                    findings.append({
                        'ResourceType': 'Reserved Instance Opportunity',
                        'ResourceId': 'ri-recommendation',
                        'ResourceName': 'Reserved Instance Savings',
                        'Region': 'global',
                        'Risk': 'LOW',
                        'Issue': f'Potential savings of ${monthly_savings:.2f}/month with Reserved Instances',
                        'Recommendation': 'Consider purchasing Reserved Instances for consistent workloads'
                    })
        except ClientError:
            pass
            
    except Exception as e:
        pass
    
    return findings