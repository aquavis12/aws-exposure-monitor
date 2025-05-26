"""
AWS Cost Explorer Scanner Module - Analyzes AWS costs and provides optimization recommendations
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta, date
import calendar

def scan_cost_explorer():
    """
    Scan AWS Cost Explorer for cost insights and optimization opportunities
    
    Returns:
        list: List of dictionaries containing cost findings
    """
    findings = []
    
    print("Scanning AWS Cost Explorer for cost insights...")
    
    try:
        ce_client = boto3.client('ce')
        
        # Get current date and first day of current month
        today = datetime.now().date()
        first_day_current_month = date(today.year, today.month, 1)
        
        # Get first day of previous month
        if today.month == 1:
            first_day_previous_month = date(today.year - 1, 12, 1)
        else:
            first_day_previous_month = date(today.year, today.month - 1, 1)
        
        # Get last day of previous month
        last_day_previous_month = first_day_current_month - timedelta(days=1)
        
        # Format dates for Cost Explorer
        start_date = first_day_previous_month.strftime('%Y-%m-%d')
        end_date = today.strftime('%Y-%m-%d')
        
        # Get cost and usage for current month
        print("  Getting cost and usage data...")
        try:
            # Add error handling for Cost Explorer API
            try:
                response = ce_client.get_cost_and_usage(
                    TimePeriod={
                        'Start': start_date,
                        'End': end_date
                    },
                    Granularity='MONTHLY',
                    Metrics=['UnblendedCost'],
                    GroupBy=[
                        {
                            'Type': 'DIMENSION',
                            'Key': 'SERVICE'
                        }
                    ]
                )
            except ClientError as e:
                if e.response['Error']['Code'] == 'DataUnavailableException':
                    print("  Cost data is not available for the specified time period")
                    findings.append({
                        'ResourceType': 'Cost Explorer',
                        'ResourceId': 'DataUnavailable',
                        'ResourceName': 'Cost Explorer Data',
                        'Region': 'global',
                        'Risk': 'LOW',
                        'Issue': 'Cost data is not available for the specified time period',
                        'Recommendation': 'Wait for AWS to process your cost data or check your account setup'
                    })
                    return findings
                else:
                    raise
            
            # Process cost data
            if 'ResultsByTime' in response:
                for result in response['ResultsByTime']:
                    time_period = result['TimePeriod']
                    period_start = time_period['Start']
                    period_end = time_period['End']
                    
                    # Get top 5 services by cost
                    services = result['Groups']
                    # Safely extract cost amount for sorting
                    def get_cost_amount(service):
                        try:
                            return float(service['Metrics']['UnblendedCost']['Amount'])
                        except (KeyError, ValueError, TypeError):
                            return 0
                    
                    services.sort(key=get_cost_amount, reverse=True)
                    top_services = services[:5]
                    
                    for service in top_services:
                        service_name = service['Keys'][0]
                        try:
                            cost = float(service['Metrics']['UnblendedCost']['Amount'])
                        except (KeyError, ValueError, TypeError):
                            cost = 0
                        unit = service['Metrics']['UnblendedCost']['Unit']
                        
                        if cost > 100:  # Only report significant costs
                            findings.append({
                                'ResourceType': 'Cost Explorer',
                                'ResourceId': service_name,
                                'ResourceName': f"{service_name} ({period_start} to {period_end})",
                                'Region': 'global',
                                'Risk': 'LOW',
                                'Issue': f'High cost service: {service_name} costs {cost:.2f} {unit}',
                                'Recommendation': 'Review usage patterns and consider cost optimization strategies for this service'
                            })
                            print(f"    [!] FINDING: High cost service: {service_name} costs {cost:.2f} {unit}")
            
            # Get cost anomalies
            try:
                anomaly_response = ce_client.get_anomalies(
                    DateInterval={
                        'StartDate': start_date,
                        'EndDate': end_date
                    }
                )
                
                if 'Anomalies' in anomaly_response and anomaly_response['Anomalies']:
                    for anomaly in anomaly_response['Anomalies']:
                        impact_value = anomaly.get('Impact', 0)
                        if isinstance(impact_value, dict):
                            impact = 0  # Default if we can't extract a numeric value
                        else:
                            impact = float(impact_value)
                        root_causes = anomaly.get('RootCauses', [])
                        service = root_causes[0].get('Service', 'Unknown') if root_causes else 'Unknown'
                        
                        findings.append({
                            'ResourceType': 'Cost Anomaly',
                            'ResourceId': service,
                            'ResourceName': service,
                            'Region': 'global',
                            'Risk': 'MEDIUM',
                            'Issue': f'Cost anomaly detected for {service} with impact of {impact:.2f}',
                            'Recommendation': 'Investigate unusual spending pattern and take corrective action'
                        })
                        print(f"    [!] FINDING: Cost anomaly detected for {service} with impact of {impact:.2f}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDeniedException':
                    print("    Access denied for Cost Anomaly Detection")
                else:
                    print(f"    Error checking cost anomalies: {e}")
            
            # Get reservation coverage
            try:
                coverage_response = ce_client.get_reservation_coverage(
                    TimePeriod={
                        'Start': start_date,
                        'End': end_date
                    },
                    Granularity='MONTHLY'
                )
                
                if 'CoveragesByTime' in coverage_response:
                    for coverage in coverage_response['CoveragesByTime']:
                        coverage_hours = coverage.get('Total', {}).get('CoverageHours', {})
                        if isinstance(coverage_hours, dict):
                            total_coverage = float(coverage_hours.get('CoverageHoursPercentage', 0))
                        else:
                            total_coverage = float(coverage_hours or 0)
                        
                        if total_coverage < 70:  # Less than 70% coverage
                            findings.append({
                                'ResourceType': 'Reservation Coverage',
                                'ResourceId': 'EC2 and RDS',
                                'ResourceName': 'EC2 and RDS Instances',
                                'Region': 'global',
                                'Risk': 'MEDIUM',
                                'Issue': f'Low reservation coverage: {total_coverage:.2f}% of eligible instances are covered',
                                'Recommendation': 'Consider purchasing Reserved Instances or Savings Plans for frequently used instances'
                            })
                            print(f"    [!] FINDING: Low reservation coverage: {total_coverage:.2f}% of eligible instances are covered")
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDeniedException':
                    print("    Access denied for Reservation Coverage")
                else:
                    print(f"    Error checking reservation coverage: {e}")
            
            # Get Savings Plans utilization
            try:
                sp_utilization_response = ce_client.get_savings_plans_utilization(
                    TimePeriod={
                        'Start': start_date,
                        'End': end_date
                    }
                )
                
                if 'SavingsPlansUtilizationsByTime' in sp_utilization_response:
                    for utilization in sp_utilization_response['SavingsPlansUtilizationsByTime']:
                        utilization_data = utilization.get('Utilization', {})
                        if isinstance(utilization_data, dict):
                            total_utilization = float(utilization_data.get('UtilizationPercentage', 0))
                        else:
                            total_utilization = float(utilization_data or 0)
                        
                        if total_utilization < 80:  # Less than 80% utilization
                            findings.append({
                                'ResourceType': 'Savings Plans',
                                'ResourceId': 'Savings Plans',
                                'ResourceName': 'Savings Plans',
                                'Region': 'global',
                                'Risk': 'MEDIUM',
                                'Issue': f'Low Savings Plans utilization: {total_utilization:.2f}%',
                                'Recommendation': 'Review your Savings Plans portfolio and adjust your usage to maximize utilization'
                            })
                            print(f"    [!] FINDING: Low Savings Plans utilization: {total_utilization:.2f}%")
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDeniedException':
                    print("    Access denied for Savings Plans Utilization")
                else:
                    print(f"    Error checking Savings Plans utilization: {e}")
        
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                print("  Access denied for Cost Explorer. Make sure you have the required permissions.")
                findings.append({
                    'ResourceType': 'Cost Explorer',
                    'ResourceId': 'Permissions',
                    'ResourceName': 'Cost Explorer Permissions',
                    'Region': 'global',
                    'Risk': 'LOW',
                    'Issue': 'No access to AWS Cost Explorer',
                    'Recommendation': 'Grant ce:* permissions to enable cost analysis and optimization recommendations'
                })
            else:
                print(f"  Error accessing Cost Explorer: {e}")
    
    except Exception as e:
        print(f"Error scanning Cost Explorer: {e}")
    
    return findings

def scan_budgets():
    """
    Scan AWS Budgets for missing budgets and alerts
    
    Returns:
        list: List of dictionaries containing budget findings
    """
    findings = []
    
    print("Scanning AWS Budgets...")
    
    try:
        budgets_client = boto3.client('budgets')
        
        # Get all budgets
        try:
            response = budgets_client.describe_budgets(
                AccountId=boto3.client('sts').get_caller_identity()['Account']
            )
            
            budgets = response.get('Budgets', [])
            
            if not budgets:
                findings.append({
                    'ResourceType': 'AWS Budgets',
                    'ResourceId': 'No Budgets',
                    'ResourceName': 'AWS Account',
                    'Region': 'global',
                    'Risk': 'MEDIUM',
                    'Issue': 'No AWS Budgets configured for cost monitoring',
                    'Recommendation': 'Set up AWS Budgets to monitor and control your AWS spending'
                })
                print("    [!] FINDING: No AWS Budgets configured for cost monitoring")
            else:
                print(f"  Found {len(budgets)} budgets")
                
                # Check each budget for notifications
                for budget in budgets:
                    budget_name = budget.get('BudgetName', 'Unknown')
                    
                    # Check if budget has notifications
                    try:
                        notifications = budgets_client.describe_notifications_for_budget(
                            AccountId=boto3.client('sts').get_caller_identity()['Account'],
                            BudgetName=budget_name
                        ).get('Notifications', [])
                        
                        if not notifications:
                            findings.append({
                                'ResourceType': 'AWS Budget',
                                'ResourceId': budget_name,
                                'ResourceName': budget_name,
                                'Region': 'global',
                                'Risk': 'LOW',
                                'Issue': f'Budget "{budget_name}" has no notifications configured',
                                'Recommendation': 'Configure notifications for your budget to be alerted when thresholds are exceeded'
                            })
                            print(f"    [!] FINDING: Budget {budget_name} has no notifications configured")
                    except ClientError as e:
                        print(f"    Error checking notifications for budget {budget_name}: {e}")
        
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                print("  Access denied for AWS Budgets. Make sure you have the required permissions.")
                findings.append({
                    'ResourceType': 'AWS Budgets',
                    'ResourceId': 'Permissions',
                    'ResourceName': 'AWS Budgets Permissions',
                    'Region': 'global',
                    'Risk': 'LOW',
                    'Issue': 'No access to AWS Budgets',
                    'Recommendation': 'Grant budgets:* permissions to enable budget analysis and recommendations'
                })
            else:
                print(f"  Error accessing AWS Budgets: {e}")
    
    except Exception as e:
        print(f"Error scanning AWS Budgets: {e}")
    
    return findings