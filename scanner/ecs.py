"""
ECS Scanner Module - Detects security issues with Amazon ECS clusters and services
"""
import boto3
from botocore.exceptions import ClientError

def scan_ecs(region=None):
    """
    Scan Amazon ECS clusters and services for security issues
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    try:
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        for current_region in regions:
            ecs_client = boto3.client('ecs', region_name=current_region)
            
            try:
                # List ECS clusters
                clusters = ecs_client.list_clusters()
                
                for cluster_arn in clusters.get('clusterArns', []):
                    cluster_name = cluster_arn.split('/')[-1]
                    
                    try:
                        # Get cluster details
                        cluster_details = ecs_client.describe_clusters(clusters=[cluster_arn])
                        cluster = cluster_details['clusters'][0]
                        
                        # Check container insights
                        settings = cluster.get('settings', [])
                        container_insights_enabled = any(
                            setting.get('name') == 'containerInsights' and setting.get('value') == 'enabled'
                            for setting in settings
                        )
                        
                        if not container_insights_enabled:
                            findings.append({
                                'ResourceType': 'ECS Cluster',
                                'ResourceId': cluster_name,
                                'ResourceName': cluster_name,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': 'ECS cluster does not have Container Insights enabled',
                                'Recommendation': 'Enable Container Insights for monitoring and observability'
                            })
                        
                        # List services in cluster
                        services = ecs_client.list_services(cluster=cluster_arn)
                        
                        for service_arn in services.get('serviceArns', []):
                            service_name = service_arn.split('/')[-1]
                            
                            try:
                                # Get service details
                                service_details = ecs_client.describe_services(
                                    cluster=cluster_arn,
                                    services=[service_arn]
                                )
                                service = service_details['services'][0]
                                
                                # Check if service is public
                                network_config = service.get('networkConfiguration', {}).get('awsvpcConfiguration', {})
                                if network_config.get('assignPublicIp') == 'ENABLED':
                                    findings.append({
                                        'ResourceType': 'ECS Service',
                                        'ResourceId': f"{cluster_name}/{service_name}",
                                        'ResourceName': f"{cluster_name} - {service_name}",
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': 'ECS service has public IP assignment enabled',
                                        'Recommendation': 'Use private subnets and NAT Gateway for outbound connectivity'
                                    })
                                
                                # Check task definition
                                task_def_arn = service.get('taskDefinition')
                                if task_def_arn:
                                    try:
                                        task_def = ecs_client.describe_task_definition(taskDefinition=task_def_arn)
                                        task_definition = task_def['taskDefinition']
                                        
                                        # Check for privileged containers
                                        for container in task_definition.get('containerDefinitions', []):
                                            if container.get('privileged'):
                                                findings.append({
                                                    'ResourceType': 'ECS Task Definition',
                                                    'ResourceId': task_def_arn.split('/')[-1],
                                                    'ResourceName': f"{service_name} - {container.get('name')}",
                                                    'Region': current_region,
                                                    'Risk': 'HIGH',
                                                    'Issue': 'ECS container runs in privileged mode',
                                                    'Recommendation': 'Remove privileged mode unless absolutely necessary'
                                                })
                                            
                                            # Check for root user
                                            if container.get('user') == 'root' or not container.get('user'):
                                                findings.append({
                                                    'ResourceType': 'ECS Task Definition',
                                                    'ResourceId': task_def_arn.split('/')[-1],
                                                    'ResourceName': f"{service_name} - {container.get('name')}",
                                                    'Region': current_region,
                                                    'Risk': 'MEDIUM',
                                                    'Issue': 'ECS container runs as root user',
                                                    'Recommendation': 'Use non-root user for container execution'
                                                })
                                            
                                            # Check for secrets in environment variables
                                            env_vars = container.get('environment', [])
                                            for env_var in env_vars:
                                                var_name = env_var.get('name', '').lower()
                                                var_value = env_var.get('value', '')
                                                if any(keyword in var_name for keyword in ['password', 'secret', 'key', 'token']) and len(var_value) > 10:
                                                    findings.append({
                                                        'ResourceType': 'ECS Task Definition',
                                                        'ResourceId': task_def_arn.split('/')[-1],
                                                        'ResourceName': f"{service_name} - {container.get('name')}",
                                                        'Region': current_region,
                                                        'Risk': 'HIGH',
                                                        'Issue': f'ECS container has potential secret in environment variable: {var_name}',
                                                        'Recommendation': 'Use AWS Secrets Manager or Parameter Store for sensitive values'
                                                    })
                                            
                                            # Check logging configuration
                                            log_config = container.get('logConfiguration', {})
                                            if not log_config.get('logDriver'):
                                                findings.append({
                                                    'ResourceType': 'ECS Task Definition',
                                                    'ResourceId': task_def_arn.split('/')[-1],
                                                    'ResourceName': f"{service_name} - {container.get('name')}",
                                                    'Region': current_region,
                                                    'Risk': 'LOW',
                                                    'Issue': 'ECS container does not have logging configured',
                                                    'Recommendation': 'Configure CloudWatch Logs or other log drivers'
                                                })
                                        
                                        # Check task role
                                        if not task_definition.get('taskRoleArn'):
                                            findings.append({
                                                'ResourceType': 'ECS Task Definition',
                                                'ResourceId': task_def_arn.split('/')[-1],
                                                'ResourceName': service_name,
                                                'Region': current_region,
                                                'Risk': 'MEDIUM',
                                                'Issue': 'ECS task does not have IAM task role',
                                                'Recommendation': 'Assign IAM task role for AWS service access'
                                            })
                                            
                                    except ClientError:
                                        pass
                                        
                            except ClientError:
                                pass
                                
                    except ClientError:
                        pass
                        
            except ClientError:
                pass
                
    except Exception:
        pass
    
    return findings