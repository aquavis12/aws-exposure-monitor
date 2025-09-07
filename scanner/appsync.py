"""
AppSync Scanner Module - Detects security issues with AWS AppSync GraphQL APIs
"""
import boto3
from botocore.exceptions import ClientError

def scan_appsync(region=None):
    """
    Scan AWS AppSync GraphQL APIs for security issues
    
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
            appsync_client = boto3.client('appsync', region_name=current_region)
            
            try:
                # List GraphQL APIs
                apis = appsync_client.list_graphql_apis()
                
                for api in apis.get('graphqlApis', []):
                    api_id = api.get('apiId')
                    api_name = api.get('name')
                    api_arn = api.get('arn')
                    auth_type = api.get('authenticationType')
                    
                    # Check authentication type
                    if auth_type == 'API_KEY':
                        findings.append({
                            'ResourceType': 'AppSync API',
                            'ResourceId': api_id,
                            'ResourceName': api_name,
                            'Region': current_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'AppSync API uses API key authentication',
                            'Recommendation': 'Consider using IAM, Cognito, or OIDC for better security'
                        })
                    
                    # Check for logging
                    log_config = api.get('logConfig', {})
                    if not log_config.get('cloudWatchLogsRoleArn'):
                        findings.append({
                            'ResourceType': 'AppSync API',
                            'ResourceId': api_id,
                            'ResourceName': api_name,
                            'Region': current_region,
                            'Risk': 'LOW',
                            'Issue': 'AppSync API does not have logging enabled',
                            'Recommendation': 'Enable CloudWatch logging for monitoring and debugging'
                        })
                    
                    # Check data sources for security issues
                    try:
                        data_sources = appsync_client.list_data_sources(apiId=api_id)
                        for ds in data_sources.get('dataSources', []):
                            ds_type = ds.get('type')
                            ds_name = ds.get('name')
                            
                            if ds_type == 'HTTP' and ds.get('httpConfig', {}).get('endpoint', '').startswith('http://'):
                                findings.append({
                                    'ResourceType': 'AppSync Data Source',
                                    'ResourceId': f"{api_id}/{ds_name}",
                                    'ResourceName': f"{api_name} - {ds_name}",
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': 'AppSync HTTP data source uses unencrypted connection',
                                    'Recommendation': 'Use HTTPS endpoints for data sources'
                                })
                    except ClientError:
                        pass
                        
            except ClientError:
                pass
                
    except Exception:
        pass
    
    return findings