"""
API Gateway Scanner Module - Detects publicly accessible API Gateway endpoints without authorization
"""
import boto3
from botocore.exceptions import ClientError


def scan_api_gateways():
    """
    Scan API Gateway endpoints for public access without authorization
    Returns a list of dictionaries containing vulnerable resources
    """
    findings = []
    
    try:
        # Get all regions
        ec2_client = boto3.client('ec2')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        for region in regions:
            # Check REST APIs
            try:
                apigw_client = boto3.client('apigateway', region_name=region)
                
                # Get all REST APIs
                rest_apis = apigw_client.get_rest_apis()
                
                for api in rest_apis.get('items', []):
                    api_id = api.get('id')
                    api_name = api.get('name')
                    
                    # Get resources for this API
                    resources = apigw_client.get_resources(restApiId=api_id)
                    
                    for resource in resources.get('items', []):
                        resource_id = resource.get('id')
                        resource_path = resource.get('path', '/')
                        
                        # Check methods for this resource
                        for method_name, method in resource.get('resourceMethods', {}).items():
                            if method_name != 'OPTIONS':  # Skip OPTIONS methods
                                # Get method details
                                method_details = apigw_client.get_method(
                                    restApiId=api_id,
                                    resourceId=resource_id,
                                    httpMethod=method_name
                                )
                                
                                # Check if method requires authorization
                                auth_type = method_details.get('authorizationType', '')
                                api_key_required = method_details.get('apiKeyRequired', False)
                                
                                if auth_type == 'NONE' and not api_key_required:
                                    findings.append({
                                        'ResourceType': 'API Gateway REST API',
                                        'ResourceId': f"{api_id}/{resource_id}",
                                        'ResourceName': f"{api_name} - {resource_path} - {method_name}",
                                        'Region': region,
                                        'Risk': 'HIGH',
                                        'Issue': f'API Gateway endpoint {resource_path} ({method_name}) has no authorization',
                                        'Recommendation': 'Add authorization (IAM, Cognito, Lambda authorizer) or API key requirement'
                                    })
            
            except ClientError as e:
                print(f"Error scanning API Gateway REST APIs in {region}: {e}")
            
            # Check HTTP APIs (API Gateway v2)
            try:
                apigwv2_client = boto3.client('apigatewayv2', region_name=region)
                
                # Get all HTTP APIs
                http_apis = apigwv2_client.get_apis()
                
                for api in http_apis.get('Items', []):
                    api_id = api.get('ApiId')
                    api_name = api.get('Name')
                    
                    # Get routes for this API
                    routes = apigwv2_client.get_routes(ApiId=api_id)
                    
                    for route in routes.get('Items', []):
                        route_id = route.get('RouteId')
                        route_key = route.get('RouteKey')
                        
                        # Check if route has authorization
                        auth_type = route.get('AuthorizationType', 'NONE')
                        api_key_required = route.get('ApiKeyRequired', False)
                        
                        if auth_type == 'NONE' and not api_key_required:
                            findings.append({
                                'ResourceType': 'API Gateway HTTP API',
                                'ResourceId': f"{api_id}/{route_id}",
                                'ResourceName': f"{api_name} - {route_key}",
                                'Region': region,
                                'Risk': 'HIGH',
                                'Issue': f'API Gateway HTTP route {route_key} has no authorization',
                                'Recommendation': 'Add authorization (JWT, IAM, Lambda authorizer) or API key requirement'
                            })
            
            except ClientError as e:
                print(f"Error scanning API Gateway HTTP APIs in {region}: {e}")
    
    except Exception as e:
        print(f"Error scanning API Gateway endpoints: {e}")
    
    return findings