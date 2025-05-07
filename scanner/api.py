"""
API Gateway Scanner Module - Detects publicly accessible API Gateway endpoints without authorization
"""
import boto3
from botocore.exceptions import ClientError


def scan_api_gateways(region=None):
    """
    Scan API Gateway endpoints for public access without authorization
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting API Gateway scan...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
            print(f"Scanning region: {region}")
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
            print(f"Scanning {len(regions)} regions")
        
        region_count = 0
        total_apis_found = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            # Check REST APIs
            try:
                apigw_client = boto3.client('apigateway', region_name=current_region)
                
                # Get all REST APIs
                rest_apis = apigw_client.get_rest_apis()
                apis = rest_apis.get('items', [])
                
                if apis:
                    total_apis_found += len(apis)
                    print(f"  Found {len(apis)} REST APIs in {current_region}")
                    
                    for api in apis:
                        api_id = api.get('id')
                        api_name = api.get('name')
                        
                        print(f"  Scanning API: {api_name} ({api_id})")
                        
                        # Get resources for this API
                        resources = apigw_client.get_resources(restApiId=api_id)
                        
                        for resource in resources.get('items', []):
                            resource_id = resource.get('id')
                            resource_path = resource.get('path', '/')
                            
                            # Check methods for this resource
                            for method_name, method in resource.get('resourceMethods', {}).items():
                                if method_name != 'OPTIONS':  # Skip OPTIONS methods
                                    # Get method details
                                    try:
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
                                                'Region': current_region,
                                                'Risk': 'HIGH',
                                                'Issue': f'API Gateway endpoint {resource_path} ({method_name}) has no authorization',
                                                'Recommendation': 'Add authorization (IAM, Cognito, Lambda authorizer) or API key requirement'
                                            })
                                            print(f"    [!] FINDING: API {api_name} endpoint {resource_path} ({method_name}) has no authorization - HIGH risk")
                                    except ClientError as e:
                                        print(f"    Error checking method {method_name} for resource {resource_path}: {e}")
            
            except ClientError as e:
                print(f"  Error scanning API Gateway REST APIs in {current_region}: {e}")
            
            # Check HTTP APIs (API Gateway v2)
            try:
                apigwv2_client = boto3.client('apigatewayv2', region_name=current_region)
                
                # Get all HTTP APIs
                http_apis = apigwv2_client.get_apis()
                apis_v2 = http_apis.get('Items', [])
                
                if apis_v2:
                    total_apis_found += len(apis_v2)
                    print(f"  Found {len(apis_v2)} HTTP APIs in {current_region}")
                    
                    for api in apis_v2:
                        api_id = api.get('ApiId')
                        api_name = api.get('Name')
                        
                        print(f"  Scanning HTTP API: {api_name} ({api_id})")
                        
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
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': f'API Gateway HTTP route {route_key} has no authorization',
                                    'Recommendation': 'Add authorization (JWT, IAM, Lambda authorizer) or API key requirement'
                                })
                                print(f"    [!] FINDING: HTTP API {api_name} route {route_key} has no authorization - HIGH risk")
            
            except ClientError as e:
                print(f"  Error scanning API Gateway HTTP APIs in {current_region}: {e}")
    
    except Exception as e:
        print(f"Error scanning API Gateway endpoints: {e}")
    
    if total_apis_found == 0:
        print("No API Gateway APIs found.")
    else:
        print(f"API Gateway scan complete. Scanned {total_apis_found} APIs.")
    
    if findings:
        print(f"Found {len(findings)} API Gateway issues.")
    else:
        print("No API Gateway issues found.")
    
    return findings