"""
SageMaker Scanner Module - Detects security issues with Amazon SageMaker
"""
import boto3
from botocore.exceptions import ClientError

def scan_sagemaker(region=None):
    """
    Scan Amazon SageMaker for security issues
    
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
            sagemaker_client = boto3.client('sagemaker', region_name=current_region)
            
            try:
                # Check notebook instances
                notebooks = sagemaker_client.list_notebook_instances()
                for notebook in notebooks.get('NotebookInstances', []):
                    notebook_name = notebook.get('NotebookInstanceName')
                    
                    try:
                        details = sagemaker_client.describe_notebook_instance(NotebookInstanceName=notebook_name)
                        
                        # Check if notebook has direct internet access
                        if details.get('DirectInternetAccess') == 'Enabled':
                            findings.append({
                                'ResourceType': 'SageMaker Notebook',
                                'ResourceId': notebook_name,
                                'ResourceName': notebook_name,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'SageMaker notebook has direct internet access enabled',
                                'Recommendation': 'Disable direct internet access and use VPC endpoints'
                            })
                        
                        # Check encryption
                        if not details.get('KmsKeyId'):
                            findings.append({
                                'ResourceType': 'SageMaker Notebook',
                                'ResourceId': notebook_name,
                                'ResourceName': notebook_name,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'SageMaker notebook storage is not encrypted with customer KMS key',
                                'Recommendation': 'Enable KMS encryption for notebook storage'
                            })
                            
                    except ClientError:
                        pass
                
                # Check endpoints
                endpoints = sagemaker_client.list_endpoints()
                for endpoint in endpoints.get('Endpoints', []):
                    endpoint_name = endpoint.get('EndpointName')
                    
                    try:
                        config_name = endpoint.get('EndpointConfigName')
                        if config_name:
                            config = sagemaker_client.describe_endpoint_config(EndpointConfigName=config_name)
                            
                            # Check if endpoint has data capture enabled
                            data_capture = config.get('DataCaptureConfig', {})
                            if not data_capture.get('EnableCapture'):
                                findings.append({
                                    'ResourceType': 'SageMaker Endpoint',
                                    'ResourceId': endpoint_name,
                                    'ResourceName': endpoint_name,
                                    'Region': current_region,
                                    'Risk': 'LOW',
                                    'Issue': 'SageMaker endpoint does not have data capture enabled',
                                    'Recommendation': 'Enable data capture for model monitoring and debugging'
                                })
                                
                    except ClientError:
                        pass
                        
            except ClientError:
                pass
                
    except Exception:
        pass
    
    return findings