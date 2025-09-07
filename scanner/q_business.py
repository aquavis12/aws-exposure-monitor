"""
Q Business Scanner Module - Detects security issues with Amazon Q Business
"""
import boto3
from botocore.exceptions import ClientError

def scan_q_business(region=None):
    """
    Scan Amazon Q Business applications for security issues
    
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
            try:
                qbusiness_client = boto3.client('qbusiness', region_name=current_region)
                
                # List Q Business applications
                applications = qbusiness_client.list_applications()
                
                for app in applications.get('applications', []):
                    app_id = app.get('applicationId')
                    app_name = app.get('displayName')
                    
                    # Check application encryption
                    try:
                        app_details = qbusiness_client.get_application(applicationId=app_id)
                        encryption_config = app_details.get('encryptionConfiguration', {})
                        
                        if not encryption_config.get('kmsKeyId'):
                            findings.append({
                                'ResourceType': 'Q Business Application',
                                'ResourceId': app_id,
                                'ResourceName': app_name,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'Q Business application not encrypted with customer-managed KMS key',
                                'Recommendation': 'Enable encryption with customer-managed KMS key'
                            })
                    except ClientError:
                        pass
                    
                    # Check data sources
                    try:
                        data_sources = qbusiness_client.list_data_sources(applicationId=app_id)
                        for ds in data_sources.get('dataSources', []):
                            ds_id = ds.get('dataSourceId')
                            ds_name = ds.get('displayName')
                            
                            # Check if data source has proper access controls
                            try:
                                ds_details = qbusiness_client.get_data_source(
                                    applicationId=app_id,
                                    dataSourceId=ds_id
                                )
                                
                                # Check for overly broad access
                                if not ds_details.get('documentEnrichmentConfiguration'):
                                    findings.append({
                                        'ResourceType': 'Q Business Data Source',
                                        'ResourceId': f"{app_id}/{ds_id}",
                                        'ResourceName': f"{app_name} - {ds_name}",
                                        'Region': current_region,
                                        'Risk': 'LOW',
                                        'Issue': 'Q Business data source lacks document enrichment configuration',
                                        'Recommendation': 'Configure document enrichment for better content filtering'
                                    })
                            except ClientError:
                                pass
                    except ClientError:
                        pass
                        
            except ClientError:
                # Q Business might not be available in all regions
                pass
                
    except Exception:
        pass
    
    return findings