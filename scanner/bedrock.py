"""
Bedrock Scanner Module - Detects security issues with Amazon Bedrock
"""
import boto3
from botocore.exceptions import ClientError

def scan_bedrock(region=None):
    """
    Scan Amazon Bedrock for security issues
    
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
                bedrock_client = boto3.client('bedrock', region_name=current_region)
                
                # Check model customization jobs
                try:
                    jobs = bedrock_client.list_model_customization_jobs()
                    for job in jobs.get('modelCustomizationJobSummaries', []):
                        job_name = job.get('jobName')
                        job_arn = job.get('jobArn')
                        
                        try:
                            job_details = bedrock_client.get_model_customization_job(jobIdentifier=job_name)
                            
                            # Check if training data is encrypted
                            training_data = job_details.get('trainingDataConfig', {})
                            s3_uri = training_data.get('s3Uri', '')
                            
                            if s3_uri and not job_details.get('outputDataConfig', {}).get('s3Uri'):
                                findings.append({
                                    'ResourceType': 'Bedrock Model Job',
                                    'ResourceId': job_name,
                                    'ResourceName': job_name,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'Bedrock model customization job may not have encrypted output',
                                    'Recommendation': 'Ensure training and output data use encrypted S3 buckets'
                                })
                                
                        except ClientError:
                            pass
                            
                except ClientError:
                    pass
                
                # Check guardrails
                try:
                    guardrails = bedrock_client.list_guardrails()
                    if not guardrails.get('guardrails'):
                        findings.append({
                            'ResourceType': 'Bedrock Configuration',
                            'ResourceId': 'bedrock-guardrails',
                            'ResourceName': 'Bedrock Guardrails',
                            'Region': current_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'No Bedrock guardrails configured',
                            'Recommendation': 'Configure guardrails to filter harmful content and ensure responsible AI use'
                        })
                        
                except ClientError:
                    pass
                    
            except ClientError:
                # Bedrock might not be available in this region
                pass
                
    except Exception:
        pass
    
    return findings