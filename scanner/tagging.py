"""
Tagging Scanner Module - Checks for proper resource tagging compliance
"""
import boto3
from botocore.exceptions import ClientError

def scan_resource_tagging(region=None):
    """
    Scan AWS resources for proper tagging compliance
    
    Returns:
        list: List of dictionaries containing tagging issues
    """
    findings = []
    
    # Required tags for compliance
    required_tags = ['Environment', 'ApplicationName', 'Owner', 'CostCenter']
    
    try:
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        for current_region in regions:
            # Check EC2 instances
            try:
                ec2 = boto3.client('ec2', region_name=current_region)
                instances = ec2.describe_instances()
                
                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                        
                        missing_tags = [tag for tag in required_tags if tag not in tags]
                        if missing_tags:
                            findings.append({
                                'ResourceType': 'EC2 Instance',
                                'ResourceId': instance_id,
                                'ResourceName': tags.get('Name', instance_id),
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': f'Missing required tags: {", ".join(missing_tags)}',
                                'Recommendation': 'Add required tags for compliance and cost tracking'
                            })
            except ClientError:
                pass
            
            # Check S3 buckets
            try:
                s3 = boto3.client('s3')
                buckets = s3.list_buckets()
                
                for bucket in buckets['Buckets']:
                    bucket_name = bucket['Name']
                    try:
                        # Get bucket location
                        location = s3.get_bucket_location(Bucket=bucket_name)
                        bucket_region = location.get('LocationConstraint') or 'us-east-1'
                        
                        if bucket_region == current_region or (current_region == 'us-east-1' and not bucket_region):
                            try:
                                tags_response = s3.get_bucket_tagging(Bucket=bucket_name)
                                tags = {tag['Key']: tag['Value'] for tag in tags_response.get('TagSet', [])}
                            except ClientError:
                                tags = {}
                            
                            missing_tags = [tag for tag in required_tags if tag not in tags]
                            if missing_tags:
                                findings.append({
                                    'ResourceType': 'S3 Bucket',
                                    'ResourceId': bucket_name,
                                    'ResourceName': bucket_name,
                                    'Region': bucket_region,
                                    'Risk': 'LOW',
                                    'Issue': f'Missing required tags: {", ".join(missing_tags)}',
                                    'Recommendation': 'Add required tags for compliance and cost tracking'
                                })
                    except ClientError:
                        pass
            except ClientError:
                pass
            
            # Check RDS instances
            try:
                rds = boto3.client('rds', region_name=current_region)
                instances = rds.describe_db_instances()
                
                for instance in instances['DBInstances']:
                    instance_id = instance['DBInstanceIdentifier']
                    instance_arn = instance['DBInstanceArn']
                    
                    try:
                        tags_response = rds.list_tags_for_resource(ResourceName=instance_arn)
                        tags = {tag['Key']: tag['Value'] for tag in tags_response.get('TagList', [])}
                        
                        missing_tags = [tag for tag in required_tags if tag not in tags]
                        if missing_tags:
                            findings.append({
                                'ResourceType': 'RDS Instance',
                                'ResourceId': instance_id,
                                'ResourceName': instance_id,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': f'Missing required tags: {", ".join(missing_tags)}',
                                'Recommendation': 'Add required tags for compliance and cost tracking'
                            })
                    except ClientError:
                        pass
            except ClientError:
                pass
                
    except Exception:
        pass
    
    return findings