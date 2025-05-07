"""
S3 Scanner Module - Detects publicly accessible S3 buckets
"""
import boto3
from botocore.exceptions import ClientError


def scan_s3_buckets():
    """
    Scan S3 buckets for public access settings
    Returns a list of dictionaries containing vulnerable resources
    """
    findings = []
    s3_client = boto3.client('s3')
    
    try:
        # Get all buckets
        response = s3_client.list_buckets()
        buckets = response['Buckets']
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            # Check bucket public access block settings
            try:
                public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                block_config = public_access_block['PublicAccessBlockConfiguration']
                
                # If any of these are False, the bucket might be publicly accessible
                if not all([
                    block_config.get('BlockPublicAcls', False),
                    block_config.get('IgnorePublicAcls', False),
                    block_config.get('BlockPublicPolicy', False),
                    block_config.get('RestrictPublicBuckets', False)
                ]):
                    findings.append({
                        'ResourceType': 'S3 Bucket',
                        'ResourceId': bucket_name,
                        'Region': 'global',
                        'Risk': 'HIGH',
                        'Issue': 'S3 bucket has public access block disabled',
                        'Recommendation': 'Enable all public access block settings for this bucket'
                    })
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    # No public access block configuration means the bucket could be public
                    findings.append({
                        'ResourceType': 'S3 Bucket',
                        'ResourceId': bucket_name,
                        'Region': 'global',
                        'Risk': 'HIGH',
                        'Issue': 'S3 bucket has no public access block configuration',
                        'Recommendation': 'Configure public access block for this bucket'
                    })
                else:
                    print(f"Error checking public access block for bucket {bucket_name}: {e}")
            
            # Check bucket policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                # Here you would analyze the policy for public access
                # This is a simplified check - a real implementation would parse the policy JSON
                if '"Principal": "*"' in policy.get('Policy', ''):
                    findings.append({
                        'ResourceType': 'S3 Bucket',
                        'ResourceId': bucket_name,
                        'Region': 'global',
                        'Risk': 'HIGH',
                        'Issue': 'S3 bucket policy allows public access',
                        'Recommendation': 'Review and restrict bucket policy'
                    })
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    print(f"Error checking bucket policy for {bucket_name}: {e}")
            
            # Check bucket ACL
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'Region': 'global',
                            'Risk': 'HIGH',
                            'Issue': 'S3 bucket ACL allows public access',
                            'Recommendation': 'Remove public access grants from bucket ACL'
                        })
                        break
            except ClientError as e:
                print(f"Error checking bucket ACL for {bucket_name}: {e}")
                
    except Exception as e:
        print(f"Error scanning S3 buckets: {e}")
    
    return findings