"""
S3 Scanner Module - Detects publicly accessible S3 buckets and encryption issues
"""
import boto3
import sys
from botocore.exceptions import ClientError


def scan_s3_buckets(region=None):
    """
    Scan S3 buckets for public access settings and encryption
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    # S3 is a global service, but we can filter by region
    s3_client = boto3.client('s3')
    
    print("Starting S3 bucket scan...")
    
    try:
        # Get all buckets
        response = s3_client.list_buckets()
        all_buckets = response['Buckets']
        
        # Filter buckets by region if specified
        if region:
            buckets = []
            for bucket in all_buckets:
                bucket_name = bucket['Name']
                try:
                    location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location_response.get('LocationConstraint') or 'us-east-1'
                    if bucket_region == region:
                        buckets.append(bucket)
                except Exception:
                    # Skip buckets we can't determine the region for
                    pass
            print(f"Found {len(buckets)} S3 buckets in region {region}")
        else:
            buckets = all_buckets
            print(f"Found {len(buckets)} S3 buckets across all regions")
        
        for i, bucket in enumerate(buckets, 1):
            bucket_name = bucket['Name']
            creation_date = bucket.get('CreationDate', 'Unknown')
            
            print(f"[{i}/{len(buckets)}] Scanning bucket: {bucket_name} (Created: {creation_date})")
            
            # Try to get bucket location
            try:
                location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = location_response.get('LocationConstraint') or 'us-east-1'
                # If location is None, it's in us-east-1
                if bucket_region is None:
                    bucket_region = 'us-east-1'
                print(f"  Region: {bucket_region}")
            except Exception as e:
                bucket_region = 'global'
                print(f"  Could not determine region: {e}")
            
            # Skip if we're filtering by region and this bucket is in a different region
            if region and bucket_region != region:
                print(f"  Skipping bucket in region {bucket_region} (not in target region {region})")
                continue
            
            # Check bucket public access block settings
            try:
                public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                block_config = public_access_block['PublicAccessBlockConfiguration']
                
                print(f"  Public Access Block: {block_config}")
                
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
                        'ResourceName': bucket_name,
                        'Region': bucket_region,
                        'Risk': 'HIGH',
                        'Issue': 'S3 bucket has public access block disabled',
                        'Recommendation': 'Enable all public access block settings for this bucket'
                    })
                    print(f"    [!] FINDING: Public access block not fully enabled")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    # No public access block configuration means the bucket could be public
                    findings.append({
                        'ResourceType': 'S3 Bucket',
                        'ResourceId': bucket_name,
                        'ResourceName': bucket_name,
                        'Region': bucket_region,
                        'Risk': 'HIGH',
                        'Issue': 'S3 bucket has no public access block configuration',
                        'Recommendation': 'Configure public access block for this bucket'
                    })
                    print(f"    [!] FINDING: No public access block configuration")
                else:
                    print(f"    Error checking public access block: {e}")
            
            # Check bucket policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                print(f"  Bucket has a policy")
                
                # Here you would analyze the policy for public access
                # This is a simplified check - a real implementation would parse the policy JSON
                if '"Principal": "*"' in policy.get('Policy', '') or '"Principal":{"AWS":"*"}' in policy.get('Policy', ''):
                    findings.append({
                        'ResourceType': 'S3 Bucket',
                        'ResourceId': bucket_name,
                        'ResourceName': bucket_name,
                        'Region': bucket_region,
                        'Risk': 'HIGH',
                        'Issue': 'S3 bucket policy allows public access',
                        'Recommendation': 'Review and restrict bucket policy'
                    })
                    print(f"    [!] FINDING: Bucket policy allows public access")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    print(f"    Error checking bucket policy: {e}")
                else:
                    print(f"  No bucket policy found")
            
            # Check bucket ACL
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                print(f"  Checking bucket ACL")
                
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'HIGH',
                            'Issue': 'S3 bucket ACL allows public access',
                            'Recommendation': 'Remove public access grants from bucket ACL'
                        })
                        print(f"    [!] FINDING: Bucket ACL allows public access")
                        break
            except ClientError as e:
                print(f"    Error checking bucket ACL: {e}")
            
            # Check bucket encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                print(f"  Bucket encryption is enabled")
                # If we get here, encryption is enabled
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    findings.append({
                        'ResourceType': 'S3 Bucket',
                        'ResourceId': bucket_name,
                        'ResourceName': bucket_name,
                        'Region': bucket_region,
                        'Risk': 'MEDIUM',
                        'Issue': 'S3 bucket does not have default encryption enabled',
                        'Recommendation': 'Enable default encryption for this bucket using SSE-S3 or SSE-KMS'
                    })
                    print(f"    [!] FINDING: Default encryption not enabled")
                else:
                    print(f"    Error checking bucket encryption: {e}")
            
            # Check if bucket has versioning enabled (additional security check)
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') == 'Enabled':
                    print(f"  Bucket versioning is enabled")
                else:
                    findings.append({
                        'ResourceType': 'S3 Bucket',
                        'ResourceId': bucket_name,
                        'ResourceName': bucket_name,
                        'Region': bucket_region,
                        'Risk': 'LOW',
                        'Issue': 'S3 bucket does not have versioning enabled',
                        'Recommendation': 'Enable versioning for this bucket to protect against accidental deletion'
                    })
                    print(f"    [!] FINDING: Versioning not enabled")
            except ClientError as e:
                print(f"    Error checking bucket versioning: {e}")
            
            # Add a blank line for readability between buckets
            print("")
                
    except Exception as e:
        print(f"Error scanning S3 buckets: {e}")
    
    print(f"S3 bucket scan complete. Found {len(findings)} issues.")
    return findings