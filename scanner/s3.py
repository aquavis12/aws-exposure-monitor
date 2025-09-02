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
    
        else:
            buckets = all_buckets

        
        for i, bucket in enumerate(buckets, 1):
            bucket_name = bucket['Name']
            creation_date = bucket.get('CreationDate', 'Unknown')
            

            
            # Try to get bucket location
            try:
                location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = location_response.get('LocationConstraint') or 'us-east-1'
                # If location is None, it's in us-east-1
                if bucket_region is None:
                    bucket_region = 'us-east-1'

            except Exception:
                bucket_region = 'global'
            
            # Skip if we're filtering by region and this bucket is in a different region
            if region and bucket_region != region:
                continue
            
            # Check bucket public access block settings
            try:
                public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                block_config = public_access_block['PublicAccessBlockConfiguration']
                

                
                # Check for intentional public access
                is_intentionally_public = False
                try:
                    tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                    for tag in tags_response.get('TagSet', []):
                        if tag.get('Key', '').lower() in ['public', 'website', 'cdn'] or \
                           tag.get('Value', '').lower() in ['true', 'yes', 'public', 'website']:
                            is_intentionally_public = True
                            break
                except ClientError:
                    pass  # No tags or access denied
                
                # If any of these are False, the bucket might be publicly accessible
                if not all([
                    block_config.get('BlockPublicAcls', False),
                    block_config.get('IgnorePublicAcls', False),
                    block_config.get('BlockPublicPolicy', False),
                    block_config.get('RestrictPublicBuckets', False)
                ]):
                    if is_intentionally_public:
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'S3 bucket is configured for public access (intentional based on tags)',
                            'Recommendation': 'Verify that public access is still required and properly secured'
                        })

                    else:
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'HIGH',
                            'Issue': 'S3 bucket has public access block disabled',
                            'Recommendation': 'Review if public access is needed. If not, enable all public access block settings'
                        })

            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    # Check if bucket is intentionally public
                    is_intentionally_public = False
                    try:
                        tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                        for tag in tags_response.get('TagSet', []):
                            if tag.get('Key', '').lower() in ['public', 'website', 'cdn'] or \
                               tag.get('Value', '').lower() in ['true', 'yes', 'public', 'website']:
                                is_intentionally_public = True
                                break
                    except ClientError:
                        pass  # No tags or access denied
                    
                    if is_intentionally_public:
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'S3 bucket has no public access block configuration (intentional based on tags)',
                            'Recommendation': 'Verify that public access configuration is appropriate for intended use'
                        })

                    else:
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'HIGH',
                            'Issue': 'S3 bucket has no public access block configuration',
                            'Recommendation': 'Configure public access block settings unless public access is specifically required'
                        })

                else:
                    pass
            
            # Check bucket policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)

                
                # Here you would analyze the policy for public access
                # This is a simplified check - a real implementation would parse the policy JSON
                # Check if bucket is intentionally public
                is_intentionally_public = False
                try:
                    tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                    for tag in tags_response.get('TagSet', []):
                        if tag.get('Key', '').lower() in ['public', 'website', 'cdn'] or \
                           tag.get('Value', '').lower() in ['true', 'yes', 'public', 'website']:
                            is_intentionally_public = True
                            break
                except ClientError:
                    pass  # No tags or access denied
                
                if '"Principal": "*"' in policy.get('Policy', '') or '"Principal":{"AWS":"*"}' in policy.get('Policy', ''):
                    if is_intentionally_public:
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'S3 bucket policy allows public access (intentional based on tags)',
                            'Recommendation': 'Verify that public access policy is still appropriate and secure'
                        })

                    else:
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'HIGH',
                            'Issue': 'S3 bucket policy allows public access',
                            'Recommendation': 'Review and restrict bucket policy unless public access is specifically required'
                        })

            except ClientError as e:
                pass
            
            # Check bucket ACL
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)

                
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        # Check if bucket is intentionally public
                        is_intentionally_public = False
                        try:
                            tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                            for tag in tags_response.get('TagSet', []):
                                if tag.get('Key', '').lower() in ['public', 'website', 'cdn'] or \
                                   tag.get('Value', '').lower() in ['true', 'yes', 'public', 'website']:
                                    is_intentionally_public = True
                                    break
                        except ClientError:
                            pass  # No tags or access denied
                        
                        if is_intentionally_public:
                            findings.append({
                                'ResourceType': 'S3 Bucket',
                                'ResourceId': bucket_name,
                                'ResourceName': bucket_name,
                                'Region': bucket_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'S3 bucket ACL allows public access (intentional based on tags)',
                                'Recommendation': 'Verify that public ACL permissions are still appropriate'
                            })

                        else:
                            findings.append({
                                'ResourceType': 'S3 Bucket',
                                'ResourceId': bucket_name,
                                'ResourceName': bucket_name,
                                'Region': bucket_region,
                                'Risk': 'HIGH',
                                'Issue': 'S3 bucket ACL allows public access',
                                'Recommendation': 'Remove public access grants from bucket ACL unless specifically required'
                            })

                        break
            except ClientError:
                pass
            
            # Check bucket encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)

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

                else:
                    pass
            
            # Check if bucket has versioning enabled (additional security check)
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    findings.append({
                        'ResourceType': 'S3 Bucket',
                        'ResourceId': bucket_name,
                        'ResourceName': bucket_name,
                        'Region': bucket_region,
                        'Risk': 'LOW',
                        'Issue': 'S3 bucket does not have versioning enabled',
                        'Recommendation': 'Enable versioning for this bucket to protect against accidental deletion'
                    })

            except ClientError:
                pass
            
            # Add a blank line for readability between buckets

                
    except Exception:
        pass
    
    return findings