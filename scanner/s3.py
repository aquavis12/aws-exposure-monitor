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
                
                # Check which public access block settings are disabled (False = allows public access)
                block_public_acls = block_config.get('BlockPublicAcls', False)
                ignore_public_acls = block_config.get('IgnorePublicAcls', False) 
                block_public_policy = block_config.get('BlockPublicPolicy', False)
                restrict_public_buckets = block_config.get('RestrictPublicBuckets', False)
                
                # Only report if there are actual security risks
                disabled_settings = []
                if not block_public_acls:
                    disabled_settings.append('BlockPublicAcls (allows public ACLs)')
                if not ignore_public_acls:
                    disabled_settings.append('IgnorePublicAcls (existing public ACLs active)')
                if not block_public_policy:
                    disabled_settings.append('BlockPublicPolicy (allows public bucket policies)')
                if not restrict_public_buckets:
                    disabled_settings.append('RestrictPublicBuckets (allows public bucket access)')
                
                # Only flag as issue if bucket could actually be accessed publicly
                if disabled_settings:
                    # Check if bucket actually has public access configured
                    has_actual_public_access = False
                    
                    # Check if bucket policy exists and allows public access
                    try:
                        policy_check = s3_client.get_bucket_policy(Bucket=bucket_name)
                        policy_text = policy_check.get('Policy', '')
                        if ('"Principal": "*"' in policy_text or 
                            '"Principal":{"AWS":"*"}' in policy_text or
                            '"Principal": {"AWS": "*"}' in policy_text):
                            has_actual_public_access = True
                    except ClientError:
                        pass
                    
                    # Check if bucket ACL allows public access
                    try:
                        acl_check = s3_client.get_bucket_acl(Bucket=bucket_name)
                        for grant in acl_check.get('Grants', []):
                            grantee = grant.get('Grantee', {})
                            if (grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' or
                                grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'):
                                has_actual_public_access = True
                                break
                    except ClientError:
                        pass
                    
                    # Only report if there's actual public access or high-risk settings
                    if has_actual_public_access or (not block_public_policy and not restrict_public_buckets):
                        risk_level = 'HIGH' if has_actual_public_access else 'MEDIUM'
                        issue_desc = 'S3 bucket is publicly accessible' if has_actual_public_access else 'S3 bucket allows public access configuration'
                        
                        if is_intentionally_public:
                            findings.append({
                                'ResourceType': 'S3 Bucket',
                                'ResourceId': bucket_name,
                                'ResourceName': bucket_name,
                                'Region': bucket_region,
                                'Risk': 'MEDIUM',
                                'Issue': f'{issue_desc} (intentional for website/CDN)',
                                'Recommendation': 'Verify public access is properly secured and still required'
                            })
                        else:
                            findings.append({
                                'ResourceType': 'S3 Bucket',
                                'ResourceId': bucket_name,
                                'ResourceName': bucket_name,
                                'Region': bucket_region,
                                'Risk': risk_level,
                                'Issue': f'{issue_desc} - {len(disabled_settings)} security settings disabled',
                                'Recommendation': f'Review and enable: {"; ".join(disabled_settings)}'
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
                            'Issue': 'S3 bucket has no public access block settings configured (intentional for website/CDN)',
                            'Recommendation': 'Verify public access configuration matches intended use case'
                        })

                    else:
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'HIGH',
                            'Issue': 'S3 bucket has no public access block settings - all public access is allowed',
                            'Recommendation': 'Configure public access block settings to prevent unintended public access'
                        })

                else:
                    pass
            
            # Check bucket policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                
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
                
                policy_text = policy.get('Policy', '')
                # Parse policy to check for public access
                if ('"Principal": "*"' in policy_text or 
                    '"Principal":{"AWS":"*"}' in policy_text or
                    '"Principal": {"AWS": "*"}' in policy_text):
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
                    # Check for public access grants
                    if (grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' or
                        grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'):
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
            
            # Check if bucket has versioning enabled
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    findings.append({
                        'ResourceType': 'S3 Bucket',
                        'ResourceId': bucket_name,
                        'ResourceName': bucket_name,
                        'Region': bucket_region,
                        'Risk': 'LOW',
                        'Issue': 'S3 bucket versioning is disabled',
                        'Recommendation': 'Enable versioning to protect against accidental deletion and provide data recovery options'
                    })
            except ClientError:
                pass
            
            # Check bucket logging
            try:
                logging = s3_client.get_bucket_logging(Bucket=bucket_name)
                if not logging.get('LoggingEnabled'):
                    findings.append({
                        'ResourceType': 'S3 Bucket',
                        'ResourceId': bucket_name,
                        'ResourceName': bucket_name,
                        'Region': bucket_region,
                        'Risk': 'LOW',
                        'Issue': 'S3 bucket access logging is disabled',
                        'Recommendation': 'Enable access logging to track requests made to your bucket'
                    })
            except ClientError:
                pass
            
            # Check for overprivileged bucket access
            try:
                # Check bucket policy for overly broad permissions
                policy_check = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_text = policy_check.get('Policy', '')
                
                # Check for wildcard actions with specific principals (not public)
                if ('"Action": "s3:*"' in policy_text or '"Action": ["s3:*"]' in policy_text) and '"Principal": "*"' not in policy_text:
                    findings.append({
                        'ResourceType': 'S3 Bucket',
                        'ResourceId': bucket_name,
                        'ResourceName': bucket_name,
                        'Region': bucket_region,
                        'Risk': 'MEDIUM',
                        'Issue': 'S3 bucket policy grants wildcard permissions (s3:*)',
                        'Recommendation': 'Replace wildcard permissions with specific actions needed (s3:GetObject, s3:PutObject, etc.)'
                    })
                
                # Check for dangerous actions
                dangerous_actions = ['s3:DeleteBucket', 's3:PutBucketPolicy', 's3:DeleteBucketPolicy', 's3:PutBucketAcl']
                for action in dangerous_actions:
                    if f'"{action}"' in policy_text and '"Principal": "*"' not in policy_text:
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'HIGH',
                            'Issue': f'S3 bucket policy allows dangerous action: {action}',
                            'Recommendation': f'Remove {action} permission or restrict to specific trusted principals'
                        })
                        break
                
                # Check for cross-account access without conditions
                if '"AWS": "arn:aws:iam::' in policy_text and '"Condition"' not in policy_text:
                    findings.append({
                        'ResourceType': 'S3 Bucket',
                        'ResourceId': bucket_name,
                        'ResourceName': bucket_name,
                        'Region': bucket_region,
                        'Risk': 'MEDIUM',
                        'Issue': 'S3 bucket allows cross-account access without conditions',
                        'Recommendation': 'Add conditions to cross-account policies (IP restrictions, MFA, etc.)'
                    })
                    
            except ClientError:
                pass
            
            # Check CORS configuration
            try:
                cors_config = s3_client.get_bucket_cors(Bucket=bucket_name)
                cors_rules = cors_config.get('CORSRules', [])
                
                for rule in cors_rules:
                    allowed_origins = rule.get('AllowedOrigins', [])
                    allowed_methods = rule.get('AllowedMethods', [])
                    
                    # Check for overly permissive CORS
                    if '*' in allowed_origins:
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'S3 bucket CORS policy allows all origins (*)',
                            'Recommendation': 'Restrict CORS origins to specific domains that need access'
                        })
                    
                    # Check for dangerous methods
                    dangerous_methods = ['DELETE', 'PUT']
                    if any(method in allowed_methods for method in dangerous_methods) and '*' in allowed_origins:
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'HIGH',
                            'Issue': f'S3 bucket CORS allows dangerous methods ({dangerous_methods}) from any origin',
                            'Recommendation': 'Restrict CORS methods and origins for write operations'
                        })
                        break
                        
            except ClientError:
                # No CORS configuration - this is normal
                pass
            
    except Exception:
        pass
    
    return findings