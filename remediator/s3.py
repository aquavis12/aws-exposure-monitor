"""
S3 Remediator Module - Automatically fixes public S3 bucket issues
"""
import boto3
from botocore.exceptions import ClientError


def remediate_s3_bucket(bucket_name):
    """
    Remediate public access issues for an S3 bucket
    
    Args:
        bucket_name (str): The name of the bucket to remediate
    
    Returns:
        dict: A dictionary with the remediation status and details
    """
    s3_client = boto3.client('s3')
    result = {
        'bucket': bucket_name,
        'success': False,
        'actions': [],
        'errors': []
    }
    
    try:
        # 1. Apply public access block configuration
        try:
            s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            result['actions'].append('Applied public access block configuration')
        except ClientError as e:
            error_msg = f"Failed to apply public access block: {str(e)}"
            result['errors'].append(error_msg)
        
        # 2. Remove public ACLs
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            has_public_grants = False
            
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' or \
                   grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                    has_public_grants = True
                    break
            
            if has_public_grants:
                # Apply private ACL
                s3_client.put_bucket_acl(
                    Bucket=bucket_name,
                    ACL='private'
                )
                result['actions'].append('Removed public grants from bucket ACL')
        except ClientError as e:
            error_msg = f"Failed to remediate bucket ACL: {str(e)}"
            result['errors'].append(error_msg)
        
        # 3. Check and remove public bucket policy
        try:
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                if '"Principal": "*"' in policy.get('Policy', ''):
                    # This is a simplified check - a real implementation would parse the policy JSON
                    # and only remove the public statements
                    s3_client.delete_bucket_policy(Bucket=bucket_name)
                    result['actions'].append('Removed public bucket policy')
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    raise e
        except ClientError as e:
            error_msg = f"Failed to remediate bucket policy: {str(e)}"
            result['errors'].append(error_msg)
        
        # Set success based on whether there were any errors
        result['success'] = len(result['errors']) == 0
        
    except Exception as e:
        result['success'] = False
        result['errors'].append(f"General error during remediation: {str(e)}")
    
    return result


def remediate_s3_findings(findings):
    """
    Remediate all S3-related findings
    
    Args:
        findings (list): A list of findings to remediate
    
    Returns:
        list: A list of remediation results
    """
    results = []
    
    for finding in findings:
        if finding.get('ResourceType') == 'S3 Bucket':
            bucket_name = finding.get('ResourceId')
            if bucket_name:
                result = remediate_s3_bucket(bucket_name)
                results.append(result)
    
    return results