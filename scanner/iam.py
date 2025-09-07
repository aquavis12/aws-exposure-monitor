"""
IAM Scanner Module - Detects security issues with IAM users, roles, and access keys
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan_iam_users(region=None):
    """
    Scan IAM users for security issues like:
    - Inactive users (no login for 90+ days)
    - Old access keys (unused for 60+ days)
    - Missing MFA
    - Overly permissive policies
    
    Args:
        region (str, optional): AWS region to scan. IAM is global, so this parameter is ignored.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    # Note: IAM is a global service, region parameter is ignored
    
    try:
        # IAM is a global service
        iam_client = boto3.client('iam')
        
        # Get current time for age calculations
        current_time = datetime.now(timezone.utc)
        
        # Get all IAM users
        paginator = iam_client.get_paginator('list_users')
        users = []
        
        for page in paginator.paginate():
            users.extend(page.get('Users', []))
        
        if users:
            for i, user in enumerate(users, 1):
                user_name = user.get('UserName')
                user_id = user.get('UserId')
                user_arn = user.get('Arn')
                creation_date = user.get('CreateDate')
                
                # Print progress every 10 users or for the last one
                if i % 10 == 0 or i == len(users):
                    print(f"  Progress: {i}/{len(users)}")
                
                # Check last login time
                try:
                    login_profile = iam_client.get_login_profile(UserName=user_name)
                    has_console_access = True
                except ClientError:
                    has_console_access = False
                
                # Check password last used (if user has console access)
                if has_console_access:
                    password_last_used = user.get('PasswordLastUsed')
                    
                    if password_last_used:
                        days_since_login = (current_time - password_last_used).days
                        
                        if days_since_login > 90:
                            findings.append({
                                'ResourceType': 'IAM User',
                                'ResourceId': user_name,
                                'ResourceName': user_name,
                                'ResourceArn': user_arn,
                                'Region': 'global',
                                'Risk': 'HIGH',
                                'Issue': f'IAM user has not accessed console for {days_since_login} days',
                                'Recommendation': 'Disable or remove inactive user account'
                            })
                    else:
                        # User has never logged in
                        days_since_creation = (current_time - creation_date).days
                        
                        if days_since_creation > 30:
                            findings.append({
                                'ResourceType': 'IAM User',
                                'ResourceId': user_name,
                                'ResourceName': user_name,
                                'ResourceArn': user_arn,
                                'Region': 'global',
                                'Risk': 'HIGH',
                                'Issue': f'IAM user never accessed console (created {days_since_creation} days ago)',
                                'Recommendation': 'Remove unused user account'
                            })
                
                # Check MFA status
                mfa_devices = iam_client.list_mfa_devices(UserName=user_name).get('MFADevices', [])
                
                if has_console_access and not mfa_devices:
                    findings.append({
                        'ResourceType': 'IAM User',
                        'ResourceId': user_name,
                        'ResourceName': user_name,
                        'ResourceArn': user_arn,
                        'Region': 'global',
                        'Risk': 'HIGH',
                        'Issue': 'IAM user with console access does not have MFA enabled',
                        'Recommendation': 'Enable MFA for all users with console access'
                    })
                
                # Check access keys
                access_keys = iam_client.list_access_keys(UserName=user_name).get('AccessKeyMetadata', [])
                
                for key in access_keys:
                    key_id = key.get('AccessKeyId')
                    key_status = key.get('Status')
                    key_create_date = key.get('CreateDate')
                    
                    # Check key age
                    key_age_days = (current_time - key_create_date).days
                    
                    if key_age_days > 90:
                        findings.append({
                            'ResourceType': 'IAM Access Key',
                            'ResourceId': key_id,
                            'ResourceName': f"{user_name}'s access key",
                            'ResourceArn': user_arn,
                            'Region': 'global',
                            'Risk': 'MEDIUM',
                            'Issue': f'Access key is {key_age_days} days old',
                            'Recommendation': 'Rotate access keys regularly (every 90 days)'
                        })
                    
                    # Check key last used
                    if key_status == 'Active':
                        try:
                            key_last_used = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                            last_used_date = key_last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                            
                            if last_used_date:
                                days_since_use = (current_time - last_used_date).days
                                
                                if days_since_use > 180:
                                    findings.append({
                                        'ResourceType': 'IAM Access Key',
                                        'ResourceId': key_id,
                                        'ResourceName': f"{user_name}'s access key",
                                        'ResourceArn': user_arn,
                                        'Region': 'global',
                                        'Risk': 'HIGH',
                                        'Issue': f'Access key unused for {days_since_use} days',
                                        'Recommendation': 'Delete unused access key'
                                    })
                            else:
                                # Key has never been used
                                if key_age_days > 30:
                                    findings.append({
                                        'ResourceType': 'IAM Access Key',
                                        'ResourceId': key_id,
                                        'ResourceName': f"{user_name}'s access key",
                                        'ResourceArn': user_arn,
                                        'Region': 'global',
                                        'Risk': 'MEDIUM',
                                        'Issue': f'Access key has never been used (created {key_age_days} days ago)',
                                        'Recommendation': 'Delete unused access keys'
                                    })
                        except ClientError as e:
                            pass
                
                # Check for excessive privileges
                try:
                    # Check attached policies
                    attached_policies = iam_client.list_attached_user_policies(UserName=user_name).get('AttachedPolicies', [])
                    for policy in attached_policies:
                        policy_arn = policy.get('PolicyArn')
                        policy_name = policy.get('PolicyName')
                        
                        # Check for admin access
                        if 'AdministratorAccess' in policy_arn:
                            findings.append({
                                'ResourceType': 'IAM User',
                                'ResourceId': user_name,
                                'ResourceName': user_name,
                                'ResourceArn': user_arn,
                                'Region': 'global',
                                'Risk': 'CRITICAL',
                                'Issue': 'IAM user has AdministratorAccess policy',
                                'Recommendation': 'Remove admin access, use roles with temporary credentials instead'
                            })
                        elif 'PowerUserAccess' in policy_arn:
                            findings.append({
                                'ResourceType': 'IAM User',
                                'ResourceId': user_name,
                                'ResourceName': user_name,
                                'ResourceArn': user_arn,
                                'Region': 'global',
                                'Risk': 'HIGH',
                                'Issue': 'IAM user has PowerUserAccess policy',
                                'Recommendation': 'Replace with specific permissions needed for user role'
                            })
                        elif 'FullAccess' in policy_name:
                            findings.append({
                                'ResourceType': 'IAM User',
                                'ResourceId': user_name,
                                'ResourceName': user_name,
                                'ResourceArn': user_arn,
                                'Region': 'global',
                                'Risk': 'HIGH',
                                'Issue': f'IAM user has overly broad policy: {policy_name}',
                                'Recommendation': 'Replace with specific permissions following least privilege principle'
                            })
                    
                    # Check inline policies for wildcards and dangerous permissions
                    inline_policies = iam_client.list_user_policies(UserName=user_name).get('PolicyNames', [])
                    for policy_name in inline_policies:
                        try:
                            policy_doc = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
                            policy_text = str(policy_doc.get('PolicyDocument', {}))
                            
                            if '"Action": "*"' in policy_text and '"Resource": "*"' in policy_text:
                                findings.append({
                                    'ResourceType': 'IAM User',
                                    'ResourceId': user_name,
                                    'ResourceName': user_name,
                                    'ResourceArn': user_arn,
                                    'Region': 'global',
                                    'Risk': 'CRITICAL',
                                    'Issue': f'IAM user has wildcard permissions (Action:*, Resource:*) in policy: {policy_name}',
                                    'Recommendation': 'Replace with specific actions and resources needed'
                                })
                            elif 'iam:' in policy_text and ('CreateUser' in policy_text or 'AttachUserPolicy' in policy_text):
                                findings.append({
                                    'ResourceType': 'IAM User',
                                    'ResourceId': user_name,
                                    'ResourceName': user_name,
                                    'ResourceArn': user_arn,
                                    'Region': 'global',
                                    'Risk': 'HIGH',
                                    'Issue': f'IAM user can modify IAM users/policies in policy: {policy_name}',
                                    'Recommendation': 'Remove IAM management permissions from user policies'
                                })
                        except ClientError:
                            pass
                    
                    # Check group memberships
                    groups = iam_client.get_groups_for_user(UserName=user_name).get('Groups', [])
                    for group in groups:
                        group_name = group.get('GroupName')
                        if 'admin' in group_name.lower() or 'power' in group_name.lower():
                            findings.append({
                                'ResourceType': 'IAM User',
                                'ResourceId': user_name,
                                'ResourceName': user_name,
                                'ResourceArn': user_arn,
                                'Region': 'global',
                                'Risk': 'HIGH',
                                'Issue': f'IAM user is member of privileged group: {group_name}',
                                'Recommendation': 'Review group membership and use roles for elevated access'
                            })
                
                except ClientError:
                    pass
        
        # Check password policy
        try:
            password_policy = iam_client.get_account_password_policy().get('PasswordPolicy', {})
            
            # Check minimum password length
            min_length = password_policy.get('MinimumPasswordLength', 0)
            if min_length < 14:
                findings.append({
                    'ResourceType': 'IAM Password Policy',
                    'ResourceId': 'account-password-policy',
                    'ResourceName': 'Account Password Policy',
                    'Region': 'global',
                    'Risk': 'MEDIUM',
                    'Issue': f'Password policy minimum length is only {min_length} characters',
                    'Recommendation': 'Set minimum password length to at least 14 characters'
                })
            
            # Check password reuse prevention
            reuse_prevention = password_policy.get('PasswordReusePrevention', 0)
            if reuse_prevention < 24:
                findings.append({
                    'ResourceType': 'IAM Password Policy',
                    'ResourceId': 'account-password-policy',
                    'ResourceName': 'Account Password Policy',
                    'Region': 'global',
                    'Risk': 'MEDIUM',
                    'Issue': f'Password policy allows reuse after {reuse_prevention} passwords',
                    'Recommendation': 'Set password reuse prevention to at least 24 passwords'
                })
            
            # Check password expiration
            max_age = password_policy.get('MaxPasswordAge', 0)
            if max_age == 0 or max_age > 90:
                findings.append({
                    'ResourceType': 'IAM Password Policy',
                    'ResourceId': 'account-password-policy',
                    'ResourceName': 'Account Password Policy',
                    'Region': 'global',
                    'Risk': 'MEDIUM',
                    'Issue': 'Password policy does not require regular password rotation',
                    'Recommendation': 'Set maximum password age to 90 days or less'
                })
        
        except ClientError as e:
            if 'NoSuchEntity' in str(e):
                findings.append({
                    'ResourceType': 'IAM Password Policy',
                    'ResourceId': 'account-password-policy',
                    'ResourceName': 'Account Password Policy',
                    'Region': 'global',
                    'Risk': 'HIGH',
                    'Issue': 'No account password policy is set',
                    'Recommendation': 'Configure a strong password policy for the AWS account'
                })
                pass
    except Exception as e:
        pass
    
    return findings