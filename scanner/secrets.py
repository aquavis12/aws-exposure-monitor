"""
Secrets Manager and KMS Scanner Module - Detects security issues with secrets and keys
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan_secrets_and_keys(region=None):
    """
    Scan AWS Secrets Manager secrets and KMS keys for security issues like:
    - Secrets not accessed for 90+ days
    - Secrets pending deletion
    - KMS keys with rotation disabled
    - KMS keys pending deletion
    - Unused KMS keys
    - Keys with overly permissive policies
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting Secrets Manager and KMS scan...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
            print(f"Scanning region: {region}")
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
            print(f"Scanning {len(regions)} regions")
        
        region_count = 0
        total_secrets_count = 0
        total_keys_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            # Scan Secrets Manager secrets
            try:
                secrets_client = boto3.client('secretsmanager', region_name=current_region)
                
                # Get current time for age calculations
                current_time = datetime.now(timezone.utc)
                
                # List all secrets
                secrets = []
                paginator = secrets_client.get_paginator('list_secrets')
                
                for page in paginator.paginate():
                    secrets.extend(page.get('SecretList', []))
                
                secrets_count = len(secrets)
                
                if secrets_count > 0:
                    total_secrets_count += secrets_count
                    print(f"  Found {secrets_count} Secrets Manager secrets in {current_region}")
                    
                    for i, secret in enumerate(secrets, 1):
                        secret_name = secret.get('Name')
                        secret_arn = secret.get('ARN')
                        last_accessed_date = secret.get('LastAccessedDate')
                        last_changed_date = secret.get('LastChangedDate')
                        deletion_date = secret.get('DeletedDate')
                        
                        # Print progress every 10 secrets or for the last one
                        if i % 10 == 0 or i == secrets_count:
                            print(f"  Progress: {i}/{secrets_count} secrets")
                        
                        # Check if secret is pending deletion
                        if deletion_date:
                            days_until_deletion = (deletion_date - current_time).days
                            findings.append({
                                'ResourceType': 'Secrets Manager Secret',
                                'ResourceId': secret_name,
                                'ResourceName': secret_name,
                                'ResourceArn': secret_arn,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': f'Secret is pending deletion in {days_until_deletion} days',
                                'Recommendation': 'Verify if this secret is still needed before it is permanently deleted'
                            })
                            print(f"    [!] FINDING: Secret {secret_name} is pending deletion - MEDIUM risk")
                        
                        # Check if secret hasn't been accessed in 90+ days
                        if last_accessed_date:
                            days_since_access = (current_time - last_accessed_date).days
                            if days_since_access > 90:
                                findings.append({
                                    'ResourceType': 'Secrets Manager Secret',
                                    'ResourceId': secret_name,
                                    'ResourceName': secret_name,
                                    'ResourceArn': secret_arn,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': f'Secret has not been accessed for {days_since_access} days',
                                    'Recommendation': 'Review if this secret is still needed or delete it to reduce costs'
                                })
                                print(f"    [!] FINDING: Secret {secret_name} has not been accessed for {days_since_access} days - MEDIUM risk")
                        
                        # Check if secret hasn't been rotated in 90+ days
                        if last_changed_date:
                            days_since_change = (current_time - last_changed_date).days
                            if days_since_change > 90:
                                findings.append({
                                    'ResourceType': 'Secrets Manager Secret',
                                    'ResourceId': secret_name,
                                    'ResourceName': secret_name,
                                    'ResourceArn': secret_arn,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': f'Secret has not been rotated for {days_since_change} days',
                                    'Recommendation': 'Enable automatic rotation or manually rotate the secret'
                                })
                                print(f"    [!] FINDING: Secret {secret_name} has not been rotated for {days_since_change} days - MEDIUM risk")
                        
                        # Check if secret has rotation enabled
                        try:
                            rotation = secrets_client.describe_secret(SecretId=secret_arn)
                            rotation_enabled = rotation.get('RotationEnabled', False)
                            
                            if not rotation_enabled and not deletion_date:
                                findings.append({
                                    'ResourceType': 'Secrets Manager Secret',
                                    'ResourceId': secret_name,
                                    'ResourceName': secret_name,
                                    'ResourceArn': secret_arn,
                                    'Region': current_region,
                                    'Risk': 'LOW',
                                    'Issue': 'Secret does not have automatic rotation enabled',
                                    'Recommendation': 'Enable automatic rotation for better security'
                                })
                                print(f"    [!] FINDING: Secret {secret_name} does not have rotation enabled - LOW risk")
                        except ClientError as e:
                            print(f"    Error checking rotation for secret {secret_name}: {e}")
            
            except ClientError as e:
                print(f"  Error scanning Secrets Manager in {current_region}: {e}")
            
            # Scan KMS keys
            try:
                kms_client = boto3.client('kms', region_name=current_region)
                
                # List all KMS keys
                keys = []
                paginator = kms_client.get_paginator('list_keys')
                
                for page in paginator.paginate():
                    keys.extend(page.get('Keys', []))
                
                keys_count = len(keys)
                
                if keys_count > 0:
                    total_keys_count += keys_count
                    print(f"  Found {keys_count} KMS keys in {current_region}")
                    
                    for i, key in enumerate(keys, 1):
                        key_id = key.get('KeyId')
                        key_arn = key.get('KeyArn')
                        
                        # Print progress every 10 keys or for the last one
                        if i % 10 == 0 or i == keys_count:
                            print(f"  Progress: {i}/{keys_count} keys")
                        
                        try:
                            # Get key details
                            key_info = kms_client.describe_key(KeyId=key_id)
                            key_metadata = key_info.get('KeyMetadata', {})
                            
                            key_state = key_metadata.get('KeyState')
                            key_manager = key_metadata.get('KeyManager')
                            creation_date = key_metadata.get('CreationDate')
                            key_usage = key_metadata.get('KeyUsage')
                            key_spec = key_metadata.get('KeySpec')
                            
                            # Skip AWS managed keys
                            if key_manager == 'AWS':
                                continue
                            
                            # Get key name from aliases
                            key_name = key_id
                            try:
                                aliases = kms_client.list_aliases(KeyId=key_id)
                                if aliases.get('Aliases'):
                                    key_name = aliases['Aliases'][0].get('AliasName', key_id)
                            except ClientError:
                                pass
                            
                            # Check if key is pending deletion
                            if key_state == 'PendingDeletion':
                                deletion_date = key_metadata.get('DeletionDate')
                                if deletion_date:
                                    days_until_deletion = (deletion_date - current_time).days
                                    findings.append({
                                        'ResourceType': 'KMS Key',
                                        'ResourceId': key_id,
                                        'ResourceName': key_name,
                                        'ResourceArn': key_arn,
                                        'Region': current_region,
                                        'Risk': 'HIGH',
                                        'Issue': f'KMS key is pending deletion in {days_until_deletion} days',
                                        'Recommendation': 'Verify if this key is still needed before it is permanently deleted'
                                    })
                                    print(f"    [!] FINDING: KMS key {key_name} is pending deletion - HIGH risk")
                            
                            # Check if key is disabled
                            elif key_state == 'Disabled':
                                findings.append({
                                    'ResourceType': 'KMS Key',
                                    'ResourceId': key_id,
                                    'ResourceName': key_name,
                                    'ResourceArn': key_arn,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'KMS key is disabled',
                                    'Recommendation': 'Enable the key if needed or schedule it for deletion'
                                })
                                print(f"    [!] FINDING: KMS key {key_name} is disabled - MEDIUM risk")
                            
                            # Check key rotation for enabled customer managed keys
                            elif key_state == 'Enabled' and key_manager == 'CUSTOMER':
                                try:
                                    rotation = kms_client.get_key_rotation_status(KeyId=key_id)
                                    key_rotation_enabled = rotation.get('KeyRotationEnabled', False)
                                    
                                    if not key_rotation_enabled and key_usage == 'ENCRYPT_DECRYPT':
                                        findings.append({
                                            'ResourceType': 'KMS Key',
                                            'ResourceId': key_id,
                                            'ResourceName': key_name,
                                            'ResourceArn': key_arn,
                                            'Region': current_region,
                                            'Risk': 'MEDIUM',
                                            'Issue': 'KMS key does not have automatic rotation enabled',
                                            'Recommendation': 'Enable automatic key rotation for better security'
                                        })
                                        print(f"    [!] FINDING: KMS key {key_name} does not have rotation enabled - MEDIUM risk")
                                except ClientError as e:
                                    # Some key types don't support rotation
                                    if 'UnsupportedOperationException' not in str(e):
                                        print(f"    Error checking rotation for key {key_id}: {e}")
                            
                            # Check for key policy issues
                            try:
                                policy = kms_client.get_key_policy(KeyId=key_id, PolicyName='default')
                                policy_text = policy.get('Policy', '')
                                
                                # Check for overly permissive policies
                                if '"Principal": "*"' in policy_text or '"Principal":{"AWS":"*"}' in policy_text:
                                    findings.append({
                                        'ResourceType': 'KMS Key',
                                        'ResourceId': key_id,
                                        'ResourceName': key_name,
                                        'ResourceArn': key_arn,
                                        'Region': current_region,
                                        'Risk': 'HIGH',
                                        'Issue': 'KMS key policy contains overly permissive statements',
                                        'Recommendation': 'Restrict key policy to specific principals'
                                    })
                                    print(f"    [!] FINDING: KMS key {key_name} has overly permissive policy - HIGH risk")
                            except ClientError as e:
                                print(f"    Error checking policy for key {key_id}: {e}")
                        
                        except ClientError as e:
                            print(f"    Error checking KMS key {key_id}: {e}")
            
            except ClientError as e:
                print(f"  Error scanning KMS in {current_region}: {e}")
        
        if total_secrets_count == 0 and total_keys_count == 0:
            print("No Secrets Manager secrets or KMS keys found.")
        else:
            print(f"Secrets and KMS scan complete. Scanned {total_secrets_count} secrets and {total_keys_count} keys.")
    
    except Exception as e:
        print(f"Error scanning Secrets Manager and KMS: {e}")
    
    if findings:
        print(f"Found {len(findings)} Secrets Manager and KMS security issues.")
    else:
        print("No Secrets Manager or KMS security issues found.")
    
    return findings