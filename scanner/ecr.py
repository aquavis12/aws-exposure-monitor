"""
ECR Scanner Module - Detects publicly accessible ECR repositories
"""
import boto3
from botocore.exceptions import ClientError


def scan_ecr_repositories():
    """
    Scan ECR repositories for public access settings
    Returns a list of dictionaries containing vulnerable resources
    """
    findings = []
    
    try:
        # Get all regions
        ec2_client = boto3.client('ec2')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        for region in regions:
            ecr_client = boto3.client('ecr', region_name=region)
            
            try:
                # Get public registries
                public_registries = ecr_client.describe_registries()
                
                for registry in public_registries.get('registries', []):
                    registry_id = registry.get('registryId')
                    
                    # Check if registry is public
                    if registry.get('registryUri', '').endswith('public.ecr.aws'):
                        findings.append({
                            'ResourceType': 'ECR Registry',
                            'ResourceId': registry_id,
                            'Region': region,
                            'Risk': 'MEDIUM',
                            'Issue': 'ECR registry is publicly accessible',
                            'Recommendation': 'Review if this registry should be public and consider making it private'
                        })
            
            except ClientError as e:
                # Some regions might not support ECR public
                if 'AccessDeniedException' not in str(e):
                    print(f"Error checking ECR public registries in {region}: {e}")
            
            try:
                # Get repositories
                paginator = ecr_client.get_paginator('describe_repositories')
                for page in paginator.paginate():
                    for repo in page.get('repositories', []):
                        repo_name = repo.get('repositoryName')
                        repo_arn = repo.get('repositoryArn')
                        
                        # Check repository policy
                        try:
                            policy = ecr_client.get_repository_policy(repositoryName=repo_name)
                            policy_text = policy.get('policyText', '')
                            
                            # Simple check for public access in policy
                            if '"Principal": "*"' in policy_text or '"Principal":{"AWS":"*"}' in policy_text:
                                findings.append({
                                    'ResourceType': 'ECR Repository',
                                    'ResourceId': repo_name,
                                    'ResourceArn': repo_arn,
                                    'Region': region,
                                    'Risk': 'HIGH',
                                    'Issue': 'ECR repository policy allows public access',
                                    'Recommendation': 'Review and restrict the repository policy'
                                })
                        except ClientError as e:
                            if e.response['Error']['Code'] != 'RepositoryPolicyNotFoundException':
                                print(f"Error checking repository policy for {repo_name} in {region}: {e}")
            
            except ClientError as e:
                print(f"Error listing ECR repositories in {region}: {e}")
    
    except Exception as e:
        print(f"Error scanning ECR repositories: {e}")
    
    return findings