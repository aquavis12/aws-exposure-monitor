"""
ECR Scanner Module - Detects publicly accessible ECR repositories
"""
import boto3
from botocore.exceptions import ClientError


def scan_ecr_repositories(region=None):
    """
    Scan ECR repositories for public access settings
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting ECR repository scan...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            # Check if the region is valid
            try:
                ec2_client.describe_regions(RegionNames=[region])
                regions = [region]
                print(f"Scanning region: {region}")
            except ClientError:
                print(f"Invalid region: {region}")
                return findings
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
            print(f"Scanning {len(regions)} regions")
        
        region_count = 0
        total_repos_found = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            ecr_client = boto3.client('ecr', region_name=current_region)
            
            # Check for public ECR repositories (ECR Public is a separate service)
            try:
                # ECR Public is only in us-east-1
                if current_region == 'us-east-1' or (region is None):
                    ecr_public_client = boto3.client('ecr-public', region_name='us-east-1')
                    public_repositories = ecr_public_client.describe_repositories()
                    public_repos = public_repositories.get('repositories', [])
                    
                    if public_repos:
                        total_repos_found += len(public_repos)
                        print(f"  Found {len(public_repos)} public ECR repositories in us-east-1")
                        
                        for repo in public_repos:
                            repo_name = repo.get('repositoryName')
                            repo_uri = repo.get('repositoryUri')
                            
                            findings.append({
                                'ResourceType': 'ECR Public Repository',
                                'ResourceId': repo_name,
                                'ResourceName': repo_name,
                                'ResourceUri': repo_uri,
                                'Region': 'us-east-1',
                                'Risk': 'MEDIUM',
                                'Issue': 'ECR repository is publicly accessible',
                                'Recommendation': 'Review if this repository should be public and consider making it private'
                            })
                            print(f"    [!] FINDING: Public ECR repository {repo_name} - MEDIUM risk")
            except (ClientError, boto3.exceptions.Boto3Error) as e:
                # Ignore errors for ECR Public service
                pass
            
            # Check private ECR repositories
            try:
                # Get repositories
                repositories = []
                paginator = ecr_client.get_paginator('describe_repositories')
                
                for page in paginator.paginate():
                    repositories.extend(page.get('repositories', []))
                
                if repositories:
                    total_repos_found += len(repositories)
                    print(f"  Found {len(repositories)} ECR repositories in {current_region}")
                    
                    for i, repo in enumerate(repositories, 1):
                        repo_name = repo.get('repositoryName')
                        repo_arn = repo.get('repositoryArn')
                        repo_uri = repo.get('repositoryUri')
                        
                        # Print progress every 10 repositories or for the last one
                        if i % 10 == 0 or i == len(repositories):
                            print(f"  Progress: {i}/{len(repositories)}")
                        
                        # Check repository policy
                        try:
                            policy = ecr_client.get_repository_policy(repositoryName=repo_name)
                            policy_text = policy.get('policyText', '')
                            
                            # Check for public access in policy
                            if '"Principal": "*"' in policy_text or '"Principal":{"AWS":"*"}' in policy_text:
                                findings.append({
                                    'ResourceType': 'ECR Repository',
                                    'ResourceId': repo_name,
                                    'ResourceName': repo_name,
                                    'ResourceArn': repo_arn,
                                    'ResourceUri': repo_uri,
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': 'ECR repository policy allows public access',
                                    'Recommendation': 'Review and restrict the repository policy'
                                })
                                print(f"    [!] FINDING: ECR repository {repo_name} policy allows public access - HIGH risk")
                        except ClientError as e:
                            if e.response['Error']['Code'] != 'RepositoryPolicyNotFoundException':
                                print(f"    Error checking repository policy for {repo_name}: {e}")
            
            except ClientError as e:
                print(f"  Error listing ECR repositories in {current_region}: {e}")
    
    except Exception as e:
        print(f"Error scanning ECR repositories: {e}")
    
    if total_repos_found == 0:
        print("No ECR repositories found.")
    else:
        print(f"ECR scan complete. Scanned {total_repos_found} repositories.")
    
    if findings:
        print(f"Found {len(findings)} ECR repository issues.")
    else:
        print("No ECR repository issues found.")
    
    return findings