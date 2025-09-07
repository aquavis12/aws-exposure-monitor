"""
EKS Scanner Module - Detects security issues with Amazon EKS clusters
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta

def scan_eks(region=None):
    """
    Scan Amazon EKS clusters for security issues
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    try:
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        for current_region in regions:
            eks_client = boto3.client('eks', region_name=current_region)
            
            try:
                # List EKS clusters
                clusters = eks_client.list_clusters()
                
                for cluster_name in clusters.get('clusters', []):
                    try:
                        cluster = eks_client.describe_cluster(name=cluster_name)['cluster']
                        cluster_arn = cluster.get('arn')
                        
                        # Check cluster version
                        version = cluster.get('version')
                        if version and float(version) < 1.28:
                            findings.append({
                                'ResourceType': 'EKS Cluster',
                                'ResourceId': cluster_name,
                                'ResourceName': cluster_name,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': f'EKS cluster running outdated Kubernetes version {version}',
                                'Recommendation': 'Upgrade to latest supported Kubernetes version'
                            })
                        
                        # Check endpoint access
                        endpoint_config = cluster.get('resourcesVpcConfig', {})
                        if endpoint_config.get('endpointPublicAccess') and not endpoint_config.get('publicAccessCidrs'):
                            findings.append({
                                'ResourceType': 'EKS Cluster',
                                'ResourceId': cluster_name,
                                'ResourceName': cluster_name,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'EKS cluster API endpoint is publicly accessible without CIDR restrictions',
                                'Recommendation': 'Restrict public access CIDRs or disable public endpoint access'
                            })
                        elif endpoint_config.get('endpointPublicAccess') and '0.0.0.0/0' in endpoint_config.get('publicAccessCidrs', []):
                            findings.append({
                                'ResourceType': 'EKS Cluster',
                                'ResourceId': cluster_name,
                                'ResourceName': cluster_name,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': 'EKS cluster API endpoint allows access from anywhere (0.0.0.0/0)',
                                'Recommendation': 'Restrict public access to specific IP ranges'
                            })
                        
                        # Check logging
                        logging = cluster.get('logging', {})
                        enabled_logs = logging.get('clusterLogging', [])
                        log_types = [log.get('types', []) for log in enabled_logs if log.get('enabled')]
                        all_log_types = [item for sublist in log_types for item in sublist]
                        
                        required_logs = ['api', 'audit', 'authenticator']
                        missing_logs = [log for log in required_logs if log not in all_log_types]
                        
                        if missing_logs:
                            findings.append({
                                'ResourceType': 'EKS Cluster',
                                'ResourceId': cluster_name,
                                'ResourceName': cluster_name,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': f'EKS cluster missing critical log types: {", ".join(missing_logs)}',
                                'Recommendation': 'Enable all log types for security monitoring'
                            })
                        
                        # Check encryption
                        encryption_config = cluster.get('encryptionConfig', [])
                        if not encryption_config:
                            findings.append({
                                'ResourceType': 'EKS Cluster',
                                'ResourceId': cluster_name,
                                'ResourceName': cluster_name,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'EKS cluster secrets are not encrypted at rest',
                                'Recommendation': 'Enable envelope encryption for Kubernetes secrets'
                            })
                        
                        # Check node groups
                        try:
                            nodegroups = eks_client.list_nodegroups(clusterName=cluster_name)
                            for ng_name in nodegroups.get('nodegroups', []):
                                try:
                                    ng = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)['nodegroup']
                                    
                                    # Check if nodes are in public subnets
                                    subnets = ng.get('subnets', [])
                                    ec2 = boto3.client('ec2', region_name=current_region)
                                    
                                    for subnet_id in subnets:
                                        try:
                                            subnet = ec2.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
                                            if subnet.get('MapPublicIpOnLaunch'):
                                                findings.append({
                                                    'ResourceType': 'EKS Node Group',
                                                    'ResourceId': f"{cluster_name}/{ng_name}",
                                                    'ResourceName': f"{cluster_name} - {ng_name}",
                                                    'Region': current_region,
                                                    'Risk': 'HIGH',
                                                    'Issue': 'EKS node group uses public subnets',
                                                    'Recommendation': 'Use private subnets for worker nodes'
                                                })
                                                break
                                        except ClientError:
                                            pass
                                    
                                    # Check AMI type for security
                                    ami_type = ng.get('amiType', '')
                                    if 'AL2' not in ami_type and 'BOTTLEROCKET' not in ami_type:
                                        findings.append({
                                            'ResourceType': 'EKS Node Group',
                                            'ResourceId': f"{cluster_name}/{ng_name}",
                                            'ResourceName': f"{cluster_name} - {ng_name}",
                                            'Region': current_region,
                                            'Risk': 'MEDIUM',
                                            'Issue': f'EKS node group uses non-optimized AMI type: {ami_type}',
                                            'Recommendation': 'Use Amazon Linux 2 or Bottlerocket AMIs for better security'
                                        })
                                        
                                except ClientError:
                                    pass
                        except ClientError:
                            pass
                            
                    except ClientError:
                        pass
                        
            except ClientError:
                pass
                
    except Exception:
        pass
    
    return findings