"""
SNS Scanner Module - Detects security issues with Amazon SNS
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan_sns(region=None):
    """
    Scan Amazon SNS for security issues like:
    - Topics with overly permissive policies
    - Unencrypted topics
    - Topics with cross-account access
    - Topics with public access
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting SNS scan...")
    
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
        total_topics_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            sns_client = boto3.client('sns', region_name=current_region)
            
            try:
                # List all SNS topics
                topics = []
                paginator = sns_client.get_paginator('list_topics')
                
                for page in paginator.paginate():
                    topics.extend(page.get('Topics', []))
                
                topics_count = len(topics)
                
                if topics_count > 0:
                    total_topics_count += topics_count
                    print(f"  Found {topics_count} SNS topics in {current_region}")
                    
                    for i, topic in enumerate(topics, 1):
                        topic_arn = topic.get('TopicArn')
                        topic_name = topic_arn.split(':')[-1] if topic_arn else "Unknown"
                        
                        # Print progress every 10 topics or for the last one
                        if i % 10 == 0 or i == topics_count:
                            print(f"  Progress: {i}/{topics_count}")
                        
                        # Check topic attributes
                        try:
                            attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)
                            policy = attributes.get('Attributes', {}).get('Policy')
                            
                            # Check for encryption
                            if 'KmsMasterKeyId' not in attributes.get('Attributes', {}):
                                findings.append({
                                    'ResourceType': 'SNS Topic',
                                    'ResourceId': topic_name,
                                    'ResourceName': topic_name,
                                    'ResourceArn': topic_arn,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'SNS topic is not encrypted with KMS',
                                    'Recommendation': 'Enable server-side encryption with KMS for sensitive topics'
                                })
                                print(f"    [!] FINDING: SNS topic {topic_name} is not encrypted - MEDIUM risk")
                            
                            # Check for public access in policy
                            if policy and ('"Principal": "*"' in policy or '"Principal":{"AWS":"*"}' in policy):
                                findings.append({
                                    'ResourceType': 'SNS Topic',
                                    'ResourceId': topic_name,
                                    'ResourceName': topic_name,
                                    'ResourceArn': topic_arn,
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': 'SNS topic has a policy with public access (Principal: *)',
                                    'Recommendation': 'Restrict the topic policy to specific principals'
                                })
                                print(f"    [!] FINDING: SNS topic {topic_name} has public access policy - HIGH risk")
                            
                            # Check for cross-account access
                            if policy:
                                account_id = topic_arn.split(':')[4]
                                if f'"AWS":"arn:aws:iam::{account_id}' not in policy and '"AWS":"*"' not in policy and '"Principal": "*"' not in policy:
                                    # This is a simplified check - in a real scenario, you'd parse the JSON policy
                                    findings.append({
                                        'ResourceType': 'SNS Topic',
                                        'ResourceId': topic_name,
                                        'ResourceName': topic_name,
                                        'ResourceArn': topic_arn,
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': 'SNS topic may have cross-account access configured',
                                        'Recommendation': 'Review the topic policy to ensure cross-account access is intended'
                                    })
                                    print(f"    [!] FINDING: SNS topic {topic_name} has potential cross-account access - MEDIUM risk")
                            
                            # Check for HTTPS-only delivery policy
                            delivery_policy = attributes.get('Attributes', {}).get('DeliveryPolicy')
                            if delivery_policy and 'http' in delivery_policy.lower() and 'https' not in delivery_policy.lower():
                                findings.append({
                                    'ResourceType': 'SNS Topic',
                                    'ResourceId': topic_name,
                                    'ResourceName': topic_name,
                                    'ResourceArn': topic_arn,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'SNS topic may allow HTTP (non-encrypted) delivery',
                                    'Recommendation': 'Configure delivery policy to use HTTPS only'
                                })
                                print(f"    [!] FINDING: SNS topic {topic_name} may allow HTTP delivery - MEDIUM risk")
                        
                        except ClientError as e:
                            print(f"    Error checking topic {topic_name}: {e}")
                
                else:
                    print(f"  No SNS topics found in {current_region}")
            
            except ClientError as e:
                print(f"  Error scanning SNS in {current_region}: {e}")
        
        if total_topics_count == 0:
            print("No SNS topics found.")
        else:
            print(f"SNS scan complete. Scanned {total_topics_count} topics.")
    
    except Exception as e:
        print(f"Error scanning SNS: {e}")
    
    if findings:
        print(f"Found {len(findings)} SNS security issues.")
    else:
        print("No SNS security issues found.")
    
    return findings