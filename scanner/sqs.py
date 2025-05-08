"""
SQS Scanner Module - Detects security issues with Amazon SQS
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan_sqs(region=None):
    """
    Scan Amazon SQS for security issues like:
    - Queues with overly permissive policies
    - Unencrypted queues
    - Queues with cross-account access
    - Queues with public access
    - Dead letter queue configuration
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting SQS scan...")
    
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
        total_queues_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            sqs_client = boto3.client('sqs', region_name=current_region)
            
            try:
                # List all SQS queues
                response = sqs_client.list_queues()
                queue_urls = response.get('QueueUrls', [])
                
                # Handle pagination if needed
                while 'NextToken' in response:
                    response = sqs_client.list_queues(NextToken=response['NextToken'])
                    queue_urls.extend(response.get('QueueUrls', []))
                
                queues_count = len(queue_urls)
                
                if queues_count > 0:
                    total_queues_count += queues_count
                    print(f"  Found {queues_count} SQS queues in {current_region}")
                    
                    for i, queue_url in enumerate(queue_urls, 1):
                        queue_name = queue_url.split('/')[-1]
                        
                        # Print progress every 10 queues or for the last one
                        if i % 10 == 0 or i == queues_count:
                            print(f"  Progress: {i}/{queues_count}")
                        
                        # Get queue attributes
                        try:
                            attributes = sqs_client.get_queue_attributes(
                                QueueUrl=queue_url,
                                AttributeNames=['All']
                            )
                            
                            queue_attributes = attributes.get('Attributes', {})
                            policy = queue_attributes.get('Policy')
                            
                            # Check for encryption
                            if 'KmsMasterKeyId' not in queue_attributes:
                                findings.append({
                                    'ResourceType': 'SQS Queue',
                                    'ResourceId': queue_name,
                                    'ResourceName': queue_name,
                                    'ResourceArn': queue_attributes.get('QueueArn'),
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'SQS queue is not encrypted with KMS',
                                    'Recommendation': 'Enable server-side encryption with KMS for sensitive queues'
                                })
                                print(f"    [!] FINDING: SQS queue {queue_name} is not encrypted - MEDIUM risk")
                            
                            # Check for public access in policy
                            if policy and ('"Principal": "*"' in policy or '"Principal":{"AWS":"*"}' in policy):
                                findings.append({
                                    'ResourceType': 'SQS Queue',
                                    'ResourceId': queue_name,
                                    'ResourceName': queue_name,
                                    'ResourceArn': queue_attributes.get('QueueArn'),
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': 'SQS queue has a policy with public access (Principal: *)',
                                    'Recommendation': 'Restrict the queue policy to specific principals'
                                })
                                print(f"    [!] FINDING: SQS queue {queue_name} has public access policy - HIGH risk")
                            
                            # Check for cross-account access
                            if policy:
                                account_id = queue_attributes.get('QueueArn').split(':')[4]
                                if f'"AWS":"arn:aws:iam::{account_id}' not in policy and '"AWS":"*"' not in policy and '"Principal": "*"' not in policy:
                                    # This is a simplified check - in a real scenario, you'd parse the JSON policy
                                    findings.append({
                                        'ResourceType': 'SQS Queue',
                                        'ResourceId': queue_name,
                                        'ResourceName': queue_name,
                                        'ResourceArn': queue_attributes.get('QueueArn'),
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': 'SQS queue may have cross-account access configured',
                                        'Recommendation': 'Review the queue policy to ensure cross-account access is intended'
                                    })
                                    print(f"    [!] FINDING: SQS queue {queue_name} has potential cross-account access - MEDIUM risk")
                            
                            # Check for missing dead letter queue
                            if 'RedrivePolicy' not in queue_attributes:
                                findings.append({
                                    'ResourceType': 'SQS Queue',
                                    'ResourceId': queue_name,
                                    'ResourceName': queue_name,
                                    'ResourceArn': queue_attributes.get('QueueArn'),
                                    'Region': current_region,
                                    'Risk': 'LOW',
                                    'Issue': 'SQS queue does not have a dead letter queue configured',
                                    'Recommendation': 'Configure a dead letter queue to capture failed messages'
                                })
                                print(f"    [!] FINDING: SQS queue {queue_name} has no dead letter queue - LOW risk")
                            
                            # Check for high visibility timeout
                            visibility_timeout = int(queue_attributes.get('VisibilityTimeout', 30))
                            if visibility_timeout > 12 * 3600:  # 12 hours
                                findings.append({
                                    'ResourceType': 'SQS Queue',
                                    'ResourceId': queue_name,
                                    'ResourceName': queue_name,
                                    'ResourceArn': queue_attributes.get('QueueArn'),
                                    'Region': current_region,
                                    'Risk': 'LOW',
                                    'Issue': f'SQS queue has a very high visibility timeout ({visibility_timeout} seconds)',
                                    'Recommendation': 'Review the visibility timeout setting to ensure it is appropriate'
                                })
                                print(f"    [!] FINDING: SQS queue {queue_name} has high visibility timeout - LOW risk")
                        
                        except ClientError as e:
                            print(f"    Error checking queue {queue_name}: {e}")
                
                else:
                    print(f"  No SQS queues found in {current_region}")
            
            except ClientError as e:
                print(f"  Error scanning SQS in {current_region}: {e}")
        
        if total_queues_count == 0:
            print("No SQS queues found.")
        else:
            print(f"SQS scan complete. Scanned {total_queues_count} queues.")
    
    except Exception as e:
        print(f"Error scanning SQS: {e}")
    
    if findings:
        print(f"Found {len(findings)} SQS security issues.")
    else:
        print("No SQS security issues found.")
    
    return findings