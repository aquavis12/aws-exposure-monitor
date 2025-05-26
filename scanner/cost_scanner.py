"""
AWS Cost Scanner Module - Detects cost optimization opportunities and provides cost analysis
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta, date
import calendar

def scan_cost_optimization(region=None):
    """
    Scan AWS resources for cost optimization opportunities
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing cost optimization findings
    """
    findings = []
    
    print("Starting AWS cost optimization scan...")
    
    # Combine findings from all cost scanners
    ec2_findings = scan_ec2_costs(region)
    findings.extend(ec2_findings)
    
    ebs_findings = scan_ebs_costs(region)
    findings.extend(ebs_findings)
    
    rds_findings = scan_rds_costs(region)
    findings.extend(rds_findings)
    
    s3_findings = scan_s3_costs(region)
    findings.extend(s3_findings)
    
    eip_findings = scan_eip_costs(region)
    findings.extend(eip_findings)
    
    # Import cost explorer scanner
    try:
        from scanner.cost_explorer import scan_cost_explorer, scan_budgets
        
        # Add cost explorer findings
        cost_explorer_findings = scan_cost_explorer()
        findings.extend(cost_explorer_findings)
        
        # Add budget findings
        budget_findings = scan_budgets()
        findings.extend(budget_findings)
    except ImportError:
        print("Cost Explorer scanner module not available")
    
    print(f"Cost optimization scan complete. Found {len(findings)} opportunities.")
    return findings

def scan_ec2_costs(region=None):
    """
    Scan EC2 instances for cost optimization opportunities
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing cost optimization findings
    """
    findings = []
    
    print("Scanning EC2 instances for cost optimization...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
        
        for current_region in regions:
            print(f"Scanning EC2 instances in region: {current_region}")
            
            try:
                ec2_client = boto3.client('ec2', region_name=current_region)
                cloudwatch = boto3.client('cloudwatch', region_name=current_region)
                
                # Get all instances
                paginator = ec2_client.get_paginator('describe_instances')
                instances = []
                
                for page in paginator.paginate():
                    for reservation in page['Reservations']:
                        instances.extend(reservation['Instances'])
                
                print(f"  Found {len(instances)} EC2 instances in {current_region}")
                
                # Check each instance
                for instance in instances:
                    instance_id = instance['InstanceId']
                    instance_type = instance['InstanceType']
                    state = instance['State']['Name']
                    
                    # Skip terminated instances
                    if state == 'terminated':
                        continue
                    
                    # Get instance name tag
                    instance_name = instance_id
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break
                    
                    # Check for stopped instances
                    if state == 'stopped':
                        # Get stop time if available
                        stop_time = None
                        try:
                            response = ec2_client.describe_instance_status(
                                InstanceIds=[instance_id],
                                IncludeAllInstances=True
                            )
                            for status in response['InstanceStatuses']:
                                if status['InstanceId'] == instance_id and 'Events' in status:
                                    for event in status['Events']:
                                        if event['Code'] == 'instance-stop':
                                            stop_time = event['NotBefore']
                                            break
                        except Exception:
                            pass
                        
                        stop_message = f" since {stop_time}" if stop_time else ""
                        findings.append({
                            'ResourceType': 'EC2 Instance',
                            'ResourceId': instance_id,
                            'ResourceName': instance_name,
                            'Region': current_region,
                            'Risk': 'LOW',
                            'Issue': f'EC2 instance is stopped{stop_message} but still incurring EBS costs',
                            'Recommendation': 'Consider terminating the instance if no longer needed or creating an AMI and terminating the instance'
                        })
                        print(f"    [!] FINDING: EC2 instance {instance_id} ({instance_name}) is stopped but incurring EBS costs")
                        continue
                    
                    # Check for low CPU utilization
                    if state == 'running':
                        try:
                            end_time = datetime.utcnow()
                            start_time = end_time - timedelta(days=14)  # Check last 14 days
                            
                            response = cloudwatch.get_metric_statistics(
                                Namespace='AWS/EC2',
                                MetricName='CPUUtilization',
                                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                                StartTime=start_time,
                                EndTime=end_time,
                                Period=86400,  # 1 day in seconds
                                Statistics=['Average']
                            )
                            
                            if response['Datapoints']:
                                # Calculate average CPU utilization
                                avg_cpu = sum(point['Average'] for point in response['Datapoints']) / len(response['Datapoints'])
                                
                                if avg_cpu < 5.0:  # Very low utilization threshold
                                    findings.append({
                                        'ResourceType': 'EC2 Instance',
                                        'ResourceId': instance_id,
                                        'ResourceName': instance_name,
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': f'EC2 instance has very low CPU utilization (avg {avg_cpu:.2f}% over 14 days)',
                                        'Recommendation': 'Consider downsizing the instance or using a burstable instance type'
                                    })
                                    print(f"    [!] FINDING: EC2 instance {instance_id} ({instance_name}) has very low CPU utilization ({avg_cpu:.2f}%)")
                                elif avg_cpu < 10.0:  # Low utilization threshold
                                    findings.append({
                                        'ResourceType': 'EC2 Instance',
                                        'ResourceId': instance_id,
                                        'ResourceName': instance_name,
                                        'Region': current_region,
                                        'Risk': 'LOW',
                                        'Issue': f'EC2 instance has low CPU utilization (avg {avg_cpu:.2f}% over 14 days)',
                                        'Recommendation': 'Consider downsizing the instance or using a burstable instance type'
                                    })
                                    print(f"    [!] FINDING: EC2 instance {instance_id} ({instance_name}) has low CPU utilization ({avg_cpu:.2f}%)")
                        except Exception as e:
                            print(f"    Error getting CPU metrics for instance {instance_id}: {e}")
                    
                    # Check for missing Savings Plan or Reserved Instance
                    if state == 'running':
                        # This is a simplified check - in a real implementation, you would check against actual Savings Plans and RIs
                        has_savings_tag = False
                        for tag in instance.get('Tags', []):
                            if tag['Key'].lower() in ['savings-plan', 'reserved-instance', 'ri']:
                                has_savings_tag = True
                                break
                        
                        if not has_savings_tag:
                            findings.append({
                                'ResourceType': 'EC2 Instance',
                                'ResourceId': instance_id,
                                'ResourceName': instance_name,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': 'EC2 instance may not be covered by Savings Plan or Reserved Instance',
                                'Recommendation': 'Consider purchasing Savings Plans or Reserved Instances for long-running instances'
                            })
                            print(f"    [!] FINDING: EC2 instance {instance_id} ({instance_name}) may not be covered by Savings Plan or RI")
            
            except Exception as e:
                print(f"  Error scanning EC2 in {current_region}: {e}")
    
    except Exception as e:
        print(f"Error scanning EC2 for cost optimization: {e}")
    
    return findings

def scan_ebs_costs(region=None):
    """
    Scan EBS volumes for cost optimization opportunities
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing cost optimization findings
    """
    findings = []
    
    print("Scanning EBS volumes for cost optimization...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
        
        for current_region in regions:
            print(f"Scanning EBS volumes in region: {current_region}")
            
            try:
                ec2_client = boto3.client('ec2', region_name=current_region)
                
                # Get all volumes
                paginator = ec2_client.get_paginator('describe_volumes')
                volumes = []
                
                for page in paginator.paginate():
                    volumes.extend(page['Volumes'])
                
                print(f"  Found {len(volumes)} EBS volumes in {current_region}")
                
                # Check each volume
                for volume in volumes:
                    volume_id = volume['VolumeId']
                    volume_size = volume['Size']
                    volume_type = volume['VolumeType']
                    state = volume['State']
                    
                    # Get volume name tag
                    volume_name = volume_id
                    for tag in volume.get('Tags', []):
                        if tag['Key'] == 'Name':
                            volume_name = tag['Value']
                            break
                    
                    # Check for unattached volumes
                    if not volume.get('Attachments'):
                        findings.append({
                            'ResourceType': 'EBS Volume',
                            'ResourceId': volume_id,
                            'ResourceName': volume_name,
                            'Region': current_region,
                            'Risk': 'MEDIUM',
                            'Issue': f'Unattached EBS volume of {volume_size} GB ({volume_type})',
                            'Recommendation': 'Delete unattached EBS volumes or attach them to instances if needed'
                        })
                        print(f"    [!] FINDING: EBS volume {volume_id} ({volume_name}) is unattached")
                    
                    # Check for over-provisioned gp2 volumes
                    if volume_type == 'gp2' and volume_size > 1000:
                        findings.append({
                            'ResourceType': 'EBS Volume',
                            'ResourceId': volume_id,
                            'ResourceName': volume_name,
                            'Region': current_region,
                            'Risk': 'LOW',
                            'Issue': f'Large gp2 EBS volume of {volume_size} GB',
                            'Recommendation': 'Consider using gp3 volume type for better performance and lower cost'
                        })
                        print(f"    [!] FINDING: EBS volume {volume_id} ({volume_name}) is a large gp2 volume")
                    
                    # Check for over-provisioned io1/io2 volumes
                    if volume_type in ['io1', 'io2'] and 'Iops' in volume:
                        iops = volume['Iops']
                        iops_ratio = iops / volume_size
                        
                        if iops_ratio < 10:  # Low IOPS to size ratio
                            findings.append({
                                'ResourceType': 'EBS Volume',
                                'ResourceId': volume_id,
                                'ResourceName': volume_name,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': f'{volume_type} EBS volume with low IOPS to size ratio ({iops} IOPS for {volume_size} GB)',
                                'Recommendation': 'Consider using gp3 volume type for better cost efficiency'
                            })
                            print(f"    [!] FINDING: EBS volume {volume_id} ({volume_name}) has low IOPS to size ratio")
            
            except Exception as e:
                print(f"  Error scanning EBS in {current_region}: {e}")
    
    except Exception as e:
        print(f"Error scanning EBS for cost optimization: {e}")
    
    return findings

def scan_rds_costs(region=None):
    """
    Scan RDS instances for cost optimization opportunities
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing cost optimization findings
    """
    findings = []
    
    print("Scanning RDS instances for cost optimization...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
        
        for current_region in regions:
            print(f"Scanning RDS instances in region: {current_region}")
            
            try:
                rds_client = boto3.client('rds', region_name=current_region)
                cloudwatch = boto3.client('cloudwatch', region_name=current_region)
                
                # Get all DB instances
                paginator = rds_client.get_paginator('describe_db_instances')
                db_instances = []
                
                for page in paginator.paginate():
                    db_instances.extend(page['DBInstances'])
                
                print(f"  Found {len(db_instances)} RDS instances in {current_region}")
                
                # Check each DB instance
                for db in db_instances:
                    db_id = db['DBInstanceIdentifier']
                    db_class = db['DBInstanceClass']
                    engine = db['Engine']
                    status = db['DBInstanceStatus']
                    
                    # Check for stopped instances
                    if status == 'stopped':
                        findings.append({
                            'ResourceType': 'RDS Instance',
                            'ResourceId': db_id,
                            'ResourceName': db_id,
                            'Region': current_region,
                            'Risk': 'LOW',
                            'Issue': 'RDS instance is stopped but still incurring storage costs',
                            'Recommendation': 'Consider taking a final snapshot and deleting the instance if no longer needed'
                        })
                        print(f"    [!] FINDING: RDS instance {db_id} is stopped but incurring storage costs")
                        continue
                    
                    # Check for low CPU utilization
                    if status == 'available':
                        try:
                            end_time = datetime.utcnow()
                            start_time = end_time - timedelta(days=14)  # Check last 14 days
                            
                            response = cloudwatch.get_metric_statistics(
                                Namespace='AWS/RDS',
                                MetricName='CPUUtilization',
                                Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_id}],
                                StartTime=start_time,
                                EndTime=end_time,
                                Period=86400,  # 1 day in seconds
                                Statistics=['Average']
                            )
                            
                            if response['Datapoints']:
                                # Calculate average CPU utilization
                                avg_cpu = sum(point['Average'] for point in response['Datapoints']) / len(response['Datapoints'])
                                
                                if avg_cpu < 5.0:  # Very low utilization threshold
                                    findings.append({
                                        'ResourceType': 'RDS Instance',
                                        'ResourceId': db_id,
                                        'ResourceName': db_id,
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': f'RDS instance has very low CPU utilization (avg {avg_cpu:.2f}% over 14 days)',
                                        'Recommendation': 'Consider downsizing the instance or using a burstable instance class'
                                    })
                                    print(f"    [!] FINDING: RDS instance {db_id} has very low CPU utilization ({avg_cpu:.2f}%)")
                                elif avg_cpu < 10.0:  # Low utilization threshold
                                    findings.append({
                                        'ResourceType': 'RDS Instance',
                                        'ResourceId': db_id,
                                        'ResourceName': db_id,
                                        'Region': current_region,
                                        'Risk': 'LOW',
                                        'Issue': f'RDS instance has low CPU utilization (avg {avg_cpu:.2f}% over 14 days)',
                                        'Recommendation': 'Consider downsizing the instance or using a burstable instance class'
                                    })
                                    print(f"    [!] FINDING: RDS instance {db_id} has low CPU utilization ({avg_cpu:.2f}%)")
                        except Exception as e:
                            print(f"    Error getting CPU metrics for RDS instance {db_id}: {e}")
                    
                    # Check for missing Reserved Instance
                    if status == 'available':
                        # This is a simplified check - in a real implementation, you would check against actual RIs
                        has_ri_tag = False
                        for tag in db.get('TagList', []):
                            if tag['Key'].lower() in ['reserved-instance', 'ri']:
                                has_ri_tag = True
                                break
                        
                        if not has_ri_tag:
                            findings.append({
                                'ResourceType': 'RDS Instance',
                                'ResourceId': db_id,
                                'ResourceName': db_id,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': 'RDS instance may not be covered by Reserved Instance',
                                'Recommendation': 'Consider purchasing Reserved Instances for long-running RDS instances'
                            })
                            print(f"    [!] FINDING: RDS instance {db_id} may not be covered by Reserved Instance")
                    
                    # Check for Multi-AZ in non-production environments
                    if db.get('MultiAZ', False):
                        is_prod = False
                        for tag in db.get('TagList', []):
                            if tag['Key'].lower() in ['environment', 'env'] and tag['Value'].lower() in ['prod', 'production']:
                                is_prod = True
                                break
                        
                        if not is_prod:
                            findings.append({
                                'ResourceType': 'RDS Instance',
                                'ResourceId': db_id,
                                'ResourceName': db_id,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': 'Non-production RDS instance is using Multi-AZ deployment',
                                'Recommendation': 'Consider disabling Multi-AZ for non-production environments to reduce costs'
                            })
                            print(f"    [!] FINDING: Non-production RDS instance {db_id} is using Multi-AZ")
            
            except Exception as e:
                print(f"  Error scanning RDS in {current_region}: {e}")
    
    except Exception as e:
        print(f"Error scanning RDS for cost optimization: {e}")
    
    return findings

def scan_s3_costs(region=None):
    """
    Scan S3 buckets for cost optimization opportunities
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing cost optimization findings
    """
    findings = []
    
    print("Scanning S3 buckets for cost optimization...")
    
    try:
        # S3 is a global service, but we can filter by region
        s3_client = boto3.client('s3')
        
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
            print(f"Found {len(buckets)} S3 buckets in region {region}")
        else:
            buckets = all_buckets
            print(f"Found {len(buckets)} S3 buckets across all regions")
        
        for i, bucket in enumerate(buckets, 1):
            bucket_name = bucket['Name']
            
            try:
                # Get bucket location
                location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = location_response.get('LocationConstraint') or 'us-east-1'
                
                print(f"[{i}/{len(buckets)}] Scanning bucket: {bucket_name} in {bucket_region}")
                
                # Check for lifecycle policies
                try:
                    lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                    has_transition_rule = False
                    has_expiration_rule = False
                    
                    for rule in lifecycle.get('Rules', []):
                        if rule.get('Status') == 'Enabled':
                            if 'Transitions' in rule:
                                has_transition_rule = True
                            if 'Expiration' in rule:
                                has_expiration_rule = True
                    
                    if not has_transition_rule:
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'LOW',
                            'Issue': 'S3 bucket has no lifecycle transition rules',
                            'Recommendation': 'Configure lifecycle rules to transition objects to cheaper storage classes'
                        })
                        print(f"    [!] FINDING: S3 bucket {bucket_name} has no lifecycle transition rules")
                    
                    if not has_expiration_rule:
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'LOW',
                            'Issue': 'S3 bucket has no lifecycle expiration rules',
                            'Recommendation': 'Configure lifecycle rules to expire old objects that are no longer needed'
                        })
                        print(f"    [!] FINDING: S3 bucket {bucket_name} has no lifecycle expiration rules")
                
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'S3 bucket has no lifecycle configuration',
                            'Recommendation': 'Configure lifecycle rules to optimize storage costs'
                        })
                        print(f"    [!] FINDING: S3 bucket {bucket_name} has no lifecycle configuration")
                    else:
                        print(f"    Error checking lifecycle configuration: {e}")
                
                # Check for Intelligent-Tiering
                try:
                    tiering = s3_client.get_bucket_intelligent_tiering_configuration(
                        Bucket=bucket_name,
                        Id="default"  # Adding required Id parameter
                    )
                    if not tiering.get('IntelligentTieringConfiguration'):
                        findings.append({
                            'ResourceType': 'S3 Bucket',
                            'ResourceId': bucket_name,
                            'ResourceName': bucket_name,
                            'Region': bucket_region,
                            'Risk': 'LOW',
                            'Issue': 'S3 bucket is not using Intelligent-Tiering',
                            'Recommendation': 'Consider enabling S3 Intelligent-Tiering for automatic cost optimization'
                        })
                        print(f"    [!] FINDING: S3 bucket {bucket_name} is not using Intelligent-Tiering")
                except ClientError:
                    # Intelligent-Tiering might not be supported or configured
                    pass
            
            except Exception as e:
                print(f"  Error scanning bucket {bucket_name}: {e}")
    
    except Exception as e:
        print(f"Error scanning S3 for cost optimization: {e}")
    
    return findings

def scan_eip_costs(region=None):
    """
    Scan Elastic IPs for cost optimization opportunities
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing cost optimization findings
    """
    findings = []
    
    print("Scanning Elastic IPs for cost optimization...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
        
        for current_region in regions:
            print(f"Scanning Elastic IPs in region: {current_region}")
            
            try:
                ec2_client = boto3.client('ec2', region_name=current_region)
                
                # Get all Elastic IPs
                addresses = ec2_client.describe_addresses()['Addresses']
                print(f"  Found {len(addresses)} Elastic IPs in {current_region}")
                
                # Check for unassociated Elastic IPs
                for address in addresses:
                    if 'AssociationId' not in address:
                        eip = address.get('PublicIp', 'Unknown')
                        allocation_id = address.get('AllocationId', 'Unknown')
                        
                        findings.append({
                            'ResourceType': 'Elastic IP',
                            'ResourceId': allocation_id,
                            'ResourceName': eip,
                            'Region': current_region,
                            'Risk': 'MEDIUM',
                            'Issue': 'Unassociated Elastic IP address',
                            'Recommendation': 'Release unused Elastic IPs to avoid charges'
                        })
                        print(f"    [!] FINDING: Unassociated Elastic IP {eip} in {current_region}")
            
            except Exception as e:
                print(f"  Error scanning Elastic IPs in {current_region}: {e}")
    
    except Exception as e:
        print(f"Error scanning Elastic IPs for cost optimization: {e}")
    
    return findings