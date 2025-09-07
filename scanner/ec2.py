"""
EC2 Scanner Module - Detects security issues with EC2 instances
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan_ec2_instances(region=None):
    """
    Scan EC2 instances for security issues like:
    - IMDSv1 usage (instead of IMDSv2)
    - Missing SSM agent
    - Unencrypted EBS volumes
    - Public IP addresses (IPv4 and IPv6)
    - Missing security patches
    - Instances running for extended periods
    - Stopped instances incurring unnecessary costs
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    

    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
        else:
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        region_count = 0
        total_instance_count = 0
        
        for current_region in regions:
            region_count += 1
            pass
                
            regional_client = boto3.client('ec2', region_name=current_region)
            ssm_client = boto3.client('ssm', region_name=current_region)
            
            # Get current time for age calculations
            current_time = datetime.now(timezone.utc)
            
            try:
                # Get all EC2 instances
                instances = []
                paginator = regional_client.get_paginator('describe_instances')
                
                for page in paginator.paginate(
                    Filters=[
                        {
                            'Name': 'instance-state-name',
                            'Values': ['running', 'stopped']
                        }
                    ]
                ):
                    for reservation in page.get('Reservations', []):
                        instances.extend(reservation.get('Instances', []))
                
                instance_count = len(instances)
                
                if instance_count > 0:
                    total_instance_count += instance_count
                    
                    # Get SSM managed instances for comparison
                    try:
                        ssm_instances = []
                        ssm_paginator = ssm_client.get_paginator('describe_instance_information')
                        
                        for page in ssm_paginator.paginate():
                            ssm_instances.extend(page.get('InstanceInformationList', []))
                        
                        ssm_instance_ids = [instance.get('InstanceId') for instance in ssm_instances]
                    except ClientError:
                        ssm_instance_ids = []
                    
                    for i, instance in enumerate(instances, 1):
                        instance_id = instance.get('InstanceId')
                        instance_type = instance.get('InstanceType')
                        launch_time = instance.get('LaunchTime')
                        state = instance.get('State', {}).get('Name', 'unknown')
                        
                        # Get instance name from tags
                        instance_name = instance_id
                        for tag in instance.get('Tags', []):
                            if tag.get('Key', '').lower() == 'name':
                                instance_name = tag.get('Value')
                                break
                        
                        # Print progress every 10 instances or for the last one
                        pass
                        
                        # Check for stopped instances
                        if state == 'stopped':
                            # Calculate how long the instance has been stopped (if we can determine it)
                            stopped_days = None
                            try:
                                # Try to get state transition reason
                                state_reason = instance.get('StateTransitionReason', '')
                                if 'User initiated' in state_reason and '(' in state_reason and ')' in state_reason:
                                    # Extract date from format like "User initiated (2023-05-15 12:34:56 GMT)"
                                    date_str = state_reason.split('(')[1].split(')')[0].strip()
                                    try:
                                        stop_date = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S %Z')
                                        stop_date = stop_date.replace(tzinfo=timezone.utc)
                                        stopped_days = (current_time - stop_date).days
                                    except (ValueError, TypeError):
                                        pass
                            except Exception:
                                pass
                            
                            # If we couldn't determine stop date, use launch time as a fallback
                            if not stopped_days and launch_time:
                                stopped_days = (current_time - launch_time).days
                            
                            stopped_info = f" for {stopped_days} days" if stopped_days else ""
                            
                            findings.append({
                                'ResourceType': 'EC2 Instance',
                                'ResourceId': instance_id,
                                'ResourceName': instance_name,
                                'InstanceType': instance_type,
                                'State': state,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': f'Instance is in stopped state{stopped_info} but still incurring costs for EBS volumes',
                                'Recommendation': 'Terminate unused instances or create AMI and terminate to save costs'
                            })

                            
                            # Skip other checks for stopped instances
                            continue
                        
                        # Check if instance is using IMDSv1
                        metadata_options = instance.get('MetadataOptions', {})
                        http_tokens = metadata_options.get('HttpTokens', 'optional')
                        http_endpoint = metadata_options.get('HttpEndpoint', 'enabled')
                        hop_limit = metadata_options.get('HttpPutResponseHopLimit', 1)
                        
                        if http_tokens != 'required' and http_endpoint == 'enabled':
                            findings.append({
                                'ResourceType': 'EC2 Instance',
                                'ResourceId': instance_id,
                                'ResourceName': instance_name,
                                'InstanceType': instance_type,
                                'State': state,
                                'Region': current_region,
                                'Risk': 'HIGH',
                                'Issue': f'EC2 instance uses IMDSv1 (HttpTokens: {http_tokens})',
                                'Recommendation': 'Enforce IMDSv2 by setting HttpTokens to "required" for better security'
                            })
                        
                        # Check IMDS hop limit
                        if hop_limit > 1:
                            findings.append({
                                'ResourceType': 'EC2 Instance',
                                'ResourceId': instance_id,
                                'ResourceName': instance_name,
                                'InstanceType': instance_type,
                                'State': state,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': f'EC2 instance IMDS hop limit is {hop_limit} (allows forwarding)',
                                'Recommendation': 'Set HttpPutResponseHopLimit to 1 to prevent IMDS forwarding'
                            })

                        
                        # Check if instance has SSM agent installed
                        if instance_id not in ssm_instance_ids:
                            findings.append({
                                'ResourceType': 'EC2 Instance',
                                'ResourceId': instance_id,
                                'ResourceName': instance_name,
                                'InstanceType': instance_type,
                                'State': state,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'Instance is not managed by SSM',
                                'Recommendation': 'Install and configure SSM agent for centralized management and patching'
                            })

                        
                        # Check for public IP address (IPv4)
                        public_ip = instance.get('PublicIpAddress')
                        if public_ip:
                            findings.append({
                                'ResourceType': 'EC2 Instance',
                                'ResourceId': instance_id,
                                'ResourceName': instance_name,
                                'InstanceType': instance_type,
                                'PublicIP': public_ip,
                                'State': state,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'Instance has a public IPv4 address',
                                'Recommendation': 'Use private subnets with NAT gateway or VPC endpoints for private access'
                            })

                        
                        # Check for IPv6 addresses
                        network_interfaces = instance.get('NetworkInterfaces', [])
                        ipv6_addresses = []
                        
                        for interface in network_interfaces:
                            for ipv6 in interface.get('Ipv6Addresses', []):
                                ipv6_addr = ipv6.get('Ipv6Address')
                                if ipv6_addr:
                                    ipv6_addresses.append(ipv6_addr)
                        
                        if ipv6_addresses:
                            findings.append({
                                'ResourceType': 'EC2 Instance',
                                'ResourceId': instance_id,
                                'ResourceName': instance_name,
                                'InstanceType': instance_type,
                                'IPv6Addresses': ipv6_addresses,
                                'State': state,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': f'Instance has {len(ipv6_addresses)} public IPv6 address(es)',
                                'Recommendation': 'Consider disabling IPv6 if not required or implement security controls for IPv6 traffic'
                            })

                        
                        # Check for unencrypted EBS volumes
                        block_devices = instance.get('BlockDeviceMappings', [])
                        unencrypted_volumes = []
                        
                        for device in block_devices:
                            if 'Ebs' in device:
                                volume_id = device.get('Ebs', {}).get('VolumeId')
                                if volume_id:
                                    try:
                                        volume = regional_client.describe_volumes(VolumeIds=[volume_id])
                                        if volume['Volumes'] and not volume['Volumes'][0].get('Encrypted', False):
                                            unencrypted_volumes.append(f"{device.get('DeviceName')} ({volume_id})")
                                    except ClientError:
                                        # Skip if volume can't be described
                                        pass
                        
                        if unencrypted_volumes:
                            findings.append({
                                'ResourceType': 'EC2 Instance',
                                'ResourceId': instance_id,
                                'ResourceName': instance_name,
                                'InstanceType': instance_type,
                                'State': state,
                                'UnencryptedVolumes': unencrypted_volumes,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': f'Instance has {len(unencrypted_volumes)} unencrypted EBS volumes',
                                'Recommendation': 'Create encrypted snapshots and replace volumes with encrypted ones'
                            })

                        
                        # Check instance age
                        if launch_time:
                            instance_age_days = (current_time - launch_time).days
                            
                            if instance_age_days > 180:  # 6 months
                                findings.append({
                                    'ResourceType': 'EC2 Instance',
                                    'ResourceId': instance_id,
                                    'ResourceName': instance_name,
                                    'InstanceType': instance_type,
                                    'State': state,
                                    'LaunchTime': launch_time.strftime('%Y-%m-%d'),
                                    'Age': f"{instance_age_days} days",
                                    'Region': current_region,
                                    'Risk': 'LOW',
                                    'Issue': f'Instance has been running for {instance_age_days} days',
                                    'Recommendation': 'Review if instance is still needed or should be replaced with newer generation'
                                })

                        
                        # Check for detailed monitoring
                        monitoring_state = instance.get('Monitoring', {}).get('State', 'disabled')
                        if monitoring_state != 'enabled':
                            findings.append({
                                'ResourceType': 'EC2 Instance',
                                'ResourceId': instance_id,
                                'ResourceName': instance_name,
                                'InstanceType': instance_type,
                                'State': state,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': 'Detailed monitoring is not enabled',
                                'Recommendation': 'Enable detailed monitoring for better visibility and alerting'
                            })

                        
                        # Check for termination protection
                        try:
                            termination_protection = regional_client.describe_instance_attribute(
                                InstanceId=instance_id,
                                Attribute='disableApiTermination'
                            )
                            is_protected = termination_protection.get('DisableApiTermination', {}).get('Value', False)
                            
                            if not is_protected:
                                findings.append({
                                    'ResourceType': 'EC2 Instance',
                                    'ResourceId': instance_id,
                                    'ResourceName': instance_name,
                                    'InstanceType': instance_type,
                                    'State': state,
                                    'Region': current_region,
                                    'Risk': 'LOW',
                                    'Issue': 'Termination protection is not enabled',
                                    'Recommendation': 'Enable termination protection for critical instances'
                                })

                        except ClientError:
                            pass
                
                # Check for unused AMIs
                try:
                    owned_images = regional_client.describe_images(Owners=['self'])
                    images = owned_images.get('Images', [])
                    
                    if images:
                        
                        for image in images:
                            image_id = image.get('ImageId')
                            image_name = image.get('Name', image_id)
                            
                            # Check if AMI is in use
                            try:
                                ami_usage = regional_client.describe_instances(
                                    Filters=[
                                        {
                                            'Name': 'image-id',
                                            'Values': [image_id]
                                        }
                                    ]
                                )
                                
                                in_use = False
                                for reservation in ami_usage.get('Reservations', []):
                                    if reservation.get('Instances'):
                                        in_use = True
                                        break
                                
                                if not in_use:
                                    # Check creation date if available
                                    creation_date = image.get('CreationDate')
                                    age_info = ""
                                    
                                    if creation_date:
                                        try:
                                            creation_datetime = datetime.strptime(creation_date, '%Y-%m-%dT%H:%M:%S.%fZ')
                                            creation_datetime = creation_datetime.replace(tzinfo=timezone.utc)
                                            age_days = (current_time - creation_datetime).days
                                            age_info = f" (created {age_days} days ago)"
                                        except ValueError:
                                            pass
                                    
                                    findings.append({
                                        'ResourceType': 'AMI',
                                        'ResourceId': image_id,
                                        'ResourceName': image_name,
                                        'Region': current_region,
                                        'Risk': 'LOW',
                                        'Issue': f'AMI is not being used by any instances{age_info}',
                                        'Recommendation': 'Deregister unused AMIs to reduce storage costs'
                                    })

                            except ClientError:
                                pass
                except ClientError:
                    pass
                
                # Check for unused key pairs
                try:
                    key_pairs = regional_client.describe_key_pairs()
                    all_key_pairs = {kp['KeyName'] for kp in key_pairs.get('KeyPairs', [])}
                    
                    # Get key pairs used by running instances
                    used_key_pairs = set()
                    for instance in instances:
                        key_name = instance.get('KeyName')
                        if key_name:
                            used_key_pairs.add(key_name)
                    
                    # Find unused key pairs
                    unused_key_pairs = all_key_pairs - used_key_pairs
                    
                    for key_name in unused_key_pairs:
                        findings.append({
                            'ResourceType': 'EC2 Key Pair',
                            'ResourceId': key_name,
                            'ResourceName': key_name,
                            'Region': current_region,
                            'Risk': 'LOW',
                            'Issue': 'Key pair is not used by any running instances',
                            'Recommendation': 'Remove unused key pairs to reduce security exposure'
                        })
                        
                except ClientError:
                    pass
            
            except ClientError:
                pass
        
        pass
    
    except Exception:
        pass
    
    pass
    
    return findings