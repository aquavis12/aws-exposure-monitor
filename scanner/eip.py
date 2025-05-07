"""
Elastic IP Scanner Module - Detects unused or improperly configured Elastic IPs
"""
import boto3
from botocore.exceptions import ClientError


def scan_elastic_ips(region=None):
    """
    Scan Elastic IPs for unused allocations or security issues
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting Elastic IP scan...")
    
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
        total_eip_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            regional_client = boto3.client('ec2', region_name=current_region)
            
            try:
                # Get all Elastic IPs
                addresses = regional_client.describe_addresses()
                eips = addresses.get('Addresses', [])
                eip_count = len(eips)
                
                if eip_count > 0:
                    total_eip_count += eip_count
                    print(f"  Found {eip_count} Elastic IPs in {current_region}")
                    
                    for i, eip in enumerate(eips, 1):
                        allocation_id = eip.get('AllocationId', 'Unknown')
                        public_ip = eip.get('PublicIp', 'Unknown')
                        
                        # Print progress every 10 EIPs or for the last one
                        if i % 10 == 0 or i == eip_count:
                            print(f"  Progress: {i}/{eip_count}")
                        
                        # Check if EIP is associated with a resource
                        if 'AssociationId' not in eip:
                            findings.append({
                                'ResourceType': 'Elastic IP',
                                'ResourceId': allocation_id,
                                'ResourceName': public_ip,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': 'Elastic IP is not associated with any resource',
                                'Recommendation': 'Associate the Elastic IP with a resource or release it to avoid charges'
                            })
                            print(f"    [!] FINDING: Elastic IP {public_ip} ({allocation_id}) is not associated with any resource - LOW risk")
                        
                        # Check if EIP is associated with an EC2 instance
                        if 'InstanceId' in eip:
                            instance_id = eip.get('InstanceId')
                            
                            # Check if the instance has a security group that allows public access
                            try:
                                instance = regional_client.describe_instances(InstanceIds=[instance_id])
                                for reservation in instance.get('Reservations', []):
                                    for inst in reservation.get('Instances', []):
                                        security_groups = inst.get('SecurityGroups', [])
                                        
                                        for sg in security_groups:
                                            sg_id = sg.get('GroupId')
                                            sg_name = sg.get('GroupName')
                                            
                                            # Get security group details
                                            sg_details = regional_client.describe_security_groups(GroupIds=[sg_id])
                                            for sg_detail in sg_details.get('SecurityGroups', []):
                                                for rule in sg_detail.get('IpPermissions', []):
                                                    # Check for sensitive ports
                                                    sensitive_ports = [22, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 9300]
                                                    from_port = rule.get('FromPort')
                                                    to_port = rule.get('ToPort')
                                                    
                                                    # Check if any IP ranges include 0.0.0.0/0
                                                    for ip_range in rule.get('IpRanges', []):
                                                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                                                            if from_port is not None and to_port is not None:
                                                                for port in range(from_port, to_port + 1):
                                                                    if port in sensitive_ports:
                                                                        findings.append({
                                                                            'ResourceType': 'Elastic IP with Vulnerable Instance',
                                                                            'ResourceId': public_ip,
                                                                            'ResourceName': f"{public_ip} (Instance: {instance_id})",
                                                                            'Region': current_region,
                                                                            'Risk': 'HIGH',
                                                                            'Issue': f'Elastic IP is attached to an instance with security group {sg_name} allowing public access to port {port}',
                                                                            'Recommendation': 'Restrict security group rules to specific IP ranges'
                                                                        })
                                                                        print(f"    [!] FINDING: Elastic IP {public_ip} attached to instance with open port {port} - HIGH risk")
                                                                        break
                                                            elif rule.get('IpProtocol') == '-1':  # All traffic
                                                                findings.append({
                                                                    'ResourceType': 'Elastic IP with Vulnerable Instance',
                                                                    'ResourceId': public_ip,
                                                                    'ResourceName': f"{public_ip} (Instance: {instance_id})",
                                                                    'Region': current_region,
                                                                    'Risk': 'CRITICAL',
                                                                    'Issue': f'Elastic IP is attached to an instance with security group {sg_name} allowing public access to ALL ports',
                                                                    'Recommendation': 'Restrict security group rules to specific ports and IP ranges'
                                                                })
                                                                print(f"    [!] FINDING: Elastic IP {public_ip} attached to instance with ALL ports open - CRITICAL risk")
                            except ClientError as e:
                                print(f"    Error checking instance {instance_id}: {e}")
            
            except ClientError as e:
                print(f"  Error scanning Elastic IPs in {current_region}: {e}")
        
        if total_eip_count == 0:
            print("No Elastic IPs found.")
        else:
            print(f"Elastic IP scan complete. Scanned {total_eip_count} Elastic IPs.")
    
    except Exception as e:
        print(f"Error scanning Elastic IPs: {e}")
    
    if findings:
        print(f"Found {len(findings)} Elastic IP issues.")
    else:
        print("No Elastic IP issues found.")
    
    return findings