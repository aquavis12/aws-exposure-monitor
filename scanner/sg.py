"""
Security Group Scanner Module - Detects security groups with open access to sensitive ports
"""
import boto3
from botocore.exceptions import ClientError
import sys


def scan_security_groups(region=None):
    """
    Scan security groups for rules allowing public access to sensitive ports
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    # Define sensitive ports and their services
    sensitive_ports = {
        22: 'SSH',
        3389: 'RDP',
        1433: 'MSSQL',
        3306: 'MySQL/MariaDB',
        5432: 'PostgreSQL',
        27017: 'MongoDB',
        6379: 'Redis',
        9200: 'Elasticsearch',
        9300: 'Elasticsearch',
        8080: 'HTTP Alt',
        8443: 'HTTPS Alt',
        23: 'Telnet',
        21: 'FTP',
        20: 'FTP Data',
        25: 'SMTP',
        53: 'DNS',
        161: 'SNMP',
        389: 'LDAP',
        636: 'LDAPS',
        445: 'SMB',
        137: 'NetBIOS',
        138: 'NetBIOS',
        139: 'NetBIOS',
        11211: 'Memcached',
        2049: 'NFS',
        5601: 'Kibana',
        9090: 'Prometheus',
        3000: 'Grafana'
    }
    
    print("Starting security group scan...")
    
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
        total_sg_count = 0
        regions_with_sgs = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            regional_client = boto3.client('ec2', region_name=current_region)
            
            try:
                # Get all security groups
                security_groups = regional_client.describe_security_groups()
                sg_list = security_groups.get('SecurityGroups', [])
                
                # Filter out default security groups
                non_default_sg = [sg for sg in sg_list if sg['GroupName'] != 'default']
                sg_count = len(non_default_sg)
                
                if sg_count > 0:
                    total_sg_count += sg_count
                    regions_with_sgs += 1
                    print(f"  Scanning {sg_count} non-default security groups in {current_region}")
                
                    sg_index = 0
                    for sg in non_default_sg:
                        sg_index += 1
                        sg_id = sg['GroupId']
                        sg_name = sg['GroupName']
                        sg_description = sg.get('Description', '')
                        vpc_id = sg.get('VpcId', 'default')
                        
                        # Print progress every 10 security groups or for the last one
                        if sg_index % 10 == 0 or sg_index == sg_count:
                            print(f"  Progress: {sg_index}/{sg_count}")
                        
                        # Get associated resources for context
                        associated_resources = []
                        try:
                            # Find EC2 instances using this security group
                            instances = regional_client.describe_instances(
                                Filters=[{'Name': 'instance.group-id', 'Values': [sg_id]}]
                            )
                            
                            for reservation in instances.get('Reservations', []):
                                for instance in reservation.get('Instances', []):
                                    instance_id = instance.get('InstanceId')
                                    instance_name = "Unknown"
                                    # Get instance name from tags
                                    for tag in instance.get('Tags', []):
                                        if tag.get('Key') == 'Name':
                                            instance_name = tag.get('Value')
                                            break
                                    
                                    if instance_id:
                                        associated_resources.append(f"EC2:{instance_id} ({instance_name})")
                        except Exception:
                            # Silently handle errors getting associated resources
                            pass
                        
                        # Check inbound rules
                        for rule in sg.get('IpPermissions', []):
                            from_port = rule.get('FromPort')
                            to_port = rule.get('ToPort')
                            ip_protocol = rule.get('IpProtocol', 'tcp')
                            
                            # Check if any IP ranges include 0.0.0.0/0 or ::/0 (IPv6)
                            public_access = False
                            public_cidr = None
                            
                            for ip_range in rule.get('IpRanges', []):
                                cidr = ip_range.get('CidrIp')
                                if cidr == '0.0.0.0/0':
                                    public_access = True
                                    public_cidr = cidr
                                    break
                            
                            if not public_access:
                                for ip_range in rule.get('Ipv6Ranges', []):
                                    cidr = ip_range.get('CidrIpv6')
                                    if cidr == '::/0':
                                        public_access = True
                                        public_cidr = cidr
                                        break
                            
                            if public_access:
                                # Check if rule affects sensitive ports
                                if from_port is not None and to_port is not None:
                                    for port in range(from_port, to_port + 1):
                                        if port in sensitive_ports:
                                            risk_level = 'HIGH'
                                            # SSH and RDP are particularly sensitive
                                            if port in [22, 3389]:
                                                risk_level = 'CRITICAL'
                                                
                                            findings.append({
                                                'ResourceType': 'Security Group',
                                                'ResourceId': sg_id,
                                                'ResourceName': sg_name,
                                                'ResourceDescription': sg_description,
                                                'VpcId': vpc_id,
                                                'AssociatedResources': associated_resources[:5],  # Limit to first 5
                                                'Region': current_region,
                                                'Risk': risk_level,
                                                'Issue': f'Security group allows public access ({public_cidr}) to {sensitive_ports[port]} (port {port})',
                                                'Recommendation': f'Restrict access to port {port} to specific IP ranges'
                                            })
                                            
                                            # Print finding immediately
                                            print(f"    [!] FINDING: {sg_name} ({sg_id}) - Public access to {sensitive_ports[port]} (port {port}) - {risk_level} risk")
                                            
                                elif ip_protocol == '-1':  # All traffic
                                    findings.append({
                                        'ResourceType': 'Security Group',
                                        'ResourceId': sg_id,
                                        'ResourceName': sg_name,
                                        'ResourceDescription': sg_description,
                                        'VpcId': vpc_id,
                                        'AssociatedResources': associated_resources[:5],  # Limit to first 5
                                        'Region': current_region,
                                        'Risk': 'CRITICAL',
                                        'Issue': f'Security group allows public access ({public_cidr}) to ALL ports and protocols',
                                        'Recommendation': 'Restrict access to specific ports and IP ranges'
                                    })
                                    
                                    # Print finding immediately
                                    print(f"    [!] FINDING: {sg_name} ({sg_id}) - Public access to ALL ports and protocols - CRITICAL risk")
                                    
                                elif from_port is None and to_port is None and ip_protocol != 'icmp':
                                    # Protocol-specific rule without port restrictions
                                    findings.append({
                                        'ResourceType': 'Security Group',
                                        'ResourceId': sg_id,
                                        'ResourceName': sg_name,
                                        'ResourceDescription': sg_description,
                                        'VpcId': vpc_id,
                                        'AssociatedResources': associated_resources[:5],  # Limit to first 5
                                        'Region': current_region,
                                        'Risk': 'HIGH',
                                        'Issue': f'Security group allows public access ({public_cidr}) to all ports on protocol {ip_protocol}',
                                        'Recommendation': f'Restrict access to specific ports for {ip_protocol} protocol'
                                    })
                                    
                                    # Print finding immediately
                                    print(f"    [!] FINDING: {sg_name} ({sg_id}) - Public access to all ports on protocol {ip_protocol} - HIGH risk")
            
            except ClientError as e:
                print(f"  Error scanning security groups in {current_region}: {e}")
    
    except Exception as e:
        print(f"Error scanning security groups: {e}")
    
    if total_sg_count == 0:
        print("No security groups found (excluding default security groups).")
    else:
        print(f"Security group scan complete. Scanned {total_sg_count} security groups across {regions_with_sgs} regions.")
    
    if findings:
        print(f"Found {len(findings)} security group issues.")
    else:
        print("No security group issues found.")
    
    return findings