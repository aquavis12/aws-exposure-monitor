"""
Security Group Scanner Module - Detects security groups with open access to sensitive ports
"""
import boto3
from botocore.exceptions import ClientError


def scan_security_groups():
    """
    Scan security groups for rules allowing public access to sensitive ports
    Returns a list of dictionaries containing vulnerable resources
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
        139: 'NetBIOS'
    }
    
    try:
        # Get all regions
        ec2_client = boto3.client('ec2')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        for region in regions:
            regional_client = boto3.client('ec2', region_name=region)
            
            try:
                # Get all security groups
                security_groups = regional_client.describe_security_groups()
                
                for sg in security_groups.get('SecurityGroups', []):
                    sg_id = sg['GroupId']
                    sg_name = sg['GroupName']
                    
                    # Check inbound rules
                    for rule in sg.get('IpPermissions', []):
                        from_port = rule.get('FromPort')
                        to_port = rule.get('ToPort')
                        
                        # Check if any IP ranges include 0.0.0.0/0 or ::/0 (IPv6)
                        public_access = False
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                public_access = True
                                break
                        
                        for ip_range in rule.get('Ipv6Ranges', []):
                            if ip_range.get('CidrIpv6') == '::/0':
                                public_access = True
                                break
                        
                        if public_access:
                            # Check if rule affects sensitive ports
                            if from_port is not None and to_port is not None:
                                for port in range(from_port, to_port + 1):
                                    if port in sensitive_ports:
                                        findings.append({
                                            'ResourceType': 'Security Group',
                                            'ResourceId': sg_id,
                                            'ResourceName': sg_name,
                                            'Region': region,
                                            'Risk': 'HIGH',
                                            'Issue': f'Security group allows public access to {sensitive_ports[port]} (port {port})',
                                            'Recommendation': f'Restrict access to port {port} to specific IP ranges'
                                        })
                            elif rule.get('IpProtocol') == '-1':  # All traffic
                                findings.append({
                                    'ResourceType': 'Security Group',
                                    'ResourceId': sg_id,
                                    'ResourceName': sg_name,
                                    'Region': region,
                                    'Risk': 'CRITICAL',
                                    'Issue': 'Security group allows public access to ALL ports',
                                    'Recommendation': 'Restrict access to specific ports and IP ranges'
                                })
            
            except ClientError as e:
                print(f"Error scanning security groups in {region}: {e}")
    
    except Exception as e:
        print(f"Error scanning security groups: {e}")
    
    return findings