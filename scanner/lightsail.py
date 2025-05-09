"""
Lightsail Scanner Module - Detects security issues with AWS Lightsail resources
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan_lightsail(region=None):
    """
    Scan AWS Lightsail for security issues like:
    - Public instances without firewalls
    - Unencrypted databases
    - Outdated blueprints
    - Missing snapshots
    
    Args:
        region (str, optional): AWS region to scan. If None, scan all regions.
    
    Returns:
        list: List of dictionaries containing vulnerable resources
    """
    findings = []
    
    print("Starting Lightsail scan...")
    
    try:
        # Get regions to scan
        ec2_client = boto3.client('ec2')
        if region:
            regions = [region]
            print(f"Scanning region: {region}")
        else:
            # Lightsail is not available in all regions
            lightsail_regions = [
                'us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1', 'eu-west-2', 
                'eu-west-3', 'eu-central-1', 'ap-northeast-1', 'ap-northeast-2', 
                'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'ca-central-1'
            ]
            regions = lightsail_regions
            print(f"Scanning {len(regions)} Lightsail regions")
        
        region_count = 0
        total_resource_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                print(f"Scanning region: {current_region}")
                
            lightsail_client = boto3.client('lightsail', region_name=current_region)
            
            # Get current time for age calculations
            current_time = datetime.now(timezone.utc)
            
            # Scan Lightsail instances
            try:
                instances = lightsail_client.get_instances().get('instances', [])
                instance_count = len(instances)
                
                if instance_count > 0:
                    total_resource_count += instance_count
                    print(f"  Found {instance_count} Lightsail instances in {current_region}")
                    
                    for i, instance in enumerate(instances, 1):
                        instance_name = instance.get('name')
                        blueprint_id = instance.get('blueprintId')
                        bundle_id = instance.get('bundleId')
                        public_ip = instance.get('publicIpAddress')
                        state = instance.get('state', {}).get('name')
                        created_at = instance.get('createdAt')
                        
                        # Print progress every 5 instances or for the last one
                        if i % 5 == 0 or i == instance_count:
                            print(f"  Progress: {i}/{instance_count} instances")
                        
                        # Check for public instances without proper firewall
                        if public_ip and state == 'running':
                            # Get firewall rules
                            firewall = lightsail_client.get_instance_port_states(instanceName=instance_name)
                            port_states = firewall.get('portStates', [])
                            
                            # Check for overly permissive rules
                            has_ssh_open = False
                            has_rdp_open = False
                            has_all_open = False
                            
                            for port in port_states:
                                protocol = port.get('protocol')
                                port_num = port.get('fromPort')
                                cidr = port.get('cidrs', [])
                                
                                if port.get('state') == 'open' and '0.0.0.0/0' in cidr:
                                    if port_num == 22 and protocol == 'tcp':
                                        has_ssh_open = True
                                    elif port_num == 3389 and protocol == 'tcp':
                                        has_rdp_open = True
                                    elif port_num == 0 and port.get('toPort') == 65535:
                                        has_all_open = True
                            
                            if has_all_open:
                                findings.append({
                                    'ResourceType': 'Lightsail Instance',
                                    'ResourceId': instance_name,
                                    'ResourceName': instance_name,
                                    'PublicIP': public_ip,
                                    'Blueprint': blueprint_id,
                                    'Region': current_region,
                                    'Risk': 'CRITICAL',
                                    'Issue': 'Lightsail instance has all ports open to the internet (0.0.0.0/0)',
                                    'Recommendation': 'Restrict firewall rules to only necessary ports and IP ranges'
                                })
                                print(f"    [!] FINDING: Lightsail instance {instance_name} has all ports open - CRITICAL risk")
                            
                            if has_ssh_open:
                                findings.append({
                                    'ResourceType': 'Lightsail Instance',
                                    'ResourceId': instance_name,
                                    'ResourceName': instance_name,
                                    'PublicIP': public_ip,
                                    'Blueprint': blueprint_id,
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': 'Lightsail instance has SSH (port 22) open to the internet (0.0.0.0/0)',
                                    'Recommendation': 'Restrict SSH access to specific IP addresses'
                                })
                                print(f"    [!] FINDING: Lightsail instance {instance_name} has SSH open to internet - HIGH risk")
                            
                            if has_rdp_open:
                                findings.append({
                                    'ResourceType': 'Lightsail Instance',
                                    'ResourceId': instance_name,
                                    'ResourceName': instance_name,
                                    'PublicIP': public_ip,
                                    'Blueprint': blueprint_id,
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': 'Lightsail instance has RDP (port 3389) open to the internet (0.0.0.0/0)',
                                    'Recommendation': 'Restrict RDP access to specific IP addresses'
                                })
                                print(f"    [!] FINDING: Lightsail instance {instance_name} has RDP open to internet - HIGH risk")
                        
                        # Check for outdated blueprints
                        if blueprint_id:
                            if 'wordpress' in blueprint_id.lower() and 'bitnami' in blueprint_id.lower():
                                # Bitnami WordPress blueprints should be updated regularly
                                if created_at:
                                    age_days = (current_time - created_at).days
                                    if age_days > 180:  # 6 months
                                        findings.append({
                                            'ResourceType': 'Lightsail Instance',
                                            'ResourceId': instance_name,
                                            'ResourceName': instance_name,
                                            'Blueprint': blueprint_id,
                                            'Region': current_region,
                                            'Risk': 'MEDIUM',
                                            'Issue': f'Lightsail instance is using an old blueprint ({age_days} days old)',
                                            'Recommendation': 'Create a new instance with the latest blueprint and migrate data'
                                        })
                                        print(f"    [!] FINDING: Lightsail instance {instance_name} has outdated blueprint - MEDIUM risk")
                        
                        # Check for missing snapshots
                        try:
                            snapshots = lightsail_client.get_instance_snapshots(instanceName=instance_name)
                            instance_snapshots = snapshots.get('instanceSnapshots', [])
                            
                            if not instance_snapshots:
                                findings.append({
                                    'ResourceType': 'Lightsail Instance',
                                    'ResourceId': instance_name,
                                    'ResourceName': instance_name,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'Lightsail instance does not have any snapshots',
                                    'Recommendation': 'Create regular snapshots for backup and recovery'
                                })
                                print(f"    [!] FINDING: Lightsail instance {instance_name} has no snapshots - MEDIUM risk")
                            else:
                                # Check age of newest snapshot
                                newest_snapshot = max(instance_snapshots, key=lambda x: x.get('createdAt', datetime.min.replace(tzinfo=timezone.utc)))
                                newest_snapshot_time = newest_snapshot.get('createdAt')
                                
                                if newest_snapshot_time:
                                    days_since_snapshot = (current_time - newest_snapshot_time).days
                                    if days_since_snapshot > 30:  # More than a month
                                        findings.append({
                                            'ResourceType': 'Lightsail Instance',
                                            'ResourceId': instance_name,
                                            'ResourceName': instance_name,
                                            'Region': current_region,
                                            'Risk': 'MEDIUM',
                                            'Issue': f'Lightsail instance has not been backed up for {days_since_snapshot} days',
                                            'Recommendation': 'Create regular snapshots for backup and recovery'
                                        })
                                        print(f"    [!] FINDING: Lightsail instance {instance_name} snapshot is {days_since_snapshot} days old - MEDIUM risk")
                        except ClientError:
                            pass
                
                # Scan Lightsail databases
                try:
                    databases = lightsail_client.get_relational_databases().get('relationalDatabases', [])
                    db_count = len(databases)
                    
                    if db_count > 0:
                        total_resource_count += db_count
                        print(f"  Found {db_count} Lightsail databases in {current_region}")
                        
                        for i, db in enumerate(databases, 1):
                            db_name = db.get('name')
                            engine = db.get('engine')
                            state = db.get('state')
                            
                            # Print progress every 5 databases or for the last one
                            if i % 5 == 0 or i == db_count:
                                print(f"  Progress: {i}/{db_count} databases")
                            
                            # Check for public accessibility
                            if db.get('publiclyAccessible', False):
                                findings.append({
                                    'ResourceType': 'Lightsail Database',
                                    'ResourceId': db_name,
                                    'ResourceName': db_name,
                                    'Engine': engine,
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': 'Lightsail database is publicly accessible',
                                    'Recommendation': 'Disable public accessibility and use private connections'
                                })
                                print(f"    [!] FINDING: Lightsail database {db_name} is publicly accessible - HIGH risk")
                            
                            # Check for backup retention
                            backup_retention = db.get('backupRetentionEnabled', False)
                            if not backup_retention:
                                findings.append({
                                    'ResourceType': 'Lightsail Database',
                                    'ResourceId': db_name,
                                    'ResourceName': db_name,
                                    'Engine': engine,
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': 'Lightsail database does not have backup retention enabled',
                                    'Recommendation': 'Enable backup retention for data protection'
                                })
                                print(f"    [!] FINDING: Lightsail database {db_name} has no backup retention - HIGH risk")
                            
                            # Check for missing snapshots
                            try:
                                snapshots = lightsail_client.get_relational_database_snapshots(relationalDatabaseName=db_name)
                                db_snapshots = snapshots.get('relationalDatabaseSnapshots', [])
                                
                                if not db_snapshots:
                                    findings.append({
                                        'ResourceType': 'Lightsail Database',
                                        'ResourceId': db_name,
                                        'ResourceName': db_name,
                                        'Engine': engine,
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': 'Lightsail database does not have any snapshots',
                                        'Recommendation': 'Create regular snapshots for backup and recovery'
                                    })
                                    print(f"    [!] FINDING: Lightsail database {db_name} has no snapshots - MEDIUM risk")
                            except ClientError:
                                pass
                except ClientError as e:
                    print(f"  Error scanning Lightsail databases in {current_region}: {e}")
                
                # Scan Lightsail load balancers
                try:
                    load_balancers = lightsail_client.get_load_balancers().get('loadBalancers', [])
                    lb_count = len(load_balancers)
                    
                    if lb_count > 0:
                        total_resource_count += lb_count
                        print(f"  Found {lb_count} Lightsail load balancers in {current_region}")
                        
                        for i, lb in enumerate(load_balancers, 1):
                            lb_name = lb.get('name')
                            
                            # Print progress every 5 load balancers or for the last one
                            if i % 5 == 0 or i == lb_count:
                                print(f"  Progress: {i}/{lb_count} load balancers")
                            
                            # Check for TLS configuration
                            tls_policy = lb.get('tlsPolicyName')
                            if not tls_policy or tls_policy == 'TLS-1-0':
                                findings.append({
                                    'ResourceType': 'Lightsail Load Balancer',
                                    'ResourceId': lb_name,
                                    'ResourceName': lb_name,
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': f'Lightsail load balancer is using outdated TLS policy: {tls_policy or "Default"}',
                                    'Recommendation': 'Update to TLS-1-2 or higher for better security'
                                })
                                print(f"    [!] FINDING: Lightsail load balancer {lb_name} uses outdated TLS policy - HIGH risk")
                            
                            # Check for HTTPS configuration
                            https_configured = False
                            for cert in lb.get('configurationOptions', {}).get('Certificate', []):
                                if cert:
                                    https_configured = True
                                    break
                            
                            if not https_configured:
                                findings.append({
                                    'ResourceType': 'Lightsail Load Balancer',
                                    'ResourceId': lb_name,
                                    'ResourceName': lb_name,
                                    'Region': current_region,
                                    'Risk': 'MEDIUM',
                                    'Issue': 'Lightsail load balancer does not have HTTPS configured',
                                    'Recommendation': 'Configure HTTPS with a valid certificate'
                                })
                                print(f"    [!] FINDING: Lightsail load balancer {lb_name} has no HTTPS - MEDIUM risk")
                except ClientError as e:
                    print(f"  Error scanning Lightsail load balancers in {current_region}: {e}")
            
            except ClientError as e:
                print(f"  Error scanning Lightsail resources in {current_region}: {e}")
        
        if total_resource_count == 0:
            print("No Lightsail resources found.")
        else:
            print(f"Lightsail scan complete. Scanned {total_resource_count} resources.")
    
    except Exception as e:
        print(f"Error scanning Lightsail: {e}")
    
    if findings:
        print(f"Found {len(findings)} Lightsail security issues.")
    else:
        print("No Lightsail security issues found.")
    
    return findings