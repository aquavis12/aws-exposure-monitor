"""
VPC Scanner Module - Detects security issues with AWS VPC
"""
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta


def scan_vpc(region=None):
    """
    Scan AWS VPC for security issues like:
    - Missing flow logs
    - Overly permissive NACLs
    - Default VPC usage
    - Public subnets with direct internet access
    - Missing VPC endpoints for private services
    - Insecure security group references
    - IPv6 security issues
    
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
        
        # Check each region for VPCs
        region_count = 0
        total_vpc_count = 0
        
        for current_region in regions:
            region_count += 1
            if len(regions) > 1:
                print(f"[{region_count}/{len(regions)}] Scanning region: {current_region}")
            else:
                pass
            ec2_client = boto3.client('ec2', region_name=current_region)
            
            try:
                # List all VPCs
                vpcs = ec2_client.describe_vpcs()
                vpc_list = vpcs.get('Vpcs', [])
                
                if not vpc_list:
                    print(f"  No VPCs found in {current_region}")
                    continue
                
                total_vpc_count += len(vpc_list)
                print(f"  Found {len(vpc_list)} VPCs in {current_region}")
                
                # Check each VPC
                for vpc in vpc_list:
                    vpc_id = vpc.get('VpcId')
                    is_default = vpc.get('IsDefault', False)
                    vpc_cidr = vpc.get('CidrBlock')
                    
                    # Get VPC name from tags
                    vpc_name = vpc_id
                    for tag in vpc.get('Tags', []):
                        if tag.get('Key') == 'Name':
                            vpc_name = tag.get('Value')
                            break
                    
                    # Check for IPv6 CIDR blocks
                    ipv6_cidrs = vpc.get('Ipv6CidrBlockAssociationSet', [])
                    has_ipv6 = len(ipv6_cidrs) > 0
                    
                    if has_ipv6:
                        print(f"    VPC {vpc_id} ({vpc_name}) has IPv6 CIDR blocks configured")
                        
                        # Check if IPv6 traffic is allowed to the internet
                        try:
                            route_tables = ec2_client.describe_route_tables(
                                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                            )
                            
                            for rt in route_tables.get('RouteTables', []):
                                rt_id = rt.get('RouteTableId')
                                
                                # Check for default IPv6 routes to internet gateway
                                for route in rt.get('Routes', []):
                                    if route.get('DestinationIpv6CidrBlock') == '::/0' and route.get('GatewayId', '').startswith('igw-'):
                                        # This route table has a default IPv6 route to an internet gateway
                                        
                                        # Check which subnets use this route table
                                        subnet_associations = []
                                        for assoc in rt.get('Associations', []):
                                            if assoc.get('SubnetId'):
                                                subnet_associations.append(assoc.get('SubnetId'))
                                        
                                        subnet_info = ""
                                        if subnet_associations:
                                            subnet_info = f" (affects subnets: {', '.join(subnet_associations[:3])})"
                                            if len(subnet_associations) > 3:
                                                subnet_info += f" and {len(subnet_associations) - 3} more"
                                        
                                        findings.append({
                                            'ResourceType': 'VPC',
                                            'ResourceId': vpc_id,
                                            'ResourceName': vpc_name,
                                            'Region': current_region,
                                            'Risk': 'MEDIUM',
                                            'Issue': f'VPC has a default route for all IPv6 traffic (::/0) to an Internet Gateway{subnet_info}',
                                            'Recommendation': 'Review if public IPv6 access is required, and if not, remove the default IPv6 route'
                                        })
                        except ClientError as e:
                            pass
                    
                    # Check if default VPC is being used
                    if is_default:
                        # Check if default VPC has resources
                        has_resources = False
                        
                        # Check for EC2 instances
                        instances = ec2_client.describe_instances(
                            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                        )
                        if any(reservation.get('Instances') for reservation in instances.get('Reservations', [])):
                            has_resources = True
                        
                        # Check for RDS instances if not already found resources
                        if not has_resources:
                            try:
                                rds_client = boto3.client('rds', region_name=current_region)
                                rds_instances = rds_client.describe_db_instances()
                                for instance in rds_instances.get('DBInstances', []):
                                    if instance.get('DBSubnetGroup', {}).get('VpcId') == vpc_id:
                                        has_resources = True
                                        break
                            except ClientError:
                                pass
                        
                        if has_resources:
                            findings.append({
                                'ResourceType': 'VPC',
                                'ResourceId': vpc_id,
                                'ResourceName': vpc_name,
                                'Region': current_region,
                                'Risk': 'MEDIUM',
                                'Issue': 'Default VPC is being used for resources',
                                'Recommendation': 'Create custom VPCs with proper security controls instead of using the default VPC'
                            })
                    
                    # Check for flow logs
                    flow_logs = ec2_client.describe_flow_logs(
                        Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                    )
                    
                    if not flow_logs.get('FlowLogs'):
                        findings.append({
                            'ResourceType': 'VPC',
                            'ResourceId': vpc_id,
                            'ResourceName': vpc_name,
                            'Region': current_region,
                            'Risk': 'HIGH',
                            'Issue': 'VPC flow logs are not enabled',
                            'Recommendation': 'Enable VPC flow logs to monitor network traffic'
                        })
                    else:
                        print(f"    VPC {vpc_id} ({vpc_name}) has flow logs enabled")
                        # Check flow log configuration
                        for flow_log in flow_logs.get('FlowLogs', []):
                            log_destination_type = flow_log.get('LogDestinationType')
                            traffic_type = flow_log.get('TrafficType')
                            
                            if traffic_type != 'ALL':
                                findings.append({
                                    'ResourceType': 'VPC Flow Log',
                                    'ResourceId': flow_log.get('FlowLogId'),
                                    'ResourceName': f"Flow Log for {vpc_name}",
                                    'Region': current_region,
                                    'Risk': 'LOW',
                                    'Issue': f'VPC flow log is only capturing {traffic_type} traffic',
                                    'Recommendation': 'Configure flow logs to capture ALL traffic types'
                                })
                            
                            if log_destination_type == 'cloud-watch-logs':
                                # Check if log group is encrypted
                                try:
                                    logs_client = boto3.client('logs', region_name=current_region)
                                    log_group_name = flow_log.get('LogGroupName')
                                    if log_group_name:
                                        log_group = logs_client.describe_log_groups(
                                            logGroupNamePrefix=log_group_name
                                        )
                                        for group in log_group.get('logGroups', []):
                                            if group.get('logGroupName') == log_group_name and not group.get('kmsKeyId'):
                                                findings.append({
                                                    'ResourceType': 'VPC Flow Log',
                                                    'ResourceId': flow_log.get('FlowLogId'),
                                                    'ResourceName': f"Flow Log for {vpc_name}",
                                                    'Region': current_region,
                                                    'Risk': 'MEDIUM',
                                                    'Issue': 'VPC flow log CloudWatch log group is not encrypted',
                                                    'Recommendation': 'Enable KMS encryption for the flow log CloudWatch log group'
                                                })
                                except ClientError:
                                    pass
                    
                    # Check subnets
                    subnets = ec2_client.describe_subnets(
                        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                    )
                    
                    public_subnet_count = 0
                    for subnet in subnets.get('Subnets', []):
                        subnet_id = subnet.get('SubnetId')
                        is_public = subnet.get('MapPublicIpOnLaunch', False)
                        
                        # Get subnet name from tags
                        subnet_name = subnet_id
                        for tag in subnet.get('Tags', []):
                            if tag.get('Key') == 'Name':
                                subnet_name = tag.get('Value')
                                break
                        
                        # Check for IPv6 addresses in subnet
                        ipv6_cidr = subnet.get('Ipv6CidrBlockAssociationSet', [])
                        if ipv6_cidr:
                            # Check if subnet assigns IPv6 addresses automatically
                            if subnet.get('AssignIpv6AddressOnCreation', False):
                                # Check if this is a private subnet
                                is_actually_private = True
                                try:
                                    # Get route tables for this subnet
                                    route_tables = ec2_client.describe_route_tables(
                                        Filters=[
                                            {'Name': 'association.subnet-id', 'Values': [subnet_id]}
                                        ]
                                    )
                                    
                                    # If no explicit association, check main route table
                                    if not route_tables.get('RouteTables'):
                                        route_tables = ec2_client.describe_route_tables(
                                            Filters=[
                                                {'Name': 'vpc-id', 'Values': [vpc_id]},
                                                {'Name': 'association.main', 'Values': ['true']}
                                            ]
                                        )
                                    
                                    # Check if any route table has a route to an internet gateway
                                    for rt in route_tables.get('RouteTables', []):
                                        for route in rt.get('Routes', []):
                                            if route.get('DestinationIpv6CidrBlock') == '::/0' and \
                                               route.get('GatewayId', '').startswith('igw-'):
                                                is_actually_private = False
                                                break
                                        if not is_actually_private:
                                            break
                                except ClientError:
                                    is_actually_private = False  # Assume public if we can't determine
                                
                                if is_actually_private:
                                    findings.append({
                                        'ResourceType': 'VPC Subnet',
                                        'ResourceId': subnet_id,
                                        'ResourceName': subnet_name,
                                        'Region': current_region,
                                        'Risk': 'HIGH',
                                        'Issue': 'Private subnet is configured to automatically assign IPv6 addresses',
                                        'Recommendation': 'Disable automatic IPv6 address assignment for private subnets to prevent unintended public exposure'
                                    })
                                else:
                                    findings.append({
                                        'ResourceType': 'VPC Subnet',
                                        'ResourceId': subnet_id,
                                        'ResourceName': subnet_name,
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': 'Public subnet is configured to automatically assign IPv6 addresses',
                                        'Recommendation': 'Review if automatic IPv6 address assignment is required for all instances'
                                    })
                        
                        if is_public:
                            public_subnet_count += 1
                            
                            # Check if this is actually a private subnet (no route to IGW)
                            is_actually_private = True
                            try:
                                # Get route tables for this subnet
                                route_tables = ec2_client.describe_route_tables(
                                    Filters=[
                                        {'Name': 'association.subnet-id', 'Values': [subnet_id]}
                                    ]
                                )
                                
                                # If no explicit association, check main route table
                                if not route_tables.get('RouteTables'):
                                    route_tables = ec2_client.describe_route_tables(
                                        Filters=[
                                            {'Name': 'vpc-id', 'Values': [vpc_id]},
                                            {'Name': 'association.main', 'Values': ['true']}
                                        ]
                                    )
                                
                                # Check if any route table has a route to an internet gateway
                                for rt in route_tables.get('RouteTables', []):
                                    for route in rt.get('Routes', []):
                                        if route.get('DestinationCidrBlock') == '0.0.0.0/0' and \
                                           route.get('GatewayId', '').startswith('igw-'):
                                            is_actually_private = False
                                            break
                                    if not is_actually_private:
                                        break
                            except ClientError:
                                is_actually_private = False  # Assume public if we can't determine
                            
                            if is_actually_private:
                                findings.append({
                                    'ResourceType': 'VPC Subnet',
                                    'ResourceId': subnet_id,
                                    'ResourceName': subnet_name,
                                    'Region': current_region,
                                    'Risk': 'HIGH',
                                    'Issue': 'Private subnet is configured to assign public IPs by default',
                                    'Recommendation': 'Disable auto-assign public IPs for private subnets to prevent unintended public exposure'
                                })
                            else:
                                findings.append({
                                    'ResourceType': 'VPC Subnet',
                                    'ResourceId': subnet_id,
                                    'ResourceName': subnet_name,
                                    'Region': current_region,
                                    'Risk': 'LOW',
                                    'Issue': 'Public subnet is configured to assign public IPs by default',
                                    'Recommendation': 'Review if auto-assign public IPs is needed for all instances in this public subnet'
                                })
                    
                    # Check NACLs
                    nacls = ec2_client.describe_network_acls(
                        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                    )
                    
                    for nacl in nacls.get('NetworkAcls', []):
                        nacl_id = nacl.get('NetworkAclId')
                        is_default = nacl.get('IsDefault', False)
                        
                        # Check for overly permissive rules
                        for entry in nacl.get('Entries', []):
                            if entry.get('Egress') is False:  # Inbound rule
                                cidr = entry.get('CidrBlock')
                                rule_action = entry.get('RuleAction')
                                protocol = entry.get('Protocol')
                                
                                if cidr == '0.0.0.0/0' and rule_action == 'allow' and (protocol == '-1' or protocol == '6'):
                                    findings.append({
                                        'ResourceType': 'VPC NACL',
                                        'ResourceId': nacl_id,
                                        'ResourceName': f"NACL for {vpc_name}",
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': 'NACL has overly permissive inbound rule allowing all traffic from any source',
                                        'Recommendation': 'Restrict NACL rules to specific IP ranges and protocols'
                                    })
                                    break
                                
                                # Check for IPv6 rules
                                ipv6_cidr = entry.get('Ipv6CidrBlock')
                                if ipv6_cidr == '::/0' and rule_action == 'allow' and not entry.get('Egress'):
                                    port_range = entry.get('PortRange', {})
                                    port_info = ""
                                    if port_range:
                                        from_port = port_range.get('From', 'all')
                                        to_port = port_range.get('To', 'all')
                                        if from_port == to_port:
                                            port_info = f" on port {from_port}"
                                        else:
                                            port_info = f" on port range {from_port}-{to_port}"
                                    
                                    findings.append({
                                        'ResourceType': 'VPC NACL',
                                        'ResourceId': nacl_id,
                                        'ResourceName': f"NACL for {vpc_name}",
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': f"Network ACL allows inbound traffic from any IPv6 address (::/0){port_info}",
                                        'Recommendation': 'Restrict inbound IPv6 traffic to specific address ranges'
                                    })
                    
                    # Check for VPC endpoints for common services
                    endpoints = ec2_client.describe_vpc_endpoints(
                        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                    )
                    
                    endpoint_services = set()
                    for endpoint in endpoints.get('VpcEndpoints', []):
                        service_name = endpoint.get('ServiceName', '')
                        if service_name:
                            endpoint_services.add(service_name.split('.')[-1])
                    
                    # Count actual private subnets (those without routes to IGW)
                    actual_private_subnet_count = 0
                    for subnet in subnets.get('Subnets', []):
                        subnet_id = subnet.get('SubnetId')
                        try:
                            # Get route tables for this subnet
                            route_tables = ec2_client.describe_route_tables(
                                Filters=[
                                    {'Name': 'association.subnet-id', 'Values': [subnet_id]}
                                ]
                            )
                            
                            # If no explicit association, check main route table
                            if not route_tables.get('RouteTables'):
                                route_tables = ec2_client.describe_route_tables(
                                    Filters=[
                                        {'Name': 'vpc-id', 'Values': [vpc_id]},
                                        {'Name': 'association.main', 'Values': ['true']}
                                    ]
                                )
                            
                            # Check if any route table has a route to an internet gateway
                            is_private = True
                            for rt in route_tables.get('RouteTables', []):
                                for route in rt.get('Routes', []):
                                    if (route.get('DestinationCidrBlock') == '0.0.0.0/0' or \
                                        route.get('DestinationIpv6CidrBlock') == '::/0') and \
                                       route.get('GatewayId', '').startswith('igw-'):
                                        is_private = False
                                        break
                                if not is_private:
                                    break
                            
                            if is_private:
                                actual_private_subnet_count += 1
                        except ClientError:
                            pass  # Skip if we can't determine
                    
                    # Check if private subnets exist but no S3 or DynamoDB endpoints
                    if actual_private_subnet_count > 0:
                        # We have at least one private subnet
                        if 's3' not in endpoint_services:
                            findings.append({
                                'ResourceType': 'VPC',
                                'ResourceId': vpc_id,
                                'ResourceName': vpc_name,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': f'VPC has {actual_private_subnet_count} private subnet(s) but no S3 endpoint',
                                'Recommendation': 'Create an S3 gateway endpoint for private subnet access to S3 to reduce data transfer costs'
                            })
                        
                        if 'dynamodb' not in endpoint_services:
                            findings.append({
                                'ResourceType': 'VPC',
                                'ResourceId': vpc_id,
                                'ResourceName': vpc_name,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': f'VPC has {actual_private_subnet_count} private subnet(s) but no DynamoDB endpoint',
                                'Recommendation': 'Create a DynamoDB gateway endpoint for private subnet access to DynamoDB to reduce data transfer costs'
                            })
                
                # Check for unused security groups
                security_groups = ec2_client.describe_security_groups(
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                )
                
                for sg in security_groups.get('SecurityGroups', []):
                    sg_id = sg.get('GroupId')
                    sg_name = sg.get('GroupName')
                    
                    # Skip default security group
                    if sg_name == 'default':
                        continue
                    
                    # Check if security group is in use
                    try:
                        sg_usage = ec2_client.describe_network_interfaces(
                            Filters=[{'Name': 'group-id', 'Values': [sg_id]}]
                        )
                        
                        if not sg_usage.get('NetworkInterfaces'):
                            findings.append({
                                'ResourceType': 'VPC Security Group',
                                'ResourceId': sg_id,
                                'ResourceName': sg_name,
                                'Region': current_region,
                                'Risk': 'LOW',
                                'Issue': 'Security group is not being used by any resources',
                                'Recommendation': 'Delete unused security groups to reduce complexity and attack surface'
                            })
                    except ClientError:
                        pass
                    
                    # Check for security group rules referencing other security groups
                    for rule in sg.get('IpPermissions', []):
                        for group_pair in rule.get('UserIdGroupPairs', []):
                            referenced_sg_id = group_pair.get('GroupId')
                            if referenced_sg_id:
                                try:
                                    referenced_sg = ec2_client.describe_security_groups(
                                        GroupIds=[referenced_sg_id]
                                    )
                                    # Security group exists, no issue
                                except ClientError:
                                    findings.append({
                                        'ResourceType': 'VPC Security Group',
                                        'ResourceId': sg_id,
                                        'ResourceName': sg_name,
                                        'Region': current_region,
                                        'Risk': 'MEDIUM',
                                        'Issue': f'Security group references non-existent security group {referenced_sg_id}',
                                        'Recommendation': 'Remove references to non-existent security groups'
                                    })
            
            except ClientError as e:
                pass
    except Exception as e:
        pass
    
    return findings