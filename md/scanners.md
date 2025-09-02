# Scanner Details

## Compute Scanners

### EC2 Instances (`ec2`)
- **IMDSv2 Usage**: Detects instances using IMDSv1 instead of IMDSv2
- **SSM Agent**: Identifies instances not managed by Systems Manager
- **Public IP Addresses**: Flags instances with public IPv4/IPv6 addresses
- **EBS Encryption**: Checks for unencrypted EBS volumes
- **Instance Age**: Reports long-running instances (>180 days)
- **Termination Protection**: Verifies protection settings
- **Detailed Monitoring**: Checks CloudWatch monitoring status

### AMIs (`amis`)
- **Public Sharing**: Detects publicly shared AMIs
- **Launch Permissions**: Checks AMI launch permissions
- **Unused AMIs**: Identifies AMIs not used by any instances

### ECR Repositories (`ecr`)
- **Public Access**: Scans for publicly accessible repositories
- **Image Scanning**: Verifies vulnerability scanning configuration
- **Repository Policies**: Checks for overly permissive policies

### Lambda Functions (`lambda`)
- **Function URLs**: Detects functions with public URLs (AuthType: NONE)
- **Resource Policies**: Identifies functions with public invocation policies
- **Runtime Security**: Checks for deprecated runtimes

### Lightsail (`lightsail`)
- **Instance Security**: Scans Lightsail instances for open ports
- **Database Security**: Checks Lightsail databases for public access
- **Load Balancer Configuration**: Verifies SSL/TLS settings

## Security Scanners

### IAM Users and Access Keys (`iam`)
- **Inactive Users**: Identifies users not logged in for 90+ days
- **Old Access Keys**: Detects keys unused for 60+ days or older than 90 days
- **MFA Status**: Checks for users without MFA enabled
- **Admin Privileges**: Flags users with administrator access
- **Password Policy**: Verifies account password policy strength

### Security Groups (`sg`)
- **Sensitive Ports**: Detects public access to SSH (22), RDP (3389), databases
- **All Traffic Rules**: Identifies rules allowing all ports/protocols
- **IPv6 Rules**: Checks for overly permissive IPv6 rules
- **Associated Resources**: Shows which resources use each security group

### Secrets Manager and KMS (`secrets`)
- **Secret Rotation**: Checks if automatic rotation is enabled
- **KMS Key Usage**: Identifies unused or overly permissive KMS keys
- **Key Rotation**: Verifies annual key rotation is enabled
- **Cross-Account Access**: Detects keys accessible from other accounts

### Hardcoded Secrets Scanner (`secrets_scanner`)
- **API Keys**: Scans for hardcoded API keys in resources
- **Database Credentials**: Detects embedded database passwords
- **AWS Credentials**: Identifies hardcoded AWS access keys
- **Generic Secrets**: Finds other potential secret patterns

### CloudTrail (`cloudtrail`)
- **Trail Status**: Verifies CloudTrail is enabled and logging
- **Encryption**: Checks if logs are encrypted with KMS
- **File Validation**: Ensures log file integrity validation
- **Multi-Region**: Verifies multi-region trail configuration

### GuardDuty (`guardduty`)
- **Service Status**: Checks if GuardDuty is enabled
- **Detector Configuration**: Verifies proper detector settings
- **Finding Types**: Reviews active threat detection capabilities

### WAF (`waf`)
- **Web ACL Configuration**: Checks WAF rule configurations
- **Logging**: Verifies WAF logging is enabled
- **Resource Associations**: Ensures WAF is protecting resources

## Database Scanners

### RDS Snapshots (`rds`)
- **Public Sharing**: Detects publicly accessible snapshots
- **Restore Attributes**: Checks for public restore permissions
- **Encryption**: Verifies snapshot encryption status

### RDS Instances (`rds-instances`)
- **Public Accessibility**: Identifies publicly accessible databases
- **Encryption**: Checks for unencrypted RDS instances
- **Backup Configuration**: Verifies automated backup settings
- **Multi-AZ**: Checks high availability configuration

### Aurora Clusters (`aurora`)
- **Public Access**: Detects publicly accessible Aurora clusters
- **Encryption**: Verifies cluster encryption settings
- **Backup Retention**: Checks backup retention periods
- **Deletion Protection**: Verifies deletion protection status

### DynamoDB Tables (`dynamodb`)
- **Encryption**: Checks for encryption at rest
- **Point-in-Time Recovery**: Verifies PITR is enabled
- **Backup Configuration**: Checks automated backup settings
- **Contributor Insights**: Verifies monitoring configuration

### Elasticsearch/OpenSearch (`elasticsearch`, `opensearch`)
- **VPC Configuration**: Checks if domain is in VPC
- **Encryption**: Verifies encryption in transit and at rest
- **Access Policies**: Reviews domain access policies
- **HTTPS**: Ensures HTTPS-only access

## Storage Scanners

### S3 Buckets (`s3`)
- **Public Access Block**: Checks bucket-level public access settings
- **Bucket Policies**: Scans for policies allowing public access
- **ACL Permissions**: Detects public ACL grants
- **Encryption**: Verifies default encryption is enabled
- **Versioning**: Checks if versioning is enabled
- **Intentional Public Access**: Respects buckets tagged as intentionally public

### EBS Snapshots (`ebs`)
- **Public Sharing**: Detects publicly shared snapshots
- **Encryption**: Checks snapshot encryption status
- **Snapshot Age**: Identifies old snapshots for cleanup

## Networking Scanners

### API Gateway (`api`)
- **Authorization**: Detects endpoints without authorization
- **API Key Requirements**: Checks for missing API key requirements
- **CORS Configuration**: Reviews cross-origin resource sharing settings

### CloudFront (`cloudfront`)
- **WAF Protection**: Checks if distributions use WAF
- **Origin Access**: Verifies OAI/OAC configuration for S3 origins
- **Geo Restrictions**: Reviews geographic access restrictions
- **SSL/TLS**: Checks certificate and protocol configurations

### Load Balancers (`elb`)
- **SSL/TLS Configuration**: Verifies secure listener configurations
- **Access Logging**: Checks if access logging is enabled
- **Security Groups**: Reviews load balancer security group rules

### VPC (`vpc`)
- **Flow Logs**: Verifies VPC flow logging is enabled
- **Network ACLs**: Checks for overly permissive network ACLs
- **Subnet Configuration**: Identifies public vs private subnet issues
- **Route Tables**: Reviews routing configurations

### SNS Topics (`sns`)
- **Encryption**: Checks for encryption at rest and in transit
- **Access Policies**: Reviews topic access policies
- **Cross-Account Access**: Detects external account permissions

### SQS Queues (`sqs`)
- **Encryption**: Verifies queue encryption settings
- **Access Policies**: Reviews queue access policies
- **Dead Letter Queues**: Checks DLQ configuration

## Cost Optimization Scanner

### Cost Scanner (`cost`)
- **Unused Resources**: Identifies idle or unused resources
- **Right-Sizing**: Suggests instance size optimizations
- **Reserved Instances**: Analyzes RI utilization and recommendations
- **Storage Optimization**: Identifies storage cost savings
- **Network Costs**: Reviews data transfer and NAT Gateway usage

## Infrastructure as Code

### Terraform Scanner (`terraform`)
- **Security Misconfigurations**: Scans Terraform code for security issues
- **Best Practices**: Checks adherence to AWS security best practices
- **Resource Policies**: Reviews IAM and resource policies in code

## Comprehensive Audit

### Security Audit Scanner (`audit`)
- **All Resources**: Scans all AWS resources comprehensively
- **Audit Attributes**: Respects security-audit and cost-audit tags
- **Compliance Tracking**: Flags resources missing audit tags
- **Risk Prioritization**: Provides comprehensive risk assessment