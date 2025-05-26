# AWS Public Resource Exposure Monitor

<div align="center">

![AWS Exposure Monitor](https://img.shields.io/badge/AWS-Security%20Monitoring-orange?style=for-the-badge&logo=amazon-aws)
![Python](https://img.shields.io/badge/Python-3.7+-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</div>

A powerful security tool that scans your AWS environment for publicly exposed resources, security vulnerabilities, and misconfigurations. It generates detailed reports and helps you identify and remediate security risks.
![](/images/image-3.png)
## ✨ Features

- **Comprehensive Scanning** of 30+ AWS services
- **Multi-Region Support** to scan your entire AWS footprint
- **Security Scoring** to track your security posture over time
- **Interactive HTML Reports** with visualizations and filtering
- **CSV and JSON Reports** for integration with other tools
- **Risk-Based Prioritization** to focus on critical issues first
- **Notification Integration** with Slack and Microsoft Teams
- **Comma-Separated Scanning** to target specific services
- **Infrastructure as Code Scanning** for CloudFormation, CDK, Terraform, Pulumi, and OpenTofu
- **AWS SDK Code Scanning** for security vulnerabilities
- **Enhanced Security Posture** with hundreds of security checks
- **AWS Profile Auto-Detection** for seamless credential management
- **Hardcoded Secrets Detection** in S3, API Gateway, and RDS
- **Cost Optimization Scanning** to identify cost-saving opportunities
- **Category-Based Organization** of findings (Compute, Security, Database, Storage, Networking, Cost)

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/aquavis12/aws-exposure-monitor.git
cd aws-exposure-monitor

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials
aws configure
```

### Basic Usage

```bash
# List all available scanners
python main.py --list-scanners

# Scan all resources in all regions
python main.py

# Scan specific services (comma-separated, no spaces)
python main.py --scan ec2,s3,iam

# Scan a specific region
python main.py --region us-east-1

# Use a specific AWS profile
python main.py --profile my-profile

# Scan by category
python main.py --scan compute  # Scans all compute resources
python main.py --scan security # Scans all security resources
python main.py --scan database # Scans all database resources
python main.py --scan storage  # Scans all storage resources
python main.py --scan networking # Scans all networking resources
python main.py --scan cost     # Scans for cost optimization

# Filter for HIGH risk issues and generate HTML report
python main.py --risk-level HIGH --html-report report.html

# Generate CSV and JSON reports
python main.py --csv-report findings.csv --json-report findings.json

# Scan CloudFormation templates
python main.py --scan cftemplate --cf-template-dir /path/to/templates

# Scan for hardcoded secrets
python main.py --scan secrets_scanner

# Scan for cost optimization opportunities
python main.py --scan cost
```

## 🛡️ Scan Outputs 

*IAM SCAN*
![](/images/image.png)

*Secrets and KMS Scan*
![](/images/image-1.png)

*S3 Bucket Scan*
![](/images/image-2.png)

*Terraform Output Scan*
![](/images/image-4.png)
*HTML Report with Security Score*
👉 [View Security Report](https://htmlreportdemo2025.s3.us-east-1.amazonaws.com/report.html)

## 📋 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--scan TYPES` | Resource type(s) to scan (comma-separated) | `--scan s3,ec2,iam` |
| `--region REGION` | AWS region to scan | `--region us-east-1` |
| `--profile PROFILE` | AWS profile to use | `--profile my-profile` |
| `--risk-level LEVEL` | Filter by minimum risk level (LOW, MEDIUM, HIGH, CRITICAL, ALL) | `--risk-level HIGH` |
| `--output FILE` | Save findings to JSON file | `--output findings.json` |
| `--html-report FILE` | Generate HTML report with security score | `--html-report report.html` |
| `--csv-report FILE` | Generate CSV report | `--csv-report findings.csv` |
| `--json-report FILE` | Generate JSON report with metadata | `--json-report findings.json` |
| `--template-dir DIR` | Directory to scan for templates and code | `--template-dir /path/to/code` |
| `--cf-template-dir DIR` | Directory containing CloudFormation templates | `--cf-template-dir /path/to/templates` |
| `--cdk-dir DIR` | Directory containing CDK code | `--cdk-dir /path/to/cdk` |
| `--terraform-dir DIR` | Directory containing Terraform code | `--terraform-dir /path/to/terraform` |
| `--pulumi-dir DIR` | Directory containing Pulumi code | `--pulumi-dir /path/to/pulumi` |
| `--opentofu-dir DIR` | Directory containing OpenTofu code | `--opentofu-dir /path/to/opentofu` |
| `--sdk-dir DIR` | Directory containing AWS SDK code | `--sdk-dir /path/to/sdk` |
| `--list-scanners` | List all available scanners | `--list-scanners` |
| `--notify` | Send notifications for findings | `--notify` |
| `--slack-webhook URL` | Slack webhook URL for notifications | `--slack-webhook https://hooks.slack.com/...` |
| `--teams-webhook URL` | Microsoft Teams webhook URL for notifications | `--teams-webhook https://your-org.webhook...` |
| `--verbose` | Show detailed progress information | `--verbose` |
| `--no-color` | Disable colored output | `--no-color` |

### Available Scan Types by Category

#### Compute
- `ec2` - EC2 instances
- `amis` - Amazon Machine Images
- `ecr` - ECR repositories
- `lambda` - Lambda functions
- `lightsail` - Lightsail resources

#### Security
- `iam` - IAM users and access keys
- `sg` - Security Groups
- `secrets` - Secrets Manager and KMS
- `secrets_scanner` - Hardcoded secrets scanner
- `cloudtrail` - CloudTrail
- `guardduty` - GuardDuty
- `config` - AWS Config
- `cloudwatch` - CloudWatch Logs
- `waf` - WAF Web ACLs
- `templates` - All templates and code
- `cftemplate` - CloudFormation templates
- `cdk` - CDK code
- `terraform` - Terraform code
- `pulumi` - Pulumi code
- `opentofu` - OpenTofu code
- `sdk` - AWS SDK code

#### Database
- `rds` - RDS snapshots
- `rds-instances` - RDS instances
- `aurora` - Aurora clusters
- `elasticsearch` - Elasticsearch domains
- `dynamodb` - DynamoDB tables

#### Storage
- `s3` - S3 buckets
- `ebs` - EBS snapshots

#### Networking
- `api` - API Gateway endpoints
- `cloudfront` - CloudFront distributions
- `elb` - Elastic Load Balancers
- `eip` - Elastic IPs
- `vpc` - VPC
- `sns` - SNS topics
- `sqs` - SQS queues

#### Cost
- `cost` - Cost optimization scanner

### Risk Levels

| Level | Description |
|-------|-------------|
| `LOW` | Minor security concerns that should be addressed |
| `MEDIUM` | Important security issues that need attention |
| `HIGH` | Serious security vulnerabilities requiring prompt action |
| `CRITICAL` | Severe security risks that need immediate remediation |

## 📊 HTML Reports

The tool generates comprehensive HTML reports with:

- **Security Score** showing your overall security posture (0-100)
- **Risk Breakdown** by severity level
- **Interactive Charts** showing findings by resource type and risk level
- **Category-Based Organization** of findings (Compute, Security, Database, Storage, Networking, Cost)
- **Detailed Tables** of all findings with filtering options
- **Remediation Recommendations** for each finding

To generate an HTML report with security score:

```bash
python main.py --html-report security_report.html
```

## 🔍 Infrastructure as Code Scanning

The tool can scan various Infrastructure as Code (IaC) formats for security issues:

```bash
# Scan all templates and code
python main.py --scan templates --template-dir /path/to/code

# Scan specific IaC formats
python main.py --scan cftemplate,terraform,cdk --template-dir /path/to/code
```

## 🔒 Required IAM Permissions

For read-only scanning:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketEncryption",
                "s3:GetBucketVersioning",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSnapshots",
                "ec2:DescribeImages",
                "ec2:DescribeAddresses",
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceAttribute",
                "ec2:DescribeVolumes",
                "rds:DescribeDBSnapshots",
                "rds:DescribeDBInstances",
                "rds:DescribeDBClusters",
                "ecr:DescribeRepositories",
                "ecr:GetRepositoryPolicy",
                "apigateway:GET",
                "lambda:ListFunctions",
                "lambda:GetPolicy",
                "lambda:GetFunctionUrlConfig",
                "cloudfront:ListDistributions",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeListeners",
                "es:ListDomainNames",
                "es:DescribeElasticsearchDomain",
                "iam:ListUsers",
                "iam:GetLoginProfile",
                "iam:ListMFADevices",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed",
                "iam:GetAccountPasswordPolicy",
                "ssm:DescribeInstanceInformation",
                "secretsmanager:ListSecrets",
                "secretsmanager:DescribeSecret",
                "kms:ListKeys",
                "kms:DescribeKey",
                "kms:GetKeyPolicy",
                "kms:GetKeyRotationStatus",
                "kms:ListAliases",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:DescribeMetricFilters",
                "config:DescribeConfigurationRecorders",
                "config:DescribeConfigurationRecorderStatus",
                "config:DescribeDeliveryChannels",
                "config:DescribeConfigRules",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:GetEventSelectors",
                "guardduty:ListDetectors",
                "guardduty:GetDetector",
                "guardduty:ListFindings",
                "guardduty:GetFindings",
                "ec2:DescribeVpcs",
                "ec2:DescribeFlowLogs",
                "ec2:DescribeSubnets",
                "ec2:DescribeNetworkAcls",
                "ec2:DescribeVpcEndpoints",
                "sns:ListTopics",
                "sns:GetTopicAttributes",
                "sqs:ListQueues",
                "sqs:GetQueueAttributes",
                "dynamodb:ListTables",
                "dynamodb:DescribeTable",
                "dynamodb:DescribeContinuousBackups",
                "dynamodb:ListBackups",
                "application-autoscaling:DescribeScalingPolicies",
                "dynamodb:DescribeTimeToLive",
                "rds:DescribeDBClusters",
                "wafv2:ListWebACLs",
                "wafv2:GetWebACL",
                "wafv2:GetLoggingConfiguration",
                "wafv2:ListResourcesForWebACL",
                "waf-regional:ListWebACLs",
                "waf-regional:GetWebACL",
                "waf-regional:ListResourcesForWebACL",
                "lightsail:GetInstances",
                "lightsail:GetInstancePortStates",
                "lightsail:GetInstanceSnapshots",
                "lightsail:GetRelationalDatabases",
                "lightsail:GetRelationalDatabaseSnapshots",
                "lightsail:GetLoadBalancers",
                "cloudformation:ListStacks",
                "cloudformation:GetTemplate"
            ],
            "Resource": "*"
        }
    ]
}
```

## 🛠️ Project Structure

```
aws-exposure-monitor/
├── scanner/                # Resource scanners
│   ├── registry.py         # Scanner registry
│   ├── profile_detector.py # AWS profile detector
│   ├── s3.py               # S3 bucket scanner
│   ├── ec2.py              # EC2 instance scanner
│   ├── iam.py              # IAM user scanner
│   ├── sg.py               # Security group scanner
│   ├── secrets_scanner.py  # Hardcoded secrets scanner
│   ├── cost_scanner.py     # Cost optimization scanner
│   ├── cloudtrail.py       # CloudTrail scanner
│   ├── config.py           # AWS Config scanner
│   ├── guardduty.py        # GuardDuty scanner
│   ├── vpc.py              # VPC scanner
│   ├── sns.py              # SNS topic scanner
│   ├── sqs.py              # SQS queue scanner
│   ├── dynamodb.py         # DynamoDB table scanner
│   ├── aurora.py           # Aurora cluster scanner
│   ├── waf.py              # WAF Web ACL scanner
│   ├── lightsail.py        # Lightsail resource scanner
│   ├── template_scan/      # Template and code scanners
│   │   ├── cftemplate.py   # CloudFormation template scanner
│   │   ├── cdk_scan.py     # CDK code scanner
│   │   ├── terraform_scan.py # Terraform code scanner
│   │   ├── pulumi_scan.py  # Pulumi code scanner
│   │   ├── opentofu_scan.py # OpenTofu code scanner
│   │   ├── sdk_scan.py     # AWS SDK code scanner
│   │   └── scanner.py      # Main template scanner
│   └── ...                 # Other scanners
├── notifier/               # Notification modules
│   ├── slack.py            # Slack notifications
│   └── teams.py            # Teams notifications
├── reporter/               # Reporting modules
│   ├── html_reporter.py    # HTML report generator
│   ├── csv_reporter.py     # CSV report generator
│   ├── json_reporter.py    # JSON report generator
│   ├── security_score.py   # Security score calculator
│   └── console_reporter.py # Console output formatter
├── main.py                 # Main application
├── requirements.txt        # Dependencies
└── README.md               # This file
```

## 📝 License

[MIT License](LICENSE)

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🛠️ Development Status

- **Scanner Modules**: Complete and fully functional
- **HTML Reporting**: Complete and fully functional
- **CSV/JSON Reporting**: Complete and fully functional
- **Console Output**: Complete with colored formatting
- **Risk Level Filtering**: Complete and fully functional
- **Multiple Resource Scanning**: Complete and fully functional
- **Template and Code Scanning**: Complete and fully functional
- **Notification Modules**: Complete and fully functional
- **AWS Profile Auto-Detection**: Complete and fully functional
- **Hardcoded Secrets Detection**: Complete and fully functional
- **Cost Optimization Scanning**: Complete and fully functional
- **Category-Based Organization**: Complete and fully functional
- **Remediation Modules**: Work in progress

---

<div align="center">
  <p>
    <img src="https://img.shields.io/badge/Made%20with-Python-1f425f.svg?style=for-the-badge&logo=python" alt="Made with Python">
    <img src="https://img.shields.io/badge/AWS-Security%20First-FF9900?style=for-the-badge&logo=amazon-aws" alt="AWS Security First">
  </p>
  <p>Made with ❤️ for AWS security</p>
</div>