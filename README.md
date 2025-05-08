# AWS Public Resource Exposure Monitor

<div align="center">

![AWS Exposure Monitor](https://img.shields.io/badge/AWS-Security%20Monitoring-orange?style=for-the-badge&logo=amazon-aws)
![Python](https://img.shields.io/badge/Python-3.7+-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</div>

A powerful security tool that scans your AWS environment for publicly exposed resources, security vulnerabilities, and misconfigurations. It generates detailed reports and helps you identify and remediate security risks.
![](/images/image-3.png)
## ✨ Features

- **Comprehensive Scanning** of 20+ AWS services
- **Multi-Region Support** to scan your entire AWS footprint
- **Security Scoring** to track your security posture over time
- **Interactive HTML Reports** with visualizations and filtering
- **Risk-Based Prioritization** to focus on critical issues first
- **Notification Integration** with Slack and Microsoft Teams
- **Comma-Separated Scanning** to target specific services

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

# Filter for HIGH risk issues and generate HTML report
python main.py --risk-level HIGH --html-report report.html

# Scan IAM users in us-east-1 region
python main.py --scan iam --region us-east-1

# Save findings to JSON file
python main.py --output findings.json

# Send notifications to Slack
python main.py --notify --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Send notifications to Microsoft Teams
python main.py --notify --teams-webhook https://your-org.webhook.office.com/webhookb2/your-webhook-url

# Combine multiple options
python main.py --scan ec2,s3 --region us-east-1 --risk-level MEDIUM --html-report report.html
```

## 🛡️ Scan Outputs 

*IAM SCAN*
![](/images/image.png)

*Secrets and KMS Scan*
![](/images/image-1.png)

*S3 Bucket Scan*
![](/images/image-2.png)

*HTML Report with Security Score*
👉 [View Security Report](https://htmlreportdemo2025.s3.us-east-1.amazonaws.com/report.html)

## 📋 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--scan TYPES` | Resource type(s) to scan (comma-separated) | `--scan s3,ec2,iam` |
| `--region REGION` | AWS region to scan | `--region us-east-1` |
| `--risk-level LEVEL` | Filter by minimum risk level (LOW, MEDIUM, HIGH, CRITICAL, ALL) | `--risk-level HIGH` |
| `--output FILE` | Save findings to JSON file | `--output findings.json` |
| `--html-report FILE` | Generate HTML report with security score | `--html-report report.html` |
| `--list-scanners` | List all available scanners | `--list-scanners` |
| `--notify` | Send notifications for findings | `--notify` |
| `--slack-webhook URL` | Slack webhook URL for notifications | `--slack-webhook https://hooks.slack.com/...` |
| `--teams-webhook URL` | Microsoft Teams webhook URL for notifications | `--teams-webhook https://your-org.webhook...` |
| `--verbose` | Show detailed progress information | `--verbose` |
| `--no-color` | Disable colored output | `--no-color` |

### Available Scan Types

| Scan Type | Description | Command |
|-----------|-------------|---------|
| `all` | All resource types (default) | `--scan all` |
| `s3` | S3 buckets | `--scan s3` |
| `ebs` | EBS snapshots | `--scan ebs` |
| `rds` | RDS snapshots | `--scan rds` |
| `amis` | Amazon Machine Images | `--scan amis` |
| `sg` | Security Groups | `--scan sg` |
| `ecr` | ECR repositories | `--scan ecr` |
| `api` | API Gateway endpoints | `--scan api` |
| `cloudfront` | CloudFront distributions | `--scan cloudfront` |
| `lambda` | Lambda functions | `--scan lambda` |
| `eip` | Elastic IPs | `--scan eip` |
| `rds-instances` | RDS instances | `--scan rds-instances` |
| `elb` | Elastic Load Balancers | `--scan elb` |
| `elasticsearch` | Elasticsearch domains | `--scan elasticsearch` |
| `iam` | IAM users and access keys | `--scan iam` |
| `ec2` | EC2 instances | `--scan ec2` |
| `secrets` | Secrets Manager and KMS | `--scan secrets` |
| `cloudwatch` | CloudWatch Logs | `--scan cloudwatch` |
| `sns` | SNS topics | `--scan sns` |
| `sqs` | SQS queues | `--scan sqs` |
| `dynamodb` | DynamoDB tables | `--scan dynamodb` |
| `config` | AWS Config | `--scan config` |
| `cloudtrail` | CloudTrail | `--scan cloudtrail` |
| `guardduty` | GuardDuty | `--scan guardduty` |
| `vpc` | VPC | `--scan vpc` |

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
- **Detailed Tables** of all findings with filtering options
- **Remediation Recommendations** for each finding

### Security Score

The security score is calculated based on the severity of findings:
- **90-100**: Excellent - Very few security issues
- **75-89**: Good - Relatively secure with some issues to address
- **60-74**: Fair - Several security issues requiring attention
- **40-59**: Poor - Significant security vulnerabilities
- **0-39**: Critical - Critical security issues requiring immediate action

To generate an HTML report with security score:

```bash
python main.py --html-report security_report.html
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
                "dynamodb:DescribeTimeToLive"
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
│   ├── s3.py               # S3 bucket scanner
│   ├── ec2.py              # EC2 instance scanner
│   ├── iam.py              # IAM user scanner
│   ├── sg.py               # Security group scanner
│   ├── cloudtrail.py       # CloudTrail scanner
│   ├── config.py           # AWS Config scanner
│   ├── guardduty.py        # GuardDuty scanner
│   ├── vpc.py              # VPC scanner
│   ├── sns.py              # SNS topic scanner
│   ├── sqs.py              # SQS queue scanner
│   ├── dynamodb.py         # DynamoDB table scanner
│   └── ...                 # Other scanners
├── notifier/               # Notification modules
│   ├── slack.py            # Slack notifications
│   └── teams.py            # Teams notifications
├── reporter/               # Reporting modules
│   ├── html_reporter.py    # HTML report generator
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
- **Console Output**: Complete with colored formatting
- **Risk Level Filtering**: Complete and fully functional
- **Multiple Resource Scanning**: Complete and fully functional
- **Notification Modules**: Work in progress
- **Remediation Modules**: Work in progress

---

<div align="center">
  <p>
    <img src="https://img.shields.io/badge/Made%20with-Python-1f425f.svg?style=for-the-badge&logo=python" alt="Made with Python">
    <img src="https://img.shields.io/badge/AWS-Security%20First-FF9900?style=for-the-badge&logo=amazon-aws" alt="AWS Security First">
  </p>
  <p>Made with ❤️ for AWS security</p>
</div>