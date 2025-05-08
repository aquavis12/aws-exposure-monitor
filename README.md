# 🛡️ AWS Public Resource Exposure Monitor

<div align="center">

![AWS Exposure Monitor](https://img.shields.io/badge/AWS-Security%20Monitoring-orange?style=for-the-badge&logo=amazon-aws)
![Python](https://img.shields.io/badge/Python-3.7+-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</div>

A powerful security tool that scans your AWS environment for publicly exposed resources, generates detailed reports, and helps you remediate security risks.

## ✨ Features

### 🔍 Comprehensive Resource Scanning

| Resource Type | What We Check |
|---------------|--------------|
| **S3 Buckets** | Public access blocks, bucket policies, ACLs, encryption, versioning, logging |
| **Security Groups** | Open ports (0.0.0.0/0), sensitive services exposure, all traffic rules |
| **EBS Snapshots** | Public sharing permissions, encryption status |
| **RDS Snapshots** | Public sharing permissions, encryption status |
| **AMIs** | Public sharing, launch permissions, encryption of underlying snapshots |
| **ECR Repositories** | Public access policies, public registry settings |
| **API Gateway** | Endpoints without authorization, missing API keys |
| **Lambda Functions** | Public access policies, function URLs without authentication |
| **CloudFront** | Distributions without WAF, S3 origins without OAI, missing default root objects |
| **Elastic IPs** | Unassociated IPs, security of attached instances |
| **RDS Instances** | Public accessibility, encryption, enhanced monitoring |
| **Load Balancers** | Internet-facing LBs, HTTP without HTTPS redirect, outdated SSL/TLS policies |
| **Elasticsearch** | Public access, encryption at rest, node-to-node encryption, HTTPS enforcement |
| **IAM Users** | Inactive users (90+ days), old access keys (60+ days), missing MFA, admin privileges |
| **EC2 Instances** | IMDSv1 usage (instead of IMDSv2), missing SSM agent, unencrypted volumes, public IPs |
| **Secrets & KMS** | Unused secrets (90+ days), pending deletions, disabled key rotation, permissive policies |

### 📊 Rich Reporting Options

- **Interactive HTML Reports** with charts and visualizations
- **JSON output** for integration with other tools
- **Colored console output** for better readability
- **Risk level filtering** to focus on critical issues first
- **Slack notifications** with detailed findings *(work in progress)*
- **Microsoft Teams notifications** with adaptive cards *(work in progress)*

### 🛠️ Remediation Capabilities

- Automatically fix S3 bucket permissions *(work in progress)*
- Make snapshots private *(work in progress)*
- Update security group rules *(work in progress)*
- Restrict RDS instance public access *(work in progress)*
- Disable inactive access keys *(work in progress)*

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/aws-exposure-monitor.git
cd aws-exposure-monitor

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials
aws configure
```

### Basic Usage

```bash
# Scan all resource types in all regions
python main.py

# Scan only S3 buckets 
python main.py --scan s3

# Scan EC2 instances in us-east-1 region
python main.py --scan ec2 --region us-east-1

# Scan IAM users, filter for HIGH risk issues, and generate HTML report
python main.py --scan iam --risk-level HIGH --html-report report.html --region us-east-1


# Scan Secrets Manager and KMS for security issues
python main.py --scan secrets --region us-east-1

# Save findings to JSON
python main.py --output findings.json


```

[IAM Scan](image.png)

## 📋 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--scan TYPE` | Resource type to scan | `--scan s3` |
| `--region REGION` | AWS region to scan | `--region us-east-1` |
| `--output FILE` | Save findings to JSON file | `--output findings.json` |
| `--html-report FILE` | Generate HTML report | `--html-report report.html` |
| `--risk-level LEVEL` | Filter by minimum risk level | `--risk-level HIGH` |
| `--verbose` | Show detailed progress | `--verbose` |
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

### Risk Levels

| Level | Description |
|-------|-------------|
| `LOW` | Minor security concerns that should be addressed |
| `MEDIUM` | Important security issues that need attention |
| `HIGH` | Serious security vulnerabilities requiring prompt action |
| `CRITICAL` | Severe security risks that need immediate remediation |

## 📊 HTML Reports

The tool generates comprehensive HTML reports with:

- Summary dashboard with risk breakdown
- Interactive charts showing findings by resource type and risk level
- Detailed tables of all findings with filtering
- Specific remediation recommendations

[HTML Report Example](https://htmlreportdemo2025.s3.us-east-1.amazonaws.com/report.html)

## 📁 Project Structure

```
aws-exposure-monitor/
├── scanner/                # Resource scanners
│   ├── s3.py              # S3 bucket scanner
│   ├── sg.py              # Security group scanner
│   ├── ebs.py             # EBS snapshot scanner
│   ├── rds.py             # RDS snapshot scanner
│   ├── amis.py            # AMI scanner
│   ├── ecr.py             # ECR repository scanner
│   ├── api.py             # API Gateway scanner
│   ├── lambda_scanner.py  # Lambda function scanner
│   ├── cloudfront.py      # CloudFront scanner
│   ├── eip.py             # Elastic IP scanner
│   ├── rds_instances.py   # RDS instance scanner
│   ├── elb.py             # Load balancer scanner
│   ├── elasticsearch.py   # Elasticsearch scanner
│   ├── iam.py             # IAM user and access key scanner
│   ├── ec2.py             # EC2 instance scanner
│   └── secrets.py         # Secrets Manager and KMS scanner
├── notifier/              # Notification modules (work in progress)
│   ├── slack.py           # Slack notifications
│   └── teams.py           # Microsoft Teams notifications
├── remediator/            # Remediation modules (work in progress)
│   ├── s3.py              # S3 remediation
│   └── ebs.py             # EBS snapshot remediation
├── reporter/              # Reporting modules
│   ├── html_reporter.py   # HTML report generator
│   └── console_reporter.py # Console output formatter
├── main.py                # Main application
├── requirements.txt       # Dependencies
└── README.md              # This file
```

## 🔒 Security Considerations

- This tool requires read access to various AWS services
- For remediation, it requires write access to modify resources
- Use a dedicated IAM role with least privilege
- Store webhook URLs securely (e.g., AWS Secrets Manager)
- Run the tool from a secure environment with proper access controls

### Required IAM Permissions

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
                "kms:ListAliases"
            ],
            "Resource": "*"
        }
    ]
}
```

For remediation capabilities, additional permissions are required.

## 🔄 Continuous Monitoring

For ongoing security monitoring:

1. Deploy as an AWS Lambda function with scheduled triggers
2. Set up CloudWatch Events to trigger scans on resource creation
3. Integrate with AWS Security Hub for centralized findings
4. Configure notifications to alert security teams of new issues
5. Implement automated remediation for critical findings

### Example CloudWatch Events Rule

```json
{
  "source": ["aws.s3", "aws.ec2", "aws.rds"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["s3.amazonaws.com", "ec2.amazonaws.com", "rds.amazonaws.com"],
    "eventName": [
      "CreateBucket", 
      "PutBucketPolicy", 
      "CreateSecurityGroup", 
      "AuthorizeSecurityGroupIngress",
      "RunInstances",
      "CreateDBInstance"
    ]
  }
}
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
- **Notification Modules**: Work in progress
- **Remediation Modules**: Work in progress

---

<div align="center">
Made with ❤️ for AWS security
</div>