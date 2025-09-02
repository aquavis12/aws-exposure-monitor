# AWS Exposure Monitor

<div align="center">

![AWS Exposure Monitor](https://img.shields.io/badge/AWS-Security%20Monitoring-orange?style=for-the-badge&logo=amazon-aws)
![Python](https://img.shields.io/badge/Python-3.7+-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</div>

A powerful security tool that scans your AWS environment for publicly exposed resources, security vulnerabilities, and cost optimization opportunities. Generates detailed reports with risk-based prioritization.

## ✨ Features

- **Comprehensive Scanning** of 30+ AWS services
- **Multi-Region Support** to scan your entire AWS footprint
- **Interactive HTML Reports** with visualizations and filtering
- **CSV and JSON Reports** for integration with other tools
- **Risk-Based Prioritization** (LOW, MEDIUM, HIGH, CRITICAL)
- **Notification Integration** with Slack and Microsoft Teams
- **Category-Based Organization** (Compute, Security, Database, Storage, Networking)

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/aquavis12/aws-exposure-monitor.git
cd aws-exposure-monitor
pip install -r requirements.txt
aws configure
```

### Basic Usage

```bash
# List all available scanners
python main.py --list-scanners

# Scan all resources in all regions
python main.py

# Scan specific services
python main.py --scan ec2,s3,iam

# Scan by category
python main.py --scan compute
python main.py --scan security

# Filter for HIGH risk issues and generate HTML report
python main.py --risk-level HIGH --html-report report.html
```

## 📋 Available Scan Types

### By Category
- **compute** - EC2, AMIs, ECR, Lambda, Lightsail
- **security** - IAM, Security Groups, Secrets, CloudTrail, GuardDuty, WAF
- **database** - RDS, Aurora, DynamoDB, Elasticsearch
- **storage** - S3, EBS
- **networking** - API Gateway, CloudFront, ELB, VPC, SNS, SQS

### Individual Services
`s3`, `ec2`, `iam`, `sg`, `rds`, `api`, `lambda`, `cloudfront`, `elb`, `vpc`, `sns`, `sqs`, `dynamodb`, `secrets`, `cloudtrail`, `guardduty`, `waf`, `terraform`

## 📊 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--scan TYPES` | Resource type(s) to scan | `--scan s3,ec2,iam` |
| `--region REGION` | AWS region to scan | `--region us-east-1` |
| `--profile PROFILE` | AWS profile to use | `--profile my-profile` |
| `--risk-level LEVEL` | Filter by risk level | `--risk-level HIGH` |
| `--html-report FILE` | Generate HTML report | `--html-report report.html` |
| `--csv-report FILE` | Generate CSV report | `--csv-report findings.csv` |
| `--json-report FILE` | Generate JSON report | `--json-report findings.json` |

| `--terraform-dir DIR` | Terraform code directory | `--terraform-dir /path/to/tf` |
| `--list-scanners` | List all available scanners | `--list-scanners` |
| `--notify` | Send notifications | `--notify` |
| `--slack-webhook URL` | Slack webhook URL | `--slack-webhook https://...` |
| `--teams-webhook URL` | Teams webhook URL | `--teams-webhook https://...` |



## 📝 Documentation

- [Commands Reference](md/commands.md) - Detailed command examples
- [Scanner Details](md/scanners.md) - Information about each scanner
- [Report Examples](md/reports.md) - Sample reports and outputs

## 🛠️ Project Structure

```
aws-exposure-monitor/
├── scanner/           # Resource scanners
├── reporter/          # Report generators
├── notifier/          # Notification modules
├── md/               # Documentation
├── main.py           # Main application
└── requirements.txt  # Dependencies
```

## 📝 License

[MIT License](LICENSE)

---

<div align="center">
  <p>Made with ❤️ for AWS security</p>
</div>