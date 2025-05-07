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
| **S3 Buckets** | Public access blocks, bucket policies, ACLs, encryption |
| **Security Groups** | Open ports (0.0.0.0/0), sensitive services exposure |
| **EBS Snapshots** | Public sharing permissions, encryption |
| **RDS Snapshots** | Public sharing permissions, encryption |
| **AMIs** | Public sharing, launch permissions, encryption |
| **ECR Repositories** | Public access policies |
| **API Gateway** | Endpoints without authorization |
| **Lambda Functions** | Public access policies, function URLs |
| **CloudFront** | Distributions without WAF, S3 origins without OAI |
| **Elastic IPs** | Unassociated IPs, security of attached instances |
| **RDS Instances** | Public accessibility, encryption |
| **Load Balancers** | Internet-facing LBs, security configurations |
| **Elasticsearch** | Public access, encryption |

### 📊 Rich Reporting Options

- **Interactive HTML Reports** with charts and visualizations
- **JSON output** for integration with other tools
- **Colored console output** for better readability
- **Slack notifications** with detailed findings *(work in progress)*
- **Microsoft Teams notifications** with adaptive cards *(work in progress)*

### 🛠️ Remediation Capabilities

- Automatically fix S3 bucket permissions *(work in progress)*
- Make snapshots private *(work in progress)*
- Update security group rules *(work in progress)*
- Restrict RDS instance public access *(work in progress)*

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

# Scan a specific region
python main.py --region us-east-1

# Scan S3 buckets in a specific region
python main.py --scan s3 --region us-east-1

# Generate an HTML report
python main.py --html-report report.html

# Save findings to JSON
python main.py --output findings.json
```

## 📋 Command Line Options

| Option | Description |
|--------|-------------|
| `--scan TYPE` | Resource type to scan (`s3`, `ebs`, `rds`, `amis`, `sg`, `ecr`, `api`, `cloudfront`, `lambda`, `eip`, `rds-instances`, `elb`, `elasticsearch`, or `all`) |
| `--region REGION` | AWS region to scan (e.g., `us-east-1`, `eu-west-1`) |
| `--output FILE` | Save findings to JSON file |
| `--html-report FILE` | Generate HTML report |
| `--notify` | Send notifications for findings |
| `--slack-webhook URL` | Slack webhook URL for notifications |
| `--teams-webhook URL` | Microsoft Teams webhook URL for notifications |
| `--remediate` | Automatically fix issues (use with caution) |
| `--verbose` | Show detailed progress information |
| `--no-color` | Disable colored output |

## 📊 HTML Reports

The tool generates comprehensive HTML reports with:

- Summary dashboard with risk breakdown
- Interactive charts showing findings by resource type and risk level
- Detailed tables of all findings with filtering
- Specific remediation recommendations

![HTML Report Example](https://via.placeholder.com/800x400?text=HTML+Report+Example)

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
│   └── elasticsearch.py   # Elasticsearch scanner
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

## 🔄 Continuous Monitoring

For ongoing security monitoring:

1. Deploy as an AWS Lambda function with scheduled triggers
2. Set up CloudWatch Events to trigger scans on resource creation
3. Integrate with AWS Security Hub for centralized findings

## 📝 License

[MIT License](LICENSE)

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🛠️ Development Status

- **Scanner Modules**: Complete and fully functional
- **HTML Reporting**: Complete and fully functional
- **Console Output**: Complete with colored formatting
- **Notification Modules**: Work in progress
- **Remediation Modules**: Work in progress

---

<div align="center">
Made with ❤️ for AWS security
</div>