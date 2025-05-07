# AWS Public Resource Exposure Monitor

A comprehensive tool to detect, alert on, and remediate publicly exposed AWS resources, helping to improve your cloud security posture.

![AWS Exposure Monitor](https://img.shields.io/badge/AWS-Security%20Monitoring-orange)
![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## Features

- **Detect public resources:**
  - S3 buckets (BlockPublicAccess settings)
  - EBS/RDS snapshots
  - AMIs
  - Security groups (open to 0.0.0.0/0 on sensitive ports)
  - ECR repositories with public access
  - API Gateway endpoints without authorization
  - CloudFront distributions with public access
  - Lambda functions with public access policies
  - Elastic IP addresses
  - RDS instances with public accessibility
  - Elastic Load Balancers (public-facing)
  - Elasticsearch domains with public access

- **Alert mechanisms:**
  - Slack integration via Webhooks
  - Microsoft Teams integration via Webhooks
  - Email notifications via Amazon SES (optional)
  - JSON output for integration with other tools
  - HTML reports with charts and visualizations
  - AWS Security Hub integration (optional)

- **Optional auto-remediation:**
  - Fix S3 bucket permissions
  - Make snapshots private
  - Update security group rules
  - Restrict RDS instance public access
  - More remediators can be added as needed

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/aws-exposure-monitor.git
   cd aws-exposure-monitor
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure AWS credentials:
   ```
   aws configure
   ```
   Or set up environment variables:
   ```
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_DEFAULT_REGION=your_default_region
   ```

## Usage

### Basic Scan

Scan all resource types and print results:

```
python main.py
```

### Scan Specific Resources

Scan only S3 buckets:

```
python main.py --scan s3
```

Available scan options: `s3`, `ebs`, `rds`, `amis`, `sg`, or `all` (default)

### Generate HTML Report

Generate a detailed HTML report with charts and tables:

```
python main.py --html-report report.html
```

### Save Results to JSON File

```
python main.py --output findings.json
```

### Send Notifications

Send alerts to Slack:

```
python main.py --notify --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

Send alerts to Microsoft Teams:

```
python main.py --notify --teams-webhook https://your-teams-webhook-url
```

### Auto-Remediation

Automatically fix issues (use with caution):

```
python main.py --remediate
```

## HTML Reports

The tool can generate comprehensive HTML reports with:

- Summary of findings by risk level
- Interactive charts and visualizations
- Detailed tables of all findings
- Filtering and sorting capabilities
- Recommendations for remediation

Example:

```
python main.py --html-report exposure_report.html
```

## Microsoft Teams Integration

The Microsoft Teams notifier sends formatted adaptive cards with:

- Color-coded risk levels
- Resource details and region
- Issue description
- Remediation recommendations

To set up Teams integration:

1. Create an incoming webhook in your Teams channel
2. Pass the webhook URL to the tool using the `--teams-webhook` parameter
3. Customize the message format in `notifier/teams.py` if needed

## Project Structure

```
aws-exposure-monitor/
├── scanner/
│   ├── s3.py         # S3 bucket scanner
│   ├── ebs.py        # EBS snapshot scanner
│   ├── rds.py        # RDS snapshot scanner
│   ├── amis.py       # AMI scanner
│   ├── sg.py         # Security group scanner
│   ├── ecr.py        # ECR repository scanner
│   └── api.py        # API Gateway scanner
├── notifier/
│   ├── slack.py      # Slack notification module
│   └── teams.py      # Microsoft Teams notification module
├── remediator/
│   ├── s3.py         # S3 remediation module
│   └── ebs.py        # EBS snapshot remediation
├── reporter/
│   ├── html_reporter.py  # HTML report generator
│   └── console_reporter.py  # Colored console output
├── main.py           # Main application
├── requirements.txt  # Dependencies
└── README.md         # This file
```

## Adding New Scanners

To add a new scanner:

1. Create a new file in the `scanner/` directory
2. Implement a function that returns findings in the standard format
3. Import and call the function from `main.py`

## Adding New Remediators

To add a new remediator:

1. Create a new file in the `remediator/` directory
2. Implement a function that takes findings and performs remediation
3. Import and call the function from `main.py`

## Continuous Monitoring

For continuous monitoring:

1. Deploy as an AWS Lambda function with scheduled triggers
2. Set up CloudWatch Events to trigger scans on resource creation/modification
3. Integrate with AWS Security Hub for centralized findings management

## Security Considerations

- This tool requires read access to various AWS services
- For remediation, it requires write access to modify resources
- Consider using a dedicated IAM role with least privilege
- Store webhook URLs and credentials securely (e.g., AWS Secrets Manager)

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.