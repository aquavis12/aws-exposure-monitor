# AWS Public Resource Exposure Monitor

A tool to detect and alert on publicly exposed AWS resources, helping to improve your cloud security posture.

## Features

- **Detect public resources:**
  - S3 buckets (BlockPublicAccess settings)
  - EBS/RDS snapshots
  - AMIs
  - Security groups (open to 0.0.0.0/0 on sensitive ports)

- **Alert mechanisms:**
  - Slack integration via Webhooks
  - Microsoft Teams integration via Webhooks
  - JSON output for integration with other tools

- **Optional auto-remediation:**
  - Fix S3 bucket permissions
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

### Save Results to File

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

## Project Structure

```
aws-exposure-monitor/
├── scanner/
│   ├── s3.py         # S3 bucket scanner
│   ├── ebs.py        # EBS snapshot scanner
│   ├── rds.py        # RDS snapshot scanner
│   ├── amis.py       # AMI scanner
│   └── sg.py         # Security group scanner
├── notifier/
│   └── slack.py      # Slack/Teams notification module
├── remediator/
│   └── s3.py         # S3 remediation module
├── main.py           # Main application
├── requirements.txt  # Dependencies
└── README.md         # This file
```

## Adding New Scanners

To add a new scanner:

1. Create a new file in the `scanner/` directory
2. Implement a function that returns findings in the standard format
3. Import and call the function from `main.py`

## Security Considerations

- This tool requires read access to various AWS services
- For remediation, it requires write access to modify resources
- Consider using a dedicated IAM role with least privilege

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.