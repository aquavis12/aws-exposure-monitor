# Commands Reference

## Basic Commands

### List Available Scanners
```bash
python main.py --list-scanners
```

### Scan All Resources
```bash
python main.py
```

### Scan Specific Services
```bash
# Single service
python main.py --scan s3

# Multiple services (comma-separated, no spaces)
python main.py --scan ec2,s3,iam

# By category
python main.py --scan compute
python main.py --scan security
python main.py --scan database
python main.py --scan storage
python main.py --scan networking
python main.py --scan cost
```

### Comprehensive Security Audit
```bash
# Scan all resources with audit attribute checks
python main.py --scan audit
```

## Regional Scanning

### Specific Region
```bash
python main.py --region us-east-1
python main.py --scan ec2 --region eu-west-1
```

### AWS Profile
```bash
python main.py --profile production
python main.py --scan s3 --profile dev-account
```

## Risk Level Filtering

### Filter by Risk Level
```bash
python main.py --risk-level HIGH
python main.py --risk-level CRITICAL
python main.py --risk-level MEDIUM
python main.py --scan ec2 --risk-level HIGH
```

## Report Generation

### HTML Reports
```bash
# Basic HTML report
python main.py --html-report security_report.html

# HTML report with risk filtering
python main.py --risk-level HIGH --html-report high_risk_report.html

# Category-specific HTML report
python main.py --scan security --html-report security_audit.html
```

### CSV Reports
```bash
python main.py --csv-report findings.csv
python main.py --scan s3,ec2 --csv-report compute_storage.csv
```

### JSON Reports
```bash
python main.py --json-report findings.json
python main.py --scan iam --json-report iam_findings.json
```

### Cost Reports
```bash
# Detailed monthly cost report
python main.py --cost-report monthly_costs.html

# Cost optimization scan with report
python main.py --scan cost --html-report cost_optimization.html
```

## Infrastructure as Code Scanning

### Terraform Code Scanning
```bash
python main.py --scan terraform --terraform-dir /path/to/terraform
python main.py --scan terraform --terraform-dir ./infrastructure
```

## Notifications

### Slack Notifications
```bash
python main.py --notify --slack-webhook https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
```

### Microsoft Teams Notifications
```bash
python main.py --notify --teams-webhook https://your-org.webhook.office.com/YOUR/TEAMS/WEBHOOK
```

## Advanced Examples

### Complete Security Audit with Reports
```bash
python main.py --scan audit --risk-level HIGH --html-report audit_report.html --csv-report audit_findings.csv --notify --slack-webhook YOUR_WEBHOOK
```

### Multi-Service Scan with Cost Analysis
```bash
python main.py --scan ec2,s3,rds,cost --region us-east-1 --html-report infrastructure_audit.html --cost-report cost_analysis.html
```

### Production Environment Audit
```bash
python main.py --profile production --scan security --risk-level CRITICAL --html-report prod_security.html --notify
```

### Development Environment Quick Scan
```bash
python main.py --profile dev --scan compute,storage --region us-west-2 --csv-report dev_findings.csv
```

## Output Control

### Verbose Output
```bash
python main.py --verbose
```

### No Color Output
```bash
python main.py --no-color
```

## Combining Options

### Comprehensive Production Scan
```bash
python main.py \
  --profile production \
  --scan audit \
  --risk-level HIGH \
  --html-report prod_audit.html \
  --csv-report prod_findings.csv \
  --cost-report prod_costs.html \
  --notify \
  --slack-webhook YOUR_WEBHOOK \
  --verbose
```

### Quick Security Check
```bash
python main.py --scan security --risk-level CRITICAL --region us-east-1
```

### Cost Optimization Analysis
```bash
python main.py --scan cost --cost-report cost_savings.html --csv-report cost_findings.csv
```