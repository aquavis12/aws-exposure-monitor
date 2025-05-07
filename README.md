# 🔍 AWS Public Resource Exposure Monitor

**Open-source tool to detect and alert on publicly exposed AWS resources.**

---

## 🚨 Features

- Detects public:
  - ✅ S3 Buckets (ACLs, Policies)
  - ✅ EBS Snapshots
  - ✅ RDS Snapshots
  - ✅ AMIs
  - ✅ Security Groups (open to 0.0.0.0/0)
- Slack or Microsoft Teams Alerts (Webhook-based)
- Optional auto-remediation via AWS Lambda
- Designed to run on:
  - Local/CLI
  - Lambda (with EventBridge trigger)
  - Docker/K8s (future roadmap)

---

## 📦 Tech Stack

- Python 3.x
- Boto3
- Slack SDK / Microsoft Teams Webhook
- AWS Lambda (optional)

---

## 🚀 Getting Started

```bash
git clone https://github.com/your-org/aws-exposure-monitor.git
cd aws-exposure-monitor
pip install -r requirements.txt
python main.py
