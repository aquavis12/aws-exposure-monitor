# main.py

from scanner import s3, ebs, rds, amis, sg
from notifier import slack
from remediator import s3 as s3_remediator
import os

def main():
    findings = []

    # Run scanners
    findings += s3.scan()
    findings += ebs.scan()
    findings += rds.scan()
    findings += amis.scan()
    findings += sg.scan()

    # Send notifications
    for finding in findings:
        slack.send_alert(finding)

        # Optional remediation
        if os.getenv("REMEDIATION_ENABLED", "false").lower() == "true":
            if finding['type'] == 's3':
                s3_remediator.remediate(finding)

if __name__ == "__main__":
    main()
