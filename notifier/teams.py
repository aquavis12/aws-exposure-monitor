"""
Microsoft Teams Notifier Module - Sends alerts to Microsoft Teams about exposed resources
"""
import json
import requests
from datetime import datetime


class TeamsNotifier:
    def __init__(self, webhook_url):
        """
        Initialize the Microsoft Teams notifier with the webhook URL
        
        Args:
            webhook_url (str): The Teams webhook URL
        """
        self.webhook_url = webhook_url
    
    def send_alert(self, finding):
        """
        Send an alert to Microsoft Teams for a single finding
        
        Args:
            finding (dict): The finding to send an alert for
        
        Returns:
            bool: True if the alert was sent successfully, False otherwise
        """
        try:
            # Determine color based on risk level
            color_map = {
                'LOW': '36a64f',      # Green
                'MEDIUM': 'ffcc00',   # Yellow
                'HIGH': 'ff9900',     # Orange
                'CRITICAL': 'ff0000'  # Red
            }
            theme_color = color_map.get(finding.get('Risk', 'HIGH'), 'ff9900')
            
            # Create the message payload
            resource_type = finding.get('ResourceType', 'Unknown')
            resource_id = finding.get('ResourceId', 'Unknown')
            resource_name = finding.get('ResourceName', resource_id)
            region = finding.get('Region', 'Unknown')
            issue = finding.get('Issue', 'Unknown issue')
            recommendation = finding.get('Recommendation', 'No recommendation provided')
            
            # Create an adaptive card for better formatting
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": theme_color,
                "summary": f"AWS Exposure Alert: {resource_type} {resource_name}",
                "sections": [
                    {
                        "activityTitle": f"AWS Exposure Alert: {resource_type} {resource_name}",
                        "activitySubtitle": issue,
                        "facts": [
                            {
                                "name": "Resource Type",
                                "value": resource_type
                            },
                            {
                                "name": "Resource ID",
                                "value": resource_id
                            },
                            {
                                "name": "Region",
                                "value": region
                            },
                            {
                                "name": "Risk Level",
                                "value": finding.get('Risk', 'HIGH')
                            },
                            {
                                "name": "Recommendation",
                                "value": recommendation
                            }
                        ],
                        "markdown": True
                    }
                ],
                "potentialAction": [
                    {
                        "@type": "OpenUri",
                        "name": "View in AWS Console",
                        "targets": [
                            {
                                "os": "default",
                                "uri": self._get_console_url(finding)
                            }
                        ]
                    }
                ]
            }
            
            # Send the message
            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                return True
            else:
                print(f"Failed to send Teams alert: {response.status_code} {response.text}")
                return False
        
        except Exception as e:
            print(f"Error sending Teams alert: {e}")
            return False
    
    def send_alerts(self, findings):
        """
        Send alerts to Microsoft Teams for multiple findings
        
        Args:
            findings (list): A list of findings to send alerts for
        
        Returns:
            int: The number of alerts sent successfully
        """
        success_count = 0
        
        for finding in findings:
            if self.send_alert(finding):
                success_count += 1
        
        return success_count
    
    def _get_console_url(self, finding):
        """
        Generate an AWS Console URL for the resource
        
        Args:
            finding (dict): The finding containing resource information
        
        Returns:
            str: URL to the resource in AWS Console
        """
        resource_type = finding.get('ResourceType')
        resource_id = finding.get('ResourceId')
        region = finding.get('Region', 'us-east-1')
        
        # Base AWS console URL
        base_url = f"https://{region}.console.aws.amazon.com"
        
        # Resource-specific URLs
        if resource_type == 'S3 Bucket':
            return f"https://s3.console.aws.amazon.com/s3/buckets/{resource_id}"
        elif resource_type == 'Security Group':
            return f"{base_url}/ec2/v2/home?region={region}#SecurityGroup:groupId={resource_id}"
        elif resource_type == 'EBS Snapshot':
            return f"{base_url}/ec2/v2/home?region={region}#Snapshots:visibility=owned;snapshotId={resource_id}"
        elif resource_type == 'RDS Snapshot':
            return f"{base_url}/rds/home?region={region}#snapshot:id={resource_id}"
        elif resource_type == 'AMI':
            return f"{base_url}/ec2/v2/home?region={region}#Images:visibility=owned-by-me;imageId={resource_id}"
        elif resource_type == 'ECR Repository':
            return f"{base_url}/ecr/repositories?region={region}"
        elif resource_type.startswith('API Gateway'):
            api_id = resource_id.split('/')[0] if '/' in resource_id else resource_id
            return f"{base_url}/apigateway/home?region={region}#/apis/{api_id}/resources/"
        
        # Default to AWS console home
        return f"https://console.aws.amazon.com/console/home?region={region}"