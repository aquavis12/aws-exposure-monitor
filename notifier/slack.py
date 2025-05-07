"""
Slack Notifier Module - Sends alerts to Slack about exposed resources
"""
import json
import requests
from datetime import datetime


class SlackNotifier:
    def __init__(self, webhook_url):
        """
        Initialize the Slack notifier with the webhook URL
        
        Args:
            webhook_url (str): The Slack webhook URL
        """
        self.webhook_url = webhook_url
    
    def send_alert(self, finding):
        """
        Send an alert to Slack for a single finding
        
        Args:
            finding (dict): The finding to send an alert for
        
        Returns:
            bool: True if the alert was sent successfully, False otherwise
        """
        try:
            # Determine color based on risk level
            color_map = {
                'LOW': '#36a64f',      # Green
                'MEDIUM': '#ffcc00',   # Yellow
                'HIGH': '#ff9900',     # Orange
                'CRITICAL': '#ff0000'  # Red
            }
            color = color_map.get(finding.get('Risk', 'HIGH'), '#ff9900')
            
            # Create the message payload
            resource_type = finding.get('ResourceType', 'Unknown')
            resource_id = finding.get('ResourceId', 'Unknown')
            resource_name = finding.get('ResourceName', resource_id)
            region = finding.get('Region', 'Unknown')
            issue = finding.get('Issue', 'Unknown issue')
            recommendation = finding.get('Recommendation', 'No recommendation provided')
            
            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"AWS Exposure Alert: {resource_type} {resource_name}",
                        "text": issue,
                        "fields": [
                            {
                                "title": "Resource Type",
                                "value": resource_type,
                                "short": True
                            },
                            {
                                "title": "Resource ID",
                                "value": resource_id,
                                "short": True
                            },
                            {
                                "title": "Region",
                                "value": region,
                                "short": True
                            },
                            {
                                "title": "Risk Level",
                                "value": finding.get('Risk', 'HIGH'),
                                "short": True
                            },
                            {
                                "title": "Recommendation",
                                "value": recommendation,
                                "short": False
                            }
                        ],
                        "footer": "AWS Exposure Monitor",
                        "ts": int(datetime.now().timestamp())
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
                print(f"Failed to send Slack alert: {response.status_code} {response.text}")
                return False
        
        except Exception as e:
            print(f"Error sending Slack alert: {e}")
            return False
    
    def send_alerts(self, findings):
        """
        Send alerts to Slack for multiple findings
        
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
        Send an alert to Teams for a single finding
        
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
        Send alerts to Teams for multiple findings
        
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