"""
AWS Profile Detector Module - Automatically detects and uses AWS profiles
"""
import os
import configparser
from pathlib import Path
import boto3
from botocore.exceptions import ClientError, ProfileNotFound

def get_available_profiles():
    """
    Get all available AWS profiles from credentials and config files
    
    Returns:
        list: List of available AWS profile names
    """
    profiles = set()
    
    # Check AWS credentials file
    credentials_path = os.path.expanduser("~/.aws/credentials")
    if os.path.isfile(credentials_path):
        config = configparser.ConfigParser()
        config.read(credentials_path)
        for section in config.sections():
            profiles.add(section)
    
    # Check AWS config file
    config_path = os.path.expanduser("~/.aws/config")
    if os.path.isfile(config_path):
        config = configparser.ConfigParser()
        config.read(config_path)
        for section in config.sections():
            # In config file, profiles are prefixed with "profile " except for 'default'
            if section.startswith("profile "):
                profiles.add(section[8:])  # Remove "profile " prefix
            elif section == "default":
                profiles.add(section)
    
    return sorted(list(profiles))

def test_profile_access(profile_name):
    """
    Test if a profile has valid credentials
    
    Args:
        profile_name (str): AWS profile name to test
        
    Returns:
        dict: Dictionary with access status and account info if successful
    """
    try:
        # Try to create a session with this profile
        session = boto3.Session(profile_name=profile_name)
        sts_client = session.client('sts')
        
        # Get caller identity to verify access
        identity = sts_client.get_caller_identity()
        
        return {
            "valid": True,
            "account_id": identity.get("Account"),
            "user_id": identity.get("UserId"),
            "arn": identity.get("Arn")
        }
    except (ClientError, ProfileNotFound) as e:
        return {
            "valid": False,
            "error": str(e)
        }

def get_usable_profiles():
    """
    Get all usable AWS profiles with their account information
    
    Returns:
        list: List of dictionaries containing profile information
    """
    profiles = get_available_profiles()
    usable_profiles = []
    
    for profile in profiles:
        result = test_profile_access(profile)
        if result["valid"]:
            usable_profiles.append({
                "profile_name": profile,
                "account_id": result["account_id"],
                "user_id": result["user_id"],
                "arn": result["arn"]
            })
    
    return usable_profiles

def create_session_for_profile(profile_name=None, region=None):
    """
    Create a boto3 session for the specified profile
    
    Args:
        profile_name (str, optional): AWS profile name to use
        region (str, optional): AWS region to use
        
    Returns:
        boto3.Session: Boto3 session configured with the profile
    """
    if profile_name:
        return boto3.Session(profile_name=profile_name, region_name=region)
    else:
        return boto3.Session(region_name=region)