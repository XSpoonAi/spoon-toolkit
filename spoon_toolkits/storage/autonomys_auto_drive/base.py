"""Base module for Autonomys Auto Drive tools"""

import os
from .provider import AutoDriveProvider

def get_provider() -> AutoDriveProvider:
    """
    Get Auto Drive provider instance.
    Validates that the API key is configured before initialization.
    """
    api_key = os.environ.get('AUTONOMYS_AUTO_DRIVE_API_KEY', 'apikey')
    auth_provider = os.environ.get('AUTONOMYS_AUTO_DRIVE_AUTH_PROVIDER', 'apikey')
    
    if not api_key:
        raise RuntimeError(
            "AUTONOMYS_AUTO_DRIVE_API_KEY is not set in environment variables. "
            "Please configure it to use Autonomys Auto Drive tools."
        )
        
    return AutoDriveProvider(
        api_key=api_key,
        auth_provider=auth_provider
    )
