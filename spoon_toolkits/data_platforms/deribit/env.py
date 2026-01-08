"""Environment variable configuration for Deribit API"""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Try to load .env file from multiple locations
# 1. Current working directory (where user runs the code) - highest priority
# 2. Examples directory (where examples are located)
# 3. Project root directory (DeribitMcp/spoon-toolkit/)
# 4. Parent project root (DeribitMcp/)
examples_dir = Path(__file__).parent / "examples"
project_root = Path(__file__).parent.parent.parent.parent  # spoon-toolkit/
parent_root = project_root.parent  # DeribitMcp/

# Load .env from current directory first, then examples, then project roots
load_dotenv()  # Current working directory (highest priority)
if examples_dir.exists():
    load_dotenv(examples_dir / ".env", override=False)  # examples/.env
if project_root.exists():
    load_dotenv(project_root / ".env", override=False)  # spoon-toolkit/.env
if parent_root.exists():
    load_dotenv(parent_root / ".env", override=False)  # DeribitMcp/.env


class DeribitConfig:
    """Deribit API configuration from environment variables"""
    
    # Required credentials
    CLIENT_ID: Optional[str] = os.getenv("DERIBIT_CLIENT_ID")
    CLIENT_SECRET: Optional[str] = os.getenv("DERIBIT_CLIENT_SECRET")
    
    # Environment settings
    USE_TESTNET: bool = os.getenv("DERIBIT_USE_TESTNET", "false").lower() == "true"
    
    # API URLs
    API_URL: str = os.getenv(
        "DERIBIT_API_URL",
        "https://test.deribit.com/api/v2" if USE_TESTNET else "https://www.deribit.com/api/v2"
    )
    
    TESTNET_API_URL: str = os.getenv(
        "DERIBIT_TESTNET_API_URL",
        "https://test.deribit.com/api/v2"
    )
    
    WS_URL: str = os.getenv(
        "DERIBIT_WS_URL",
        "wss://test.deribit.com/ws/api/v2" if USE_TESTNET else "wss://www.deribit.com/ws/api/v2"
    )
    
    TESTNET_WS_URL: str = os.getenv(
        "DERIBIT_TESTNET_WS_URL",
        "wss://test.deribit.com/ws/api/v2"
    )
    
    # Connection settings
    TIMEOUT: int = int(os.getenv("DERIBIT_TIMEOUT", "30"))
    RETRY_COUNT: int = int(os.getenv("DERIBIT_RETRY_COUNT", "3"))
    CACHE_TTL: int = int(os.getenv("DERIBIT_CACHE_TTL", "300"))
    
    # Logging
    LOG_LEVEL: str = os.getenv("DERIBIT_LOG_LEVEL", "INFO")
    
    # Rate limiting
    RATE_LIMIT: int = int(os.getenv("DERIBIT_RATE_LIMIT", "0"))
    
    @classmethod
    def get_api_url(cls) -> str:
        """Get the appropriate API URL based on testnet setting"""
        return cls.TESTNET_API_URL if cls.USE_TESTNET else cls.API_URL
    
    @classmethod
    def get_ws_url(cls) -> str:
        """Get the appropriate WebSocket URL based on testnet setting"""
        return cls.TESTNET_WS_URL if cls.USE_TESTNET else cls.WS_URL
    
    @classmethod
    def validate_credentials(cls) -> bool:
        """Validate that required credentials are set"""
        if not cls.CLIENT_ID or not cls.CLIENT_SECRET:
            return False
        return True
    
    @classmethod
    def get_credentials(cls) -> tuple[str, str]:
        """Get client credentials"""
        if not cls.validate_credentials():
            raise ValueError(
                "Deribit API credentials not configured. "
                "Please set DERIBIT_CLIENT_ID and DERIBIT_CLIENT_SECRET environment variables."
            )
        return cls.CLIENT_ID, cls.CLIENT_SECRET

