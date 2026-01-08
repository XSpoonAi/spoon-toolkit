"""Pytest configuration for Deribit toolkit tests"""

import pytest
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


@pytest.fixture(scope="session")
def test_credentials():
    """Fixture for test credentials"""
    return {
        "client_id": os.getenv("DERIBIT_CLIENT_ID"),
        "client_secret": os.getenv("DERIBIT_CLIENT_SECRET"),
        "use_testnet": os.getenv("DERIBIT_USE_TESTNET", "false").lower() == "true"
    }


@pytest.fixture(scope="session")
def has_credentials():
    """Check if credentials are available"""
    client_id = os.getenv("DERIBIT_CLIENT_ID")
    client_secret = os.getenv("DERIBIT_CLIENT_SECRET")
    return bool(client_id and client_secret)

