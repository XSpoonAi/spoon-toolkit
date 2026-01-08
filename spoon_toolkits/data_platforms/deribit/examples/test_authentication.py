"""Test authentication flow"""

import asyncio
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from spoon_toolkits.deribit.env import DeribitConfig
from spoon_toolkits.deribit.auth import DeribitAuth


async def test_authentication():
    """Test OAuth2 authentication"""
    print("=" * 60)
    print("Testing Deribit Authentication")
    print("=" * 60)
    
    # Check credentials
    if not DeribitConfig.validate_credentials():
        print("❌ Error: API credentials not configured!")
        print("   Please set DERIBIT_CLIENT_ID and DERIBIT_CLIENT_SECRET")
        print("   in your .env file or environment variables.")
        return
    
    print(f"✅ Credentials found")
    print(f"   Using {'Testnet' if DeribitConfig.USE_TESTNET else 'Mainnet'}")
    
    auth = DeribitAuth()
    
    # Test 1: Initial authentication
    print("\n[Test 1] Authenticating...")
    try:
        result = await auth.authenticate()
        print("✅ Authentication successful!")
        print(f"   Access token: {auth.get_access_token()[:20]}...")
        print(f"   Scope: {result.get('scope', 'N/A')}")
        print(f"   Expires in: {result.get('expires_in', 'N/A')} seconds")
    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        return
    
    # Test 2: Token validity check
    print("\n[Test 2] Checking token validity...")
    is_valid = auth.is_token_valid()
    print(f"✅ Token is {'valid' if is_valid else 'invalid'}")
    
    # Test 3: Token refresh (if refresh_token available)
    if auth.refresh_token:
        print("\n[Test 3] Testing token refresh...")
        try:
            result = await auth.refresh_access_token()
            print("✅ Token refresh successful!")
            print(f"   New access token: {auth.get_access_token()[:20]}...")
        except Exception as e:
            print(f"⚠️  Token refresh failed (may be expected): {e}")
    else:
        print("\n[Test 3] Skipping token refresh (no refresh_token)")
    
    # Test 4: Ensure authenticated
    print("\n[Test 4] Testing ensure_authenticated...")
    try:
        await auth.ensure_authenticated()
        print("✅ ensure_authenticated() successful!")
    except Exception as e:
        print(f"❌ ensure_authenticated() failed: {e}")
    
    print("\n" + "=" * 60)
    print("Authentication Test Complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_authentication())

