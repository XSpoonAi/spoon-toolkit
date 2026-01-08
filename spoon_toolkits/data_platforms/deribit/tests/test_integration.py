"""Integration tests for Deribit API toolkit"""

import pytest
import asyncio
from spoon_toolkits.data_platforms.deribit.env import DeribitConfig
from spoon_toolkits.data_platforms.deribit.jsonrpc_client import DeribitJsonRpcClient
from spoon_toolkits.data_platforms.deribit.auth import DeribitAuth


@pytest.mark.integration
class TestDeribitJsonRpcClientIntegration:
    """Integration tests for JSON-RPC client"""

    @pytest.mark.asyncio
    async def test_public_api_connection(self):
        """Test connection to Deribit public API"""
        async with DeribitJsonRpcClient() as client:
            result = await client.call(
                "public/get_instruments",
                {"currency": "BTC", "kind": "future"}
            )
            assert result is not None
            assert isinstance(result, list)
            if result:
                assert "instrument_name" in result[0]

    @pytest.mark.asyncio
    async def test_get_order_book(self):
        """Test getting order book"""
        async with DeribitJsonRpcClient() as client:
            result = await client.call(
                "public/get_order_book",
                {"instrument_name": "BTC-PERPETUAL", "depth": 5}
            )
            assert result is not None
            assert "bids" in result or "asks" in result


@pytest.mark.integration
@pytest.mark.skipif(
    not DeribitConfig.validate_credentials(),
    reason="API credentials not configured"
)
class TestDeribitAuthIntegration:
    """Integration tests for authentication (requires API credentials)"""

    @pytest.mark.asyncio
    async def test_authentication(self):
        """Test OAuth2 authentication"""
        auth = DeribitAuth()

        result = await auth.authenticate()

        assert result is not None
        assert "access_token" in result
        assert auth.get_access_token() is not None
        assert auth.is_token_valid() is True

    @pytest.mark.asyncio
    async def test_token_refresh(self):
        """Test token refresh"""
        auth = DeribitAuth()

        # First authenticate
        await auth.authenticate()
        original_token = auth.get_access_token()

        # Refresh token
        await auth.refresh_access_token()
        new_token = auth.get_access_token()

        assert new_token is not None
        # Token might be the same or different depending on implementation
        assert auth.is_token_valid() is True


@pytest.mark.integration
@pytest.mark.skipif(
    not DeribitConfig.validate_credentials(),
    reason="API credentials not configured"
)
class TestAccountToolsIntegration:
    """Integration tests for account tools (requires API credentials)"""

    @pytest.mark.asyncio
    async def test_get_account_summary(self):
        """Test getting account summary"""
        from spoon_toolkits.data_platforms.deribit.account import GetAccountSummaryTool

        tool = GetAccountSummaryTool()
        result = await tool.execute(currency="BTC")

        assert result.get("error") is None
        output = result.get("output")
        assert output is not None
        assert "balance" in output or "equity" in output

    @pytest.mark.asyncio
    async def test_get_positions(self):
        """Test getting positions"""
        from spoon_toolkits.data_platforms.deribit.account import GetPositionsTool

        tool = GetPositionsTool()
        result = await tool.execute(currency="BTC")

        assert result.get("error") is None
        output = result.get("output")
        assert output is not None
        assert isinstance(output, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])

