"""Basic tests for Deribit API toolkit"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from spoon_toolkits.data_platforms.deribit.jsonrpc_client import DeribitJsonRpcClient, DeribitJsonRpcError
from spoon_toolkits.data_platforms.deribit.auth import DeribitAuth, DeribitAuthError
from spoon_toolkits.data_platforms.deribit.market_data import GetInstrumentsTool, GetOrderBookTool
from spoon_toolkits.data_platforms.deribit.account import GetAccountSummaryTool


class TestDeribitJsonRpcClient:
    """Test JSON-RPC client"""

    @pytest.mark.asyncio
    async def test_call_public_method(self):
        """Test calling a public method"""
        async with DeribitJsonRpcClient() as client:
            # Mock the HTTP response
            with patch('httpx.AsyncClient.post') as mock_post:
                mock_response = MagicMock()
                mock_response.json.return_value = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": [{"instrument_name": "BTC-PERPETUAL"}]
                }
                mock_response.raise_for_status = MagicMock()
                mock_post.return_value = mock_response

                result = await client.call("public/get_instruments", {"currency": "BTC"})
                assert result is not None
                assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_call_with_error(self):
        """Test handling API errors"""
        async with DeribitJsonRpcClient() as client:
            with patch('httpx.AsyncClient.post') as mock_post:
                mock_response = MagicMock()
                mock_response.json.return_value = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params"
                    }
                }
                mock_response.raise_for_status = MagicMock()
                mock_post.return_value = mock_response

                with pytest.raises(DeribitJsonRpcError):
                    await client.call("public/get_instruments", {"currency": "INVALID"})


class TestDeribitAuth:
    """Test authentication"""

    @pytest.mark.asyncio
    async def test_authenticate_success(self):
        """Test successful authentication"""
        auth = DeribitAuth(client_id="test_id", client_secret="test_secret")

        with patch.object(auth.jsonrpc_client, 'call') as mock_call:
            mock_call.return_value = {
                "access_token": "test_token",
                "refresh_token": "test_refresh",
                "expires_in": 3600,
                "scope": "account:read"
            }

            result = await auth.authenticate()
            assert result["access_token"] == "test_token"
            assert auth.get_access_token() == "test_token"
            assert auth.is_token_valid() is True

    @pytest.mark.asyncio
    async def test_token_refresh(self):
        """Test token refresh"""
        auth = DeribitAuth(client_id="test_id", client_secret="test_secret")
        auth.refresh_token = "test_refresh"

        with patch.object(auth.jsonrpc_client, 'call') as mock_call:
            mock_call.return_value = {
                "access_token": "new_token",
                "refresh_token": "new_refresh",
                "expires_in": 3600
            }

            result = await auth.refresh_access_token()
            assert result["access_token"] == "new_token"
            assert auth.get_access_token() == "new_token"


class TestMarketDataTools:
    """Test market data tools"""

    @pytest.mark.asyncio
    async def test_get_instruments_tool(self):
        """Test GetInstrumentsTool"""
        tool = GetInstrumentsTool()

        with patch.object(tool, '_call_public_method') as mock_call:
            mock_call.return_value = [{"instrument_name": "BTC-PERPETUAL"}]

            result = await tool.execute(currency="BTC")
            assert result.error is None
            assert result.output is not None

    @pytest.mark.asyncio
    async def test_get_order_book_tool(self):
        """Test GetOrderBookTool"""
        tool = GetOrderBookTool()

        with patch.object(tool, '_call_public_method') as mock_call:
            mock_call.return_value = {
                "bids": [[50000, 1.0]],
                "asks": [[50001, 1.0]]
            }

            result = await tool.execute(instrument_name="BTC-PERPETUAL")
            assert result.error is None
            assert result.output is not None


class TestAccountTools:
    """Test account tools"""

    @pytest.mark.asyncio
    async def test_get_account_summary_tool(self):
        """Test GetAccountSummaryTool"""
        tool = GetAccountSummaryTool()

        with patch.object(tool, '_ensure_authenticated') as mock_auth:
            with patch.object(tool, '_call_private_method') as mock_call:
                mock_call.return_value = {
                    "balance": 1.0,
                    "equity": 1.0,
                    "available_funds": 0.9
                }

                result = await tool.execute(currency="BTC")
                assert result.error is None
                assert result.output is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

