"""Unit tests for account management tools"""

import pytest
from unittest.mock import AsyncMock, patch

from spoon_toolkits.data_platforms.deribit.account import (
    GetAccountSummaryTool,
    GetPositionsTool,
    GetOrderHistoryTool,
    GetTradeHistoryTool
)


class TestGetAccountSummaryTool:
    """Test GetAccountSummaryTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful account summary retrieval"""
        tool = GetAccountSummaryTool()

        mock_result = {
            "balance": 1.0,
            "equity": 1.0,
            "available_funds": 0.9,
            "margin_balance": 1.0
        }

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(currency="BTC")

            assert result.error is None
            assert result.output == mock_result
            mock_call.assert_called_once_with(
                "private/get_account_summary",
                {"currency": "BTC", "extended": False}
            )

    @pytest.mark.asyncio
    async def test_execute_with_extended(self):
        """Test with extended parameter"""
        tool = GetAccountSummaryTool()

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {}

            await tool.execute(currency="BTC", extended=True)

            call_params = mock_call.call_args[0][1]
            assert call_params["extended"] is True

    @pytest.mark.asyncio
    async def test_execute_missing_currency(self):
        """Test missing currency parameter"""
        tool = GetAccountSummaryTool()

        result = await tool.execute()

        assert result.error is not None
        assert "currency" in (result.error or "").lower()


class TestGetPositionsTool:
    """Test GetPositionsTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful positions retrieval"""
        tool = GetPositionsTool()

        mock_result = [
            {
                "instrument_name": "BTC-PERPETUAL",
                "size": 1.0,
                "entry_price": 50000.0,
                "mark_price": 51000.0
            }
        ]

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(currency="BTC")

            assert result.error is None
            assert result.output == mock_result

    @pytest.mark.asyncio
    async def test_execute_with_kind_filter(self):
        """Test with kind filter"""
        tool = GetPositionsTool()

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = []

            await tool.execute(currency="BTC", kind="future")

            call_params = mock_call.call_args[0][1]
            assert call_params["kind"] == "future"


class TestGetOrderHistoryTool:
    """Test GetOrderHistoryTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful order history retrieval"""
        tool = GetOrderHistoryTool()

        mock_result = {
            "orders": [
                {"order_id": "12345", "order_state": "filled"},
                {"order_id": "12346", "order_state": "cancelled"}
            ]
        }

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(instrument_name="BTC-PERPETUAL", count=20)

            assert result.error is None
            assert result.output == mock_result

    @pytest.mark.asyncio
    async def test_execute_invalid_count(self):
        """Test invalid count parameter"""
        tool = GetOrderHistoryTool()

        result = await tool.execute(instrument_name="BTC-PERPETUAL", count=2000)

        assert result.error is not None
        assert "count" in (result.error or "").lower()


class TestGetTradeHistoryTool:
    """Test GetTradeHistoryTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful trade history retrieval"""
        tool = GetTradeHistoryTool()

        mock_result = {
            "trades": [
                {"trade_id": "t1", "price": 50000, "amount": 1.0},
                {"trade_id": "t2", "price": 50001, "amount": 0.5}
            ]
        }

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(instrument_name="BTC-PERPETUAL", count=20)

            assert result.error is None
            assert result.output == mock_result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

