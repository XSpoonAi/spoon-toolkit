"""Unit tests for market data tools"""

import pytest
from unittest.mock import AsyncMock, patch

from spoon_toolkits.data_platforms.deribit.market_data import (
    GetInstrumentsTool,
    GetOrderBookTool,
    GetTickerTool,
    GetLastTradesTool,
    GetIndexPriceTool,
    GetBookSummaryTool
)


class TestGetInstrumentsTool:
    """Test GetInstrumentsTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful execution"""
        tool = GetInstrumentsTool()

        mock_result = [
            {"instrument_name": "BTC-PERPETUAL", "currency": "BTC", "kind": "future"},
            {"instrument_name": "BTC-25JAN25", "currency": "BTC", "kind": "future"}
        ]

        with patch.object(tool, '_call_public_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(currency="BTC", kind="future")

            assert result.error is None
            assert result.output == mock_result
            mock_call.assert_called_once_with(
                "public/get_instruments",
                {"currency": "BTC", "kind": "future", "expired": False}
            )

    @pytest.mark.asyncio
    async def test_execute_missing_currency(self):
        """Test missing required parameter"""
        tool = GetInstrumentsTool()

        result = await tool.execute()

        assert result.error is not None
        assert "currency" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_execute_with_expired(self):
        """Test with expired parameter"""
        tool = GetInstrumentsTool()

        with patch.object(tool, '_call_public_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = []

            await tool.execute(currency="BTC", expired=True)

            mock_call.assert_called_once()
            call_args = mock_call.call_args[0][1]
            assert call_args["expired"] is True


class TestGetOrderBookTool:
    """Test GetOrderBookTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful execution"""
        tool = GetOrderBookTool()

        mock_result = {
            "bids": [[50000, 1.0], [49999, 2.0]],
            "asks": [[50001, 1.0], [50002, 2.0]]
        }

        with patch.object(tool, '_call_public_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(instrument_name="BTC-PERPETUAL", depth=5)

            assert result.error is None
            assert result.output == mock_result
            mock_call.assert_called_once_with(
                "public/get_order_book",
                {"instrument_name": "BTC-PERPETUAL", "depth": 5}
            )

    @pytest.mark.asyncio
    async def test_execute_missing_instrument_name(self):
        """Test missing required parameter"""
        tool = GetOrderBookTool()

        result = await tool.execute()

        assert result.error is not None
        assert "instrument_name" in (result.error or "").lower()


class TestGetTickerTool:
    """Test GetTickerTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful execution"""
        tool = GetTickerTool()

        mock_result = {
            "last_price": 50000.0,
            "mark_price": 50001.0,
            "index_price": 50000.5
        }

        with patch.object(tool, '_call_public_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(instrument_name="BTC-PERPETUAL")

            assert result.error is None
            assert result.output == mock_result


class TestGetLastTradesTool:
    """Test GetLastTradesTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful execution"""
        tool = GetLastTradesTool()

        mock_result = {
            "trades": [
                {"price": 50000, "amount": 1.0, "direction": "buy"},
                {"price": 50001, "amount": 0.5, "direction": "sell"}
            ]
        }

        with patch.object(tool, '_call_public_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(instrument_name="BTC-PERPETUAL", count=5)

            assert result.error is None
            assert result.output == mock_result

    @pytest.mark.asyncio
    async def test_execute_invalid_count(self):
        """Test invalid count parameter"""
        tool = GetLastTradesTool()

        result = await tool.execute(instrument_name="BTC-PERPETUAL", count=2000)

        assert result.error is not None
        assert "count" in (result.error or "").lower()


class TestGetIndexPriceTool:
    """Test GetIndexPriceTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful execution"""
        tool = GetIndexPriceTool()

        mock_result = {"index_price": 50000.5}

        with patch.object(tool, '_call_public_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(index_name="btc_usd")

            assert result.error is None
            assert result.output == mock_result


class TestGetBookSummaryTool:
    """Test GetBookSummaryTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful execution"""
        tool = GetBookSummaryTool()

        mock_result = [
            {"instrument_name": "BTC-PERPETUAL", "best_bid": 50000, "best_ask": 50001}
        ]

        with patch.object(tool, '_call_public_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(currency="BTC", kind="future")

            assert result.error is None
            assert result.output == mock_result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

