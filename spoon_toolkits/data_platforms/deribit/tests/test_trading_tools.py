"""Unit tests for trading tools"""

import pytest
from unittest.mock import AsyncMock, patch

from spoon_toolkits.data_platforms.deribit.trading import (
    PlaceBuyOrderTool,
    PlaceSellOrderTool,
    CancelOrderTool,
    CancelAllOrdersTool,
    GetOpenOrdersTool,
    EditOrderTool
)


class TestPlaceBuyOrderTool:
    """Test PlaceBuyOrderTool"""

    @pytest.mark.asyncio
    async def test_execute_success_limit_order(self):
        """Test successful limit order placement"""
        tool = PlaceBuyOrderTool()

        mock_result = {
            "order_id": "12345",
            "order_state": "open",
            "amount": 1.0,
            "price": 50000.0
        }

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(
                instrument_name="BTC-PERPETUAL",
                amount=1.0,
                price=50000.0,
                order_type="limit"
            )

            assert result.error is None
            assert result.output == mock_result
            mock_call.assert_called_once()
            call_params = mock_call.call_args[0][1]
            assert call_params["instrument_name"] == "BTC-PERPETUAL"
            assert call_params["amount"] == 1.0
            assert call_params["price"] == 50000.0

    @pytest.mark.asyncio
    async def test_execute_market_order(self):
        """Test market order (no price required)"""
        tool = PlaceBuyOrderTool()

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {"order_id": "12345"}

            result = await tool.execute(
                instrument_name="BTC-PERPETUAL",
                amount=1.0,
                order_type="market"
            )

            assert result.error is None

    @pytest.mark.asyncio
    async def test_execute_missing_required_params(self):
        """Test missing required parameters"""
        tool = PlaceBuyOrderTool()

        result = await tool.execute()
        assert result.error is not None

        result = await tool.execute(instrument_name="BTC-PERPETUAL")
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_execute_limit_order_missing_price(self):
        """Test limit order without price"""
        tool = PlaceBuyOrderTool()

        result = await tool.execute(
            instrument_name="BTC-PERPETUAL",
            amount=1.0,
            order_type="limit"
        )

        assert result.error is not None
        assert "price" in (result.error or "").lower()


class TestPlaceSellOrderTool:
    """Test PlaceSellOrderTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful sell order placement"""
        tool = PlaceSellOrderTool()

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {"order_id": "12345"}

            result = await tool.execute(
                instrument_name="BTC-PERPETUAL",
                amount=1.0,
                price=50000.0
            )

            assert result.error is None


class TestCancelOrderTool:
    """Test CancelOrderTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful order cancellation"""
        tool = CancelOrderTool()

        mock_result = {
            "order_id": "12345",
            "order_state": "cancelled"
        }

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(order_id="12345")

            assert result.error is None
            assert result.output == mock_result
            mock_call.assert_called_once_with(
                "private/cancel",
                {"order_id": "12345"}
            )

    @pytest.mark.asyncio
    async def test_execute_missing_order_id(self):
        """Test missing order_id"""
        tool = CancelOrderTool()

        result = await tool.execute()

        assert result.error is not None
        assert "order_id" in (result.error or "").lower()


class TestCancelAllOrdersTool:
    """Test CancelAllOrdersTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful cancellation of all orders"""
        tool = CancelAllOrdersTool()

        mock_result = {"cancelled": 5}

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(currency="BTC", kind="future")

            assert result.error is None
            assert result.output == mock_result

    @pytest.mark.asyncio
    async def test_execute_missing_currency(self):
        """Test missing currency"""
        tool = CancelAllOrdersTool()

        result = await tool.execute()

        assert result.error is not None


class TestGetOpenOrdersTool:
    """Test GetOpenOrdersTool"""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful retrieval of open orders"""
        tool = GetOpenOrdersTool()

        mock_result = [
            {"order_id": "12345", "order_state": "open"},
            {"order_id": "12346", "order_state": "open"}
        ]

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(instrument_name="BTC-PERPETUAL")

            assert result.error is None
            assert result.output == mock_result


class TestEditOrderTool:
    """Test EditOrderTool"""

    @pytest.mark.asyncio
    async def test_execute_success_edit_price(self):
        """Test successful order edit (price)"""
        tool = EditOrderTool()

        mock_result = {
            "order_id": "12345",
            "price": 51000.0
        }

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_result

            result = await tool.execute(order_id="12345", price=51000.0)

            assert result.error is None
            assert result.output == mock_result

    @pytest.mark.asyncio
    async def test_execute_success_edit_amount(self):
        """Test successful order edit (amount)"""
        tool = EditOrderTool()

        with patch.object(tool, '_call_private_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {"order_id": "12345"}

            result = await tool.execute(order_id="12345", amount=2.0)

            assert result.error is None

    @pytest.mark.asyncio
    async def test_execute_missing_order_id(self):
        """Test missing order_id"""
        tool = EditOrderTool()

        result = await tool.execute()

        assert result.error is not None

    @pytest.mark.asyncio
    async def test_execute_no_changes(self):
        """Test edit without amount or price"""
        tool = EditOrderTool()

        result = await tool.execute(order_id="12345")

        assert result.error is not None
        assert "amount" in (result.error or "").lower() or "price" in (result.error or "").lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

