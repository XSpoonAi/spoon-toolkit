"""Inspect Deribit futures contract specs and approximate minimum trade sizes."""
import asyncio
import sys
from pathlib import Path
sys.path.insert(0, '../../..')

from spoon_toolkits.deribit.market_data import GetInstrumentsTool, GetTickerTool


async def get_contract_specs():
    print("=" * 60)
    print("Deribit futures contract specs overview")
    print("=" * 60)
    
    # Fetch BTC perpetual futures
    tool = GetInstrumentsTool()
    result = await tool.execute(currency="BTC", kind="future", expired=False)
    
    if result.get("error"):
        print(f'❌ Query failed: {result.get("error")}')
        return
    
    instruments = result.get("output", [])
    
    # Find BTC-PERPETUAL
    perpetual = None
    for inst in instruments:
        if inst.get("instrument_name") == "BTC-PERPETUAL":
            perpetual = inst
            break
    
    if perpetual:
        print("\n📊 BTC-PERPETUAL contract specs:")
        print(f'  instrument_name : {perpetual.get("instrument_name")}')
        print(f'  currency        : {perpetual.get("currency")}')
        print(f'  kind            : {perpetual.get("kind")}')
        print(f'  min_trade_amount: {perpetual.get("min_trade_amount", "unknown")} contracts')
        print(f'  contract_size   : {perpetual.get("contract_size", "unknown")} BTC')
        print(f'  tick_size       : {perpetual.get("tick_size", "unknown")}')
        print(f'  amount_step     : {perpetual.get("amount_step", "unknown")}')
        
        # Fetch current price
        ticker_tool = GetTickerTool()
        ticker_result = await ticker_tool.execute(instrument_name="BTC-PERPETUAL")
        if not ticker_result.get("error"):
            ticker = ticker_result.get("output", {})
            current_price = ticker.get("last_price") or ticker.get("mark_price")
            if current_price:
                print(f"\n💰 Current price: ${current_price:,.2f}")
                
                # Estimate minimum notional
                min_amount = perpetual.get("min_trade_amount", 1)
                contract_size = perpetual.get("contract_size", 1)
                min_usd_value = min_amount * contract_size * current_price
                
                print("\n💵 Estimated minimum notional:")
                print(f"  min contracts   : {min_amount}")
                print(f"  contract_size   : {contract_size} BTC")
                print(f"  minimum notional: ~${min_usd_value:,.2f} USD")
                print(
                    f"  suggested deposit: ${min_usd_value * 2:,.2f}–${min_usd_value * 5:,.2f} USD "
                    "(2–5× minimum notional)"
                )
                
                # Margin estimate
                print("\n💳 Margin estimate (assuming ~10% margin rate):")
                margin_required = min_usd_value * 0.1
                print(f"  margin required : ~${margin_required:,.2f} USD")
                print(
                    f"  suggested margin: ${margin_required * 2:,.2f}–${margin_required * 3:,.2f} USD "
                    "(2–3× margin)"
                )
    
    # Fetch ETH perpetual futures
    eth_result = await tool.execute(currency="ETH", kind="future", expired=False)
    if not eth_result.get("error"):
        eth_instruments = eth_result.get("output", [])
        eth_perpetual = None
        for inst in eth_instruments:
            if inst.get("instrument_name") == "ETH-PERPETUAL":
                eth_perpetual = inst
                break
        
        if eth_perpetual:
            print("\n" + "=" * 60)
            print("📊 ETH-PERPETUAL contract specs:")
            print(f'  instrument_name : {eth_perpetual.get("instrument_name")}')
            print(f'  min_trade_amount: {eth_perpetual.get("min_trade_amount", "unknown")} contracts')
            print(f'  contract_size   : {eth_perpetual.get("contract_size", "unknown")} ETH')
            
            # Fetch ETH futures price
            eth_ticker_tool = GetTickerTool()
            eth_ticker_result = await eth_ticker_tool.execute(instrument_name="ETH-PERPETUAL")
            if not eth_ticker_result.get("error"):
                eth_ticker = eth_ticker_result.get("output", {})
                eth_price = eth_ticker.get("last_price") or eth_ticker.get("mark_price")
                if eth_price:
                    print(f"  current_price   : ${eth_price:,.2f}")
                    
                    eth_min_amount = eth_perpetual.get("min_trade_amount", 1)
                    eth_contract_size = eth_perpetual.get("contract_size", 1)
                    eth_min_usd = eth_min_amount * eth_contract_size * eth_price
                    
                    print(f"  minimum notional: ~${eth_min_usd:,.2f} USD")
                    print(
                        f"  suggested deposit: ${eth_min_usd * 2:,.2f}–${eth_min_usd * 5:,.2f} USD "
                        "(2–5× minimum notional)"
                    )
                    
                    # ETH margin estimate
                    eth_margin = eth_min_usd * 0.1
                    print(f"  margin required (10%): ~${eth_margin:,.2f} USD")
                    print(
                        f"  suggested margin: ${eth_margin * 2:,.2f}–${eth_margin * 3:,.2f} USD "
                        "(2–3× margin)"
                    )
    
    print("\n" + "=" * 60)
    print("💡 Notes:")
    print("  1. Deribit uses margin trading; you do not need to fund the full notional.")
    print("  2. Actual margin rates depend on market conditions (often 5–20%).")
    print("  3. Start with the minimum notional and scale up as you gain confidence.")
    print("  4. Prefer limit + post_only orders for safe integration tests.")
    print("=" * 60)


if __name__ == '__main__':
    asyncio.run(get_contract_specs())

