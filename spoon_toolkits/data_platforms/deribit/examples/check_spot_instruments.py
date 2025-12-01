"""Inspect Deribit instruments (spot/futures/options) and highlight spot support."""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent.parent))

from spoon_toolkits.deribit.market_data import GetInstrumentsTool, GetTickerTool


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text:^70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}\n")


def print_success(text):
    print(f"{Colors.GREEN}✅ {text}{Colors.RESET}")


def print_info(text):
    print(f"{Colors.CYAN}ℹ️  {text}{Colors.RESET}")


async def check_spot_instruments():
    """Query Deribit instruments and summarize spot pairs and basic prices."""
    print_header("Inspect Deribit instruments (spot / futures / options)")
    
    tool = GetInstrumentsTool()
    
    # Query multiple currencies and instrument kinds
    currencies = ["BTC", "ETH", "USDC"]
    kinds = ["spot", "future", "option"]
    
    results = {}
    
    for currency in currencies:
        print(f"\n{Colors.BOLD}{Colors.CYAN}Querying {currency} instruments...{Colors.RESET}")
        
        for kind in kinds:
            try:
                result = await tool.execute(currency=currency, kind=kind, expired=False)
                
                if isinstance(result, dict) and result.get("error"):
                    print(f"  {Colors.RED}❌ {kind} query failed: {result.get('error')}{Colors.RESET}")
                    continue
                
                instruments = result.get("output") if isinstance(result, dict) else result
                
                if instruments:
                    key = f"{currency}_{kind}"
                    results[key] = instruments
                    
                    print(f"  {Colors.GREEN}✅ {kind}: {len(instruments)} instruments{Colors.RESET}")
                    
                    # Show first 5 instruments
                    for inst in instruments[:5]:
                        inst_name = inst.get("instrument_name", "N/A")
                        print(f"     - {inst_name}")
                    
                    if len(instruments) > 5:
                        print(f"     ... and {len(instruments) - 5} more")
                else:
                    print(f"  {Colors.YELLOW}⚠️  {kind}: no instruments found{Colors.RESET}")
                    
            except Exception as e:
                print(f"  {Colors.RED}❌ {kind} query raised exception: {e}{Colors.RESET}")
    
    # Spot summary
    print_header("Spot instrument summary")
    
    spot_pairs = {}
    for key, instruments in results.items():
        if "spot" in key:
            currency = key.split("_")[0]
            spot_pairs[currency] = instruments
    
    if spot_pairs:
        print_success("Deribit exposes spot instruments.")
        print()
        
        for currency, instruments in spot_pairs.items():
            print(f"{Colors.BOLD}{currency} spot instruments ({len(instruments)} instruments):{Colors.RESET}")
            for inst in instruments:
                inst_name = inst.get("instrument_name", "N/A")
                base_currency = inst.get("base_currency", "N/A")
                quote_currency = inst.get("quote_currency", "N/A")
                print(f"  - {inst_name} ({base_currency}/{quote_currency})")
        
        # Try to fetch some sample spot prices
        print_header("Example spot price lookups")
        
        # BTC spot
        btc_spot = spot_pairs.get("BTC", [])
        if btc_spot:
            # Prefer BTC-USD-like spot pairs
            btc_usd = None
            for inst in btc_spot:
                inst_name = inst.get("instrument_name", "")
                if "USD" in inst_name or "USDC" in inst_name:
                    btc_usd = inst_name
                    break
            
            if btc_usd:
                print_info(f"Querying price for {btc_usd}...")
                try:
                    ticker_tool = GetTickerTool()
                    ticker_result = await ticker_tool.execute(instrument_name=btc_usd)
                    
                    if not ticker_result.get("error"):
                        ticker = ticker_result.get("output")
                        price = ticker.get("last_price") or ticker.get("mark_price")
                        print_success(f"{btc_usd} price: ${price:,.2f}")
                    else:
                        print(f"{Colors.YELLOW}⚠️  Price query failed: {ticker_result.get('error')}{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.YELLOW}⚠️  Price query raised exception: {e}{Colors.RESET}")
        
        # ETH spot
        eth_spot = spot_pairs.get("ETH", [])
        if eth_spot:
            eth_usd = None
            for inst in eth_spot:
                inst_name = inst.get("instrument_name", "")
                if "USD" in inst_name or "USDC" in inst_name:
                    eth_usd = inst_name
                    break
            
            if eth_usd:
                print_info(f"Querying price for {eth_usd}...")
                try:
                    ticker_tool = GetTickerTool()
                    ticker_result = await ticker_tool.execute(instrument_name=eth_usd)
                    
                    if not ticker_result.get("error"):
                        ticker = ticker_result.get("output")
                        price = ticker.get("last_price") or ticker.get("mark_price")
                        print_success(f"{eth_usd} price: ${price:,.2f}")
                    else:
                        print(f"{Colors.YELLOW}⚠️  Price query failed: {ticker_result.get('error')}{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.YELLOW}⚠️  Price query raised exception: {e}{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}⚠️  No spot instruments found{Colors.RESET}")
        print_info("Deribit primarily focuses on derivatives (futures and options).")
    
    # Compare how many instruments exist by kind
    print_header("Instrument type comparison")
    
    for currency in currencies:
        future_count = len(results.get(f"{currency}_future", []))
        spot_count = len(results.get(f"{currency}_spot", []))
        option_count = len(results.get(f"{currency}_option", []))
        
        print(f"\n{Colors.BOLD}{currency}:{Colors.RESET}")
        print(f"  futures: {future_count}")
        print(f"  spot   : {spot_count}")
        print(f"  options: {option_count}")
    
    print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}\n")


if __name__ == "__main__":
    try:
        asyncio.run(check_spot_instruments())
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Query interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"\n\n{Colors.RED}Query failed with exception: {e}{Colors.RESET}")

