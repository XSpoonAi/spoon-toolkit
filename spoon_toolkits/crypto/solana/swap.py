import inspect
import logging
from typing import Optional, Dict, Any, Union, List
import httpx
from pydantic import Field
from spoon_ai.tools.base import BaseTool, ToolResult
from .service import (
    get_rpc_url,
    get_wallet_cache_scheduler,
    is_native_sol,
    parse_token_amount,
    format_token_amount,
    parse_transaction_error,
    validate_solana_address,
)
from .signers import SignerManager, SolanaSigner
from .constants import (
    JUPITER_QUOTE_ENDPOINT,
    JUPITER_SWAP_ENDPOINT,
    NATIVE_SOL_ADDRESS,
    MAX_SLIPPAGE_BPS,
    JUPITER_PRIORITY_LEVELS,
    SOLANA_SERVICE_NAME,
    SOLANA_WALLET_DATA_CACHE_KEY,
    TOKEN_ADDRESSES,
)
from solana.rpc.async_api import AsyncClient
logger = logging.getLogger(__name__)

class SolanaSwapTool(BaseTool):
    """Swap tokens on Solana using Jupiter aggregator.

    Supports both local private key and Turnkey secure signing.
    """

    name: str = "solana_swap"
    description: str = "Swap tokens on Solana using Jupiter aggregator. Supports local and Turnkey secure signing."
    parameters: dict = {
        "type": "object",
        "properties": {
            "rpc_url": {
                "type": "string",
                "description": "Solana RPC endpoint URL. Defaults to SOLANA_RPC_URL env var."
            },
            "signer_type": {
                "type": "string",
                "enum": ["local", "turnkey", "auto"],
                "description": "Signing method: 'local' (private key), 'turnkey' (secure API), or 'auto' (detect from env)",
                "default": "auto",
            },
            "private_key": {
                "type": "string",
                "description": "Wallet private key. Required for local signing. Defaults to SOLANA_PRIVATE_KEY env var."
            },
            "turnkey_sign_with": {
                "type": "string",
                "description": "Turnkey signing identity (Solana address). Required for Turnkey signing. Defaults to TURNKEY_SOLANA_ADDRESS env var.",
            },
            "input_token": {
                "type": "string",
                "description": "Input token mint address (or 'SOL' for native SOL)"
            },
            "output_token": {
                "type": "string",
                "description": "Output token mint address (or 'SOL' for native SOL)"
            },
            "amount": {
                "type": "number",
                "description": "Amount to swap (in input token units)"
            },
            "slippage_bps": {
                "type": "integer",
                "description": "Slippage tolerance in basis points (100 = 1%)",
            },
            "priority_level": {
                "type": "string",
                "enum": ["low", "medium", "high", "veryHigh"],
                "description": "Priority level for transaction processing",
                "default": "veryHigh"
            }
        },
        "required": ["input_token", "output_token", "amount"],
    }

    rpc_url: Optional[str] = Field(default=None)
    signer_type: str = Field(default="auto")
    private_key: Optional[str] = Field(default=None)
    turnkey_sign_with: Optional[str] = Field(default=None)
    input_token: Optional[str] = Field(default=None)
    output_token: Optional[str] = Field(default=None)
    amount: Optional[Union[str, float]] = Field(default=None)
    slippage_bps: Optional[int] = Field(default=None)
    priority_level: str = Field(default="veryHigh")

    async def execute(
        self,
        rpc_url: Optional[str] = None,
        signer_type: Optional[str] = None,
        private_key: Optional[str] = None,
        turnkey_sign_with: Optional[str] = None,
        input_token: Optional[str] = None,
        output_token: Optional[str] = None,
        amount: Optional[Union[str, float]] = None,
        slippage_bps: Optional[int] = None,
        priority_level: str = "veryHigh",
        runtime: Any = None,
    ) -> ToolResult:
        """Execute token swap operation."""
        try:
            # Resolve parameters
            rpc_url = rpc_url or self.rpc_url or get_rpc_url()
            signer_type = signer_type or self.signer_type
            private_key = private_key or self.private_key
            turnkey_sign_with = turnkey_sign_with or self.turnkey_sign_with
            input_token = input_token or self.input_token
            output_token = output_token or self.output_token
            amount = amount or self.amount
            slippage_bps = slippage_bps if slippage_bps is not None else self.slippage_bps
            priority_level = priority_level or self.priority_level

            # Log received parameters for debugging
            logger.debug(f"SolanaSwapTool.execute called with: input_token={input_token}, output_token={output_token}, amount={amount}")

            # Validate required parameters early
            if not input_token:
                return ToolResult(error="input_token parameter is required. Please provide 'SOL' for native SOL or a token mint address.")
            if not output_token:
                return ToolResult(error="output_token parameter is required. Please provide 'SOL' for native SOL or a token mint address.")
            if amount is None:
                return ToolResult(error="amount parameter is required.")

            # Create signer using SignerManager (supports local and Turnkey)
            try:
                signer = SignerManager.create_signer(
                    signer_type=signer_type,
                    private_key=private_key,
                    turnkey_sign_with=turnkey_sign_with,
                )
            except Exception as e:
                return ToolResult(error=f"Failed to create signer: {str(e)}")

            wallet_pubkey = signer.get_address()

            portfolio = await self._load_wallet_portfolio(runtime, rpc_url, wallet_pubkey)

            resolved_input = await self._resolve_token_identifier(
                input_token,
                runtime=runtime,
                rpc_url=rpc_url,
                wallet_address=wallet_pubkey,
                portfolio=portfolio,
            )
            # For native SOL, NATIVE_SOL_ADDRESS is None, which needs special handling
            if resolved_input is None and not is_native_sol(input_token):
                return ToolResult(error="Could not find the input token in your wallet")
            # If input is native SOL but resolved_input is None, use Wrapped SOL mint address for Jupiter
            if resolved_input is None and is_native_sol(input_token):
                # Jupiter API uses Wrapped SOL mint address for native SOL swaps
                resolved_input = "So11111111111111111111111111111111111111112"

            resolved_output = await self._resolve_token_identifier(
                output_token,
                runtime=runtime,
                rpc_url=rpc_url,
                wallet_address=wallet_pubkey,
                portfolio=portfolio,
            )
            # For native SOL output, NATIVE_SOL_ADDRESS is None, which needs special handling
            if resolved_output is None and not is_native_sol(output_token):
                return ToolResult(error="Could not find the output token in your wallet")
            # If output is native SOL but resolved_output is None, use Wrapped SOL mint address for Jupiter
            if resolved_output is None and is_native_sol(output_token):
                # Jupiter API uses Wrapped SOL mint address for native SOL swaps
                resolved_output = "So11111111111111111111111111111111111111112"

            # Build quote context (validates inputs and fetches quote)
            quote_context = await self._build_quote_context(
                rpc_url=rpc_url,
                input_token=resolved_input,
                output_token=resolved_output,
                amount=amount,
                slippage_bps=slippage_bps,
                user_public_key=wallet_pubkey
            )

            if not quote_context["success"]:
                return ToolResult(error=quote_context["error"])

            quote = quote_context["quote"]

            # Get swap transaction
            swap_result = await self._get_jupiter_swap_transaction(
                quote, wallet_pubkey, priority_level
            )

            if not swap_result["success"]:
                return ToolResult(error=swap_result["error"])

            # Execute swap
            execute_result = await self._execute_swap_transaction(
                rpc_url, signer, swap_result["swap_transaction"]
            )

            if not execute_result["success"]:
                return ToolResult(error=execute_result["error"])

            # Format output
            output_amount = quote_context["output_amount"]

            return ToolResult(output={
                "success": True,
                "signature": execute_result["signature"],
                "input_token": input_token,
                "input_mint": resolved_input,
                "output_token": output_token,
                "output_mint": resolved_output,
                "input_amount": amount,
                "output_amount": output_amount,
                "price_impact": float(quote.get("priceImpactPct", 0)),
                "slippage_bps": quote_context["slippage_bps"],
                "route_plan": quote.get("routePlan", []),
                "fees": execute_result.get("fees", {}),
                "signer_type": signer.signer_type,
            })

        except Exception as e:
            logger.error(f"SolanaSwapTool error: {e}")
            return ToolResult(error=f"Swap failed: {str(e)}")

    async def _build_quote_context(
        self,
        rpc_url: str,
        input_token: Optional[str],
        output_token: Optional[str],
        amount: Optional[Union[str, float]],
        slippage_bps: Optional[int],
        user_public_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate inputs, resolve decimals, and fetch a Jupiter quote."""
        if not input_token or not output_token:
            error_msg = f"Both input_token and output_token are required. Received: input_token={input_token}, output_token={output_token}"
            logger.error(f"SolanaSwapTool validation error: {error_msg}")
            return {"success": False, "error": error_msg}

        if amount is None:
            return {"success": False, "error": "Amount is required"}

        try:
            from decimal import Decimal, InvalidOperation
            amount_decimal = Decimal(str(amount))
        except (TypeError, InvalidOperation):
            return {"success": False, "error": "Invalid amount format"}

        if amount_decimal <= 0:
            return {"success": False, "error": "Amount must be positive"}

        if slippage_bps is not None and (slippage_bps < 1 or slippage_bps > MAX_SLIPPAGE_BPS):
            return {"success": False, "error": f"Slippage must be between 1 and {MAX_SLIPPAGE_BPS} bps"}

        input_mint = self._normalize_token_address(input_token)
        output_mint = self._normalize_token_address(output_token)

        if input_mint == output_mint:
            return {"success": False, "error": "Input and output tokens cannot be the same"}

        input_decimals = await self._get_token_decimals(rpc_url, input_mint)
        if input_decimals is None:
            return {"success": False, "error": f"Failed to get decimals for input token: {input_token}"}

        input_amount_raw = parse_token_amount(str(amount_decimal), input_decimals)

        quote_result = await self._get_jupiter_quote(
            input_mint, output_mint, input_amount_raw, slippage_bps, user_public_key
        )

        if not quote_result["success"]:
            return {"success": False, "error": quote_result["error"]}

        quote = quote_result["quote"]
        output_decimals = await self._get_token_decimals(rpc_url, output_mint)
        if output_decimals is None:
            return {
                "success": False,
                "error": f"Failed to get decimals for output token: {output_token}"
            }

        output_amount = format_token_amount(int(quote["outAmount"]), output_decimals)

        return {
            "success": True,
            "input_mint": input_mint,
            "output_mint": output_mint,
            "input_amount_raw": input_amount_raw,
            "quote": quote,
            "output_decimals": output_decimals,
            "output_amount": output_amount,
            "slippage_bps": slippage_bps,
        }

    def _normalize_token_address(self, token: str) -> str:
        """Normalize token address for Jupiter API."""
        if token.upper() == "SOL" or is_native_sol(token) or token == NATIVE_SOL_ADDRESS:
            # Jupiter API uses Wrapped SOL mint address for native SOL swaps
            return "So11111111111111111111111111111111111111112"
        return token

    async def _get_token_decimals(self, rpc_url: str, mint_address: str) -> Optional[int]:
        """Get token decimals from mint account."""
        try:
            from solana.rpc.async_api import AsyncClient
            from solders.pubkey import Pubkey

            # Native SOL and Wrapped SOL both have 9 decimals
            # Wrapped SOL mint: So11111111111111111111111111111111111111112
            if mint_address == NATIVE_SOL_ADDRESS or mint_address == "So11111111111111111111111111111111111111112":
                return 9

            async with AsyncClient(rpc_url) as client:
                mint_pubkey = Pubkey.from_string(mint_address)
                account_info = await client.get_account_info(mint_pubkey, encoding="jsonParsed")

                if account_info.value and account_info.value.data:
                    # Handle different response formats
                    data = account_info.value.data
                    if isinstance(data, dict):
                        parsed = data.get("parsed", {})
                        if isinstance(parsed, dict):
                            info = parsed.get("info", {})
                            if isinstance(info, dict) and "decimals" in info:
                                return info["decimals"]
                    elif hasattr(data, 'parsed'):
                        parsed = data.parsed
                        if isinstance(parsed, dict) and "info" in parsed:
                            info = parsed["info"]
                            if isinstance(info, dict) and "decimals" in info:
                                return info["decimals"]

        except Exception as e:
            logger.error(f"Error getting token decimals for {mint_address}: {e}")
            # For Wrapped SOL, return 9 as fallback
            if mint_address == "So11111111111111111111111111111111111111112":
                return 9

        return None

    async def _get_jupiter_quote(
        self,
        input_mint: str,
        output_mint: str,
        amount: int,
        slippage_bps: Optional[int],
        user_public_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get quote from Jupiter API."""
        try:
            params = {
                "inputMint": input_mint,
                "outputMint": output_mint,
                "amount": str(amount),
                "dynamicSlippage": "true",
                "maxAccounts": "64"
            }

            if slippage_bps is not None:
                params["slippageBps"] = str(slippage_bps)
            if user_public_key:
                params["userPublicKey"] = user_public_key

            # Log the request for debugging
            logger.debug(f"Requesting Jupiter quote from {JUPITER_QUOTE_ENDPOINT} with params: {params}")
            
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
            ) as client:
                response = await client.get(JUPITER_QUOTE_ENDPOINT, params=params)
                response.raise_for_status()  # Raise exception for bad status codes
                quote_data = response.json()
                
            if "error" in quote_data:
                return {
                    "success": False,
                    "error": f"Jupiter quote error: {quote_data['error']}"
                }
            return {
                "success": True,
                "quote": quote_data
            }
        except httpx.TimeoutException as e:
            logger.error(f"Timeout getting Jupiter quote: {e}")
            return {
                "success": False,
                "error": f"Timeout connecting to Jupiter API. Please check your network connection."
            }
        except httpx.ConnectError as e:
            error_msg = str(e)
            logger.error(f"Connection error getting Jupiter quote: {e}")
            
            # Check if it's a DNS resolution error
            if "nodename nor servname provided" in error_msg or "Could not resolve host" in error_msg:
                return {
                    "success": False,
                    "error": (
                        f"DNS resolution failed for Jupiter API ({JUPITER_QUOTE_ENDPOINT}). "
                        "This may be due to:\n"
                        "1. Network connectivity issues\n"
                        "2. DNS server problems\n"
                        "3. Firewall/proxy restrictions (if you're in a restricted network environment, you may need a VPN or proxy)\n"
                        "4. The Jupiter API endpoint may be temporarily unavailable\n\n"
                        f"Error details: {error_msg}\n\n"
                        "To resolve:\n"
                        "- Check your internet connection\n"
                        "- Try using a VPN if you're in a restricted network\n"
                        "- Verify DNS settings: try 'nslookup quote-api.jup.ag' or 'ping quote-api.jup.ag'\n"
                        "- Check if you need to configure proxy settings for httpx"
                    )
                }
            else:
                return {
                    "success": False,
                    "error": f"Failed to connect to Jupiter API. Please check your network connection. Error: {error_msg}"
                }
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error getting Jupiter quote: {e.response.status_code} - {e.response.text}")
            return {
                "success": False,
                "error": f"Jupiter API returned error {e.response.status_code}: {e.response.text[:200]}"
            }
        except Exception as e:
            logger.error(f"Error getting Jupiter quote: {e}", exc_info=True)
            return {
                "success": False,
                "error": f"Failed to get quote: {str(e)}"
            }
    async def _get_jupiter_swap_transaction(
        self,
        quote: Dict[str, Any],
        user_public_key: str,
        priority_level: str
    ) -> Dict[str, Any]:
        """Get swap transaction from Jupiter API."""
        try:
            priority_fee = JUPITER_PRIORITY_LEVELS.get(priority_level, JUPITER_PRIORITY_LEVELS["veryHigh"])

            payload = {
                "quoteResponse": quote,
                "userPublicKey": user_public_key,
                "dynamicComputeUnitLimit": True,
                "dynamicSlippage": True,
                "priorityLevelWithMaxLamports": {
                    "maxLamports": priority_fee,
                    "priorityLevel": priority_level
                }
            }

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    JUPITER_SWAP_ENDPOINT,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=30
                )
            swap_data = response.json()
            return {
                "success": True,
                "swap_transaction": swap_data["swapTransaction"],
                "last_valid_block_height": swap_data.get("lastValidBlockHeight")
            }

        except Exception as e:
            logger.error(f"Error getting Jupiter swap transaction: {e}")
            return {
                "success": False,
                "error": f"Failed to get swap transaction: {str(e)}"
            }

    async def _execute_swap_transaction(
        self,
        rpc_url: str,
        signer: SolanaSigner,
        swap_transaction_base64: str
    ) -> Dict[str, Any]:
        """Execute the swap transaction."""
        try:
            from solders.transaction import VersionedTransaction
            from solders.signature import Signature
            import base64

            transaction_bytes = base64.b64decode(swap_transaction_base64)
            transaction = VersionedTransaction.from_bytes(transaction_bytes)

            # Sign the transaction using the signer
            # For Turnkey, we need to sign the message and reconstruct the transaction
            if signer.signer_type == "turnkey":
                # Get the message bytes for signing
                message_bytes = bytes(transaction.message)
                # Sign using Turnkey
                signature_bytes = signer.sign_transaction(message_bytes)
                signature = Signature.from_bytes(signature_bytes)
                # Reconstruct transaction with new signature
                # The transaction already has a placeholder signature, replace it
                signatures = list(transaction.signatures)
                signatures[0] = signature
                transaction = VersionedTransaction.populate(transaction.message, signatures)
            else:
                # Local signer - use the keypair directly
                transaction.sign([signer.keypair])

            return await self._submit_signed_transaction(rpc_url, transaction)

        except Exception as e:
            logger.error(f"Error executing swap transaction: {e}")
            error_msg = parse_transaction_error(str(e))
            return {
                "success": False,
                "error": error_msg
            }

    async def _submit_signed_transaction(self, rpc_url: str, transaction) -> Dict[str, Any]:
        """Send, confirm, and fetch fee information for a signed transaction."""

        async with AsyncClient(rpc_url) as client:
            # Send transaction
            response = await client.send_transaction(transaction)
            signature = str(response.value)

            # Wait for confirmation
            confirmation = await client.confirm_transaction(
                signature,
                commitment="confirmed"
            )
            fees = await self._extract_transaction_fees(client, signature)
            return {
                "success": True,
                "signature": signature,
                "fees": fees
            }

    async def _extract_transaction_fees(self, client, signature: str) -> Dict[str, Any]:
        try:
            tx_details = await client.get_transaction(
                signature,
                encoding="jsonParsed",
                commitment="confirmed",
            )

            if tx_details.value and tx_details.value.transaction.meta:
                fee_lamports = tx_details.value.transaction.meta.fee
                return {
                    "transaction_fee": fee_lamports,
                    "fee_sol": fee_lamports / 1_000_000_000
                }
        except Exception as e:
            logger.warning(f"Failed to get transaction fees: {e}")

        return {}

    @staticmethod
    def _normalize_symbol_value(value: Optional[str]) -> str:
        if not isinstance(value, str):
            return ""
        return value.strip().lstrip("$").upper()

    @staticmethod
    def _extract_mint_from_item(item: Dict[str, Any]) -> Optional[str]:
        for key in ("mint", "address", "token_address", "tokenAddress"):
            mint = item.get(key)
            if isinstance(mint, str) and mint:
                return mint
        return None

    @staticmethod
    def _extract_symbol_candidates(item: Dict[str, Any]) -> List[str]:
        candidates: List[str] = []
        for key, value in item.items():
            if not isinstance(value, str):
                continue
            lowered = key.lower()
            if lowered in {"symbol", "tokensymbol", "token_symbol", "ticker"}:
                candidates.append(value)
        name = item.get("name")
        if isinstance(name, str):
            candidates.append(name)
        return candidates

    def _build_symbol_index(self, portfolio: Optional[Dict[str, Any]]) -> Dict[str, str]:
        symbol_index: Dict[str, str] = {}
        if not isinstance(portfolio, dict):
            return symbol_index

        for key in ("items", "token_balances", "tokens"):
            entries = portfolio.get(key)
            if not isinstance(entries, list):
                continue

            for entry in entries:
                if not isinstance(entry, dict):
                    continue

                mint = self._extract_mint_from_item(entry)
                if not mint or not validate_solana_address(mint):
                    continue

                for symbol in self._extract_symbol_candidates(entry):
                    normalized = self._normalize_symbol_value(symbol)
                    if normalized and normalized not in symbol_index:
                        symbol_index[normalized] = mint

        return symbol_index

    @staticmethod
    async def _get_runtime_service(runtime: Any, service_name: str) -> Any:
        if runtime is None:
            return None

        for attr in ("get_service", "getService", "get"):
            getter = getattr(runtime, attr, None)
            if callable(getter):
                try:
                    result = getter(service_name)
                except TypeError:
                    continue
                if inspect.isawaitable(result):
                    result = await result
                if result:
                    return result

        services_attr = getattr(runtime, "services", None)
        if isinstance(services_attr, dict):
            candidate = services_attr.get(service_name)
            if inspect.isawaitable(candidate):
                candidate = await candidate
            if candidate:
                return candidate
        return None

    @staticmethod
    async def _runtime_get_cache(runtime: Any, key: str) -> Any:
        if runtime is None:
            return None

        for attr in ("get_cache", "getCache"):
            getter = getattr(runtime, attr, None)
            if callable(getter):
                try:
                    result = getter(key)
                except TypeError:
                    continue
                if inspect.isawaitable(result):
                    return await result
                return result

        cache_attr = getattr(runtime, "cache", None)
        if isinstance(cache_attr, dict):
            return cache_attr.get(key)
        return None

    async def _load_wallet_portfolio(
        self,
        runtime: Any,
        rpc_url: str,
        wallet_address: str,
    ) -> Optional[Dict[str, Any]]:
        if runtime is not None:
            service = await self._get_runtime_service(runtime, SOLANA_SERVICE_NAME)
            if service and hasattr(service, "getCachedData"):
                try:
                    cached = service.getCachedData()
                    if inspect.isawaitable(cached):
                        cached = await cached
                    if cached:
                        return cached
                except Exception as exc:
                    logger.debug("Failed to fetch wallet data from Solana service: %s", exc)

            runtime_cache = await self._runtime_get_cache(runtime, SOLANA_WALLET_DATA_CACHE_KEY)
            if runtime_cache:
                return runtime_cache

        scheduler = get_wallet_cache_scheduler()

        try:
            await scheduler.ensure_running(rpc_url, wallet_address, include_tokens=True)
        except Exception as exc:
            logger.debug("Failed to ensure wallet cache scheduler: %s", exc)

        cached_entry = None
        try:
            cached_entry = await scheduler.get_cached(rpc_url, wallet_address)
        except Exception as exc:
            logger.debug("Failed to retrieve cached wallet data: %s", exc)

        if isinstance(cached_entry, dict):
            data = cached_entry.get("data")
            if data:
                return data

        try:
            return await scheduler.force_refresh(rpc_url, wallet_address, include_tokens=True)
        except Exception as exc:
            logger.debug("Failed to refresh wallet data: %s", exc)
            return None

    async def _resolve_token_identifier(
        self,
        token: Optional[str],
        *,
        runtime: Any,
        rpc_url: str,
        wallet_address: str,
        portfolio: Optional[Dict[str, Any]],
    ) -> Optional[str]:
        if token is None:
            return None

        token_str = str(token).strip()
        if not token_str:
            return None

        normalized_symbol = self._normalize_symbol_value(token_str)

        if normalized_symbol == "SOL" or is_native_sol(token_str):
            return NATIVE_SOL_ADDRESS

        if validate_solana_address(token_str):
            return token_str

        if normalized_symbol in TOKEN_ADDRESSES:
            return TOKEN_ADDRESSES[normalized_symbol]

        if portfolio is None:
            portfolio = await self._load_wallet_portfolio(runtime, rpc_url, wallet_address)

        symbol_index = self._build_symbol_index(portfolio)
        if normalized_symbol in symbol_index:
            return symbol_index[normalized_symbol]

        return None
