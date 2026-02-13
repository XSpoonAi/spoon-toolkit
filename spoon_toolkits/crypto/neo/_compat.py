import logging

logger = logging.getLogger(__name__)

_PATCHED = False


def apply():
    """Apply all neo-mamba compatibility fixes (idempotent)."""
    global _PATCHED
    if _PATCHED:
        return
    _PATCHED = True

    from neo3.api import noderpc

    # -- Fix 1: raise default timeout from 3 s to 30 s --------------------
    _original_init = noderpc.RPCClient.__init__

    def _init_with_longer_timeout(self, *args, **kwargs):
        kwargs.setdefault("timeout", 30.0)
        _original_init(self, *args, **kwargs)

    noderpc.RPCClient.__init__ = _init_with_longer_timeout

    # -- Fix 2: robust error handling in _do_post --------------------------
    async def _safe_do_post(self, method, params=None, id=0, jsonrpc_version="2.0"):
        json_payload = {
            "jsonrpc": jsonrpc_version,
            "id": id,
            "method": method,
            "params": params if params else [],
        }
        response = await noderpc.RPCClient._post(self, json_payload)
        error = response.get("error")
        if error:
            if isinstance(error, dict):
                raise noderpc.JsonRpcError(**error)
            raise noderpc.JsonRpcError(code=-1, message=str(error))
        return response["result"]

    noderpc.NeoRpcClient._do_post = _safe_do_post

    logger.debug("neo-mamba compatibility patches applied")
