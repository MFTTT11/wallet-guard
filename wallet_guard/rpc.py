"""Minimal JSON-RPC client (standard library only)."""
from __future__ import annotations

import json
import urllib.request

EVM_RPC = {
    'ethereum': 'https://ethereum-rpc.publicnode.com',
    'base': 'https://mainnet.base.org',
    'arbitrum': 'https://arb1.arbitrum.io/rpc',
    'optimism': 'https://mainnet.optimism.io',
    'polygon': 'https://polygon-bor-rpc.publicnode.com',
}
SOLANA_RPC = 'https://api.mainnet-beta.solana.com'


class RpcError(Exception):
    pass


def call(url, method, params, timeout=20):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json', 'User-Agent': 'wallet-guard/0.1'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read(20_000_001))
    if 'error' in data:
        raise RpcError(str(data['error'])[:200])
    return data.get('result')
