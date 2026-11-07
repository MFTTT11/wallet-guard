"""EVM checks: open ERC-20 approvals and token impersonation."""
from __future__ import annotations

import re

from . import rpc

APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925'  # Approval(address,address,uint256)
UNLIMITED = 2 ** 255
ADDRESS = re.compile(r'0x[0-9a-fA-F]{40}\Z')

# Canonical addresses of widely impersonated tokens (lower case).
CANONICAL = {
    'ethereum': {'USDC': '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', 'USDT': '0xdac17f958d2ee523a2206206994597c13d831ec7',
                 'DAI': '0x6b175474e89094c44da98b954eedeac495271d0f', 'WETH': '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'},
    'base': {'USDC': '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', 'WETH': '0x4200000000000000000000000000000000000006',
             'DAI': '0x50c5725949a6f0c72e6c4a641f24049a917db0cb'},
    'arbitrum': {'USDC': '0xaf88d065e77c8cc2239327c5edb3a432268e5831', 'USDT': '0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9',
                 'WETH': '0x82af49447d8a07e3bd95bd0d56f35241523fbab1', 'DAI': '0xda10009cbd5d07dd0cecc66161fc93d7c9000da1'},
    'optimism': {'USDC': '0x0b2c639c533813f4aa9d7837caf62653d097ff85', 'USDT': '0x94b008aa00579c1307b0ef2c499ad98a8ce58e58',
                 'WETH': '0x4200000000000000000000000000000000000006', 'DAI': '0xda10009cbd5d07dd0cecc66161fc93d7c9000da1'},
    'polygon': {'USDC': '0x3c499c542cef5e3811e1192ce70d8cc03d5c3359', 'USDT': '0xc2132d05d31c914a87c6611c10748aeb04b58e8f',
                'WETH': '0x7ceb23fd6bc0add59e62ac25578270cff1b9f619', 'DAI': '0x8f3cf7ad23cd3cadbd9735aff958023239c6a063'},
}


def _addr(value):
    if not isinstance(value, str) or not ADDRESS.fullmatch(value):
        raise ValueError('invalid EVM address')
    return value.lower()


def _topic(address):
    return '0x' + '0' * 24 + _addr(address)[2:]


def _decode_string(hexdata):
    data = bytes.fromhex(str(hexdata)[2:])
    if len(data) == 32:  # bytes32 names (old tokens)
        return data.rstrip(b'\0').decode('utf-8', 'replace')
    if len(data) < 64:
        return ''
    length = int.from_bytes(data[32:64], 'big')
    return data[64:64 + length].decode('utf-8', 'replace')


def token_info(chain, token, call=rpc.call):
    url = rpc.EVM_RPC[chain]
    token = _addr(token)
    code = call(url, 'eth_getCode', [token, 'latest'])
    info = {'token': token, 'chain': chain, 'has_code': code not in (None, '0x', '0x0')}
    for field, selector in (('name', '0x06fdde03'), ('symbol', '0x95d89b41')):
        try:
            info[field] = _decode_string(call(url, 'eth_call', [{'to': token, 'data': selector}, 'latest']))
        except (rpc.RpcError, ValueError):
            info[field] = None
    info['flags'] = impersonation_flags(chain, token, info.get('symbol'), info.get('name'))
    if not info['has_code']:
        info['flags'].append('no contract code at this address')
    return info


def impersonation_flags(chain, token, symbol, name=None):
    flags = []
    canon = CANONICAL.get(chain, {})
    norm = re.sub(r'[^A-Z0-9]', '', str(symbol or '').upper())
    if norm in canon and canon[norm] != token.lower():
        flags.append(f'symbol {norm} but not the canonical {norm} address on {chain} ({canon[norm]})')
    text = f'{symbol or ""} {name or ""}'.lower()
    if re.search(r'https?://|www\.|\.com|\.io|claim|airdrop|visit|reward', text):
        flags.append('name or symbol advertises a link or claim (common scam pattern)')
    return flags


def approvals(chain, owner, from_block, to_block, step=2000, call=rpc.call):
    """Current non-zero allowances granted by owner in the block range, with risk flags."""
    url = rpc.EVM_RPC[chain]
    owner = _addr(owner)
    if to_block < from_block or to_block - from_block > 2_000_000:
        raise ValueError('block range must be ascending and at most 2,000,000 blocks')
    pairs = set()
    for start in range(from_block, to_block + 1, step):
        logs = call(url, 'eth_getLogs', [{'fromBlock': hex(start), 'toBlock': hex(min(start + step - 1, to_block)),
                                          'topics': [APPROVAL_TOPIC, _topic(owner)]}])
        for log in logs or []:
            topics = log.get('topics') or []
            if len(topics) >= 3:
                pairs.add((log['address'].lower(), '0x' + topics[2][-40:].lower()))
    out = []
    for token, spender in sorted(pairs):
        data = '0xdd62ed3e' + owner[2:].rjust(64, '0') + spender[2:].rjust(64, '0')
        try:
            allowance = int(call(url, 'eth_call', [{'to': token, 'data': data}, 'latest']), 16)
        except (rpc.RpcError, ValueError, TypeError):
            continue
        if allowance == 0:
            continue
        flags = []
        if allowance >= UNLIMITED:
            flags.append('unlimited allowance')
        code = call(url, 'eth_getCode', [spender, 'latest'])
        if code in (None, '0x', '0x0'):
            flags.append('spender has no contract code (EOA): it can move these tokens directly')
        out.append({'token': token, 'spender': spender, 'allowance': str(allowance), 'flags': flags})
    return out
