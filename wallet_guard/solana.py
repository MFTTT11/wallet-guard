"""Solana checks: token-account delegates (the Solana form of an approval)."""
from __future__ import annotations

import re

from . import rpc

PROGRAMS = ('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb')
PUBKEY = re.compile(r'[1-9A-HJ-NP-Za-km-z]{32,44}\Z')


def delegates(owner, call=rpc.call, url=rpc.SOLANA_RPC):
    """Token accounts with a delegate, frozen state or Token-2022 hooks; failed queries make the report incomplete."""
    if not isinstance(owner, str) or not PUBKEY.fullmatch(owner):
        raise ValueError('invalid Solana address')
    out, failed = [], []
    for program in PROGRAMS:
        try:
            res = call(url, 'getTokenAccountsByOwner', [owner, {'programId': program}, {'encoding': 'jsonParsed', 'commitment': 'finalized'}])
        except (rpc.RpcError, OSError, ValueError) as exc:
            failed.append({'query': 'getTokenAccountsByOwner', 'program': program, 'error': f'{type(exc).__name__}: {exc}'[:160]})
            continue
        for acc in (res or {}).get('value', []):
            info = (((acc.get('account') or {}).get('data') or {}).get('parsed') or {}).get('info') or {}
            flags = []
            if info.get('delegate'):
                flags.append(f"delegate {info['delegate']} may move {(info.get('delegatedAmount') or {}).get('uiAmountString', '?')} tokens")
            if info.get('state') == 'frozen':
                flags.append('account is frozen by the mint authority')
            if program == PROGRAMS[1]:
                flags.append('Token-2022 account: check transfer hooks / fees of this mint')
            if flags:
                out.append({'account': acc.get('pubkey'), 'mint': info.get('mint'),
                            'amount': (info.get('tokenAmount') or {}).get('uiAmountString'), 'flags': flags})
    return {'owner': owner, 'programs_scanned': list(PROGRAMS), 'incomplete': bool(failed), 'failed_queries': failed, 'accounts': out}
