"""Solana checks for a wallet's SPL and Token-2022 holdings.

Account level: delegates (the Solana form of an approval), frozen accounts.
Mint level (Token-2022 extensions and authorities): PermanentDelegate,
TransferHook, MintCloseAuthority, FreezeAuthority, MintAuthority,
TransferFeeConfig, DefaultAccountState, Pausable, NonTransferable, and fake
stablecoins whose metadata symbol copies USDC / USDT / USDG / PYUSD at a
non-canonical mint.

Regulated stablecoins (USDG, PYUSD) legitimately carry a permanent delegate,
a transfer hook and a close authority; for the canonical mints these are
reported as "expected" issuer controls instead of alarms.
"""
from __future__ import annotations

import re

from . import rpc

TOKEN, TOKEN_2022 = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
PROGRAMS = (TOKEN, TOKEN_2022)
PUBKEY = re.compile(r'[1-9A-HJ-NP-Za-km-z]{32,44}\Z')
# Canonical mints, checked against mainnet getAccountInfo (2026-11-07).
KNOWN_MINTS = {
    'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v': ('USDC', 'Circle'),
    'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB': ('USDT', 'Tether'),
    '2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH': ('USDG', 'Paxos (Global Dollar)'),
    '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo': ('PYUSD', 'Paxos (PayPal USD)'),
}
IMPERSONATED = {sym: mint for mint, (sym, _) in KNOWN_MINTS.items()}
SEVERITY = ('high', 'medium', 'low', 'expected')


def _flag(severity, code, text):
    return {'severity': severity, 'code': code, 'text': text}


def _extensions(info):
    return {e.get('extension'): (e.get('state') or {}) for e in info.get('extensions', []) or [] if isinstance(e, dict)}


def mint_flags(mint, parsed_info, program):
    """Risk flags for one mint from its jsonParsed info."""
    known = KNOWN_MINTS.get(mint)
    issuer = 'expected' if known else None
    ext = _extensions(parsed_info)
    flags = []
    if 'permanentDelegate' in ext and ext['permanentDelegate'].get('delegate'):
        flags.append(_flag(issuer or 'high', 'permanent_delegate',
                           f"permanent delegate {ext['permanentDelegate']['delegate']} can transfer or burn tokens from any holder"))
    if 'transferHook' in ext and ext['transferHook'].get('programId'):
        flags.append(_flag(issuer or 'medium', 'transfer_hook',
                           f"transfer hook program {ext['transferHook']['programId']} runs on every transfer and can block it"))
    if 'mintCloseAuthority' in ext and ext['mintCloseAuthority'].get('closeAuthority'):
        flags.append(_flag(issuer or 'medium', 'close_authority', f"mint can be closed by {ext['mintCloseAuthority']['closeAuthority']}"))
    if parsed_info.get('freezeAuthority'):
        flags.append(_flag(issuer or 'medium', 'freeze_authority', f"freeze authority {parsed_info['freezeAuthority']} can freeze any holder's account"))
    if parsed_info.get('mintAuthority'):
        flags.append(_flag(issuer or 'low', 'mint_authority', f"mint authority {parsed_info['mintAuthority']} can create new supply"))
    fee = ext.get('transferFeeConfig') or {}
    bps = max([int((fee.get(k) or {}).get('transferFeeBasisPoints') or 0) for k in ('newerTransferFee', 'olderTransferFee')] or [0])
    if bps > 0:
        flags.append(_flag(issuer or ('high' if bps >= 1000 else 'medium'), 'transfer_fee', f'transfer fee {bps / 100:.2f}% on every transfer'))
    if str((ext.get('defaultAccountState') or {}).get('accountState', '')).casefold() == 'frozen':
        flags.append(_flag(issuer or 'high', 'default_frozen', 'new token accounts start frozen'))
    if 'pausableConfig' in ext:
        flags.append(_flag(issuer or 'medium', 'pausable', 'issuer can pause all transfers'))
    if 'nonTransferable' in ext:
        flags.append(_flag('low', 'non_transferable', 'tokens cannot be transferred (soulbound)'))
    symbol = str((ext.get('tokenMetadata') or {}).get('symbol') or '').strip()
    norm = re.sub(r'[^A-Z0-9]', '', symbol.upper())
    if norm in IMPERSONATED and IMPERSONATED[norm] != mint:
        flags.append(_flag('high', 'fake_stablecoin', f'metadata symbol {symbol} but not the canonical {norm} mint {IMPERSONATED[norm]}'))
    name = f"{(ext.get('tokenMetadata') or {}).get('name') or ''} {symbol}".lower()
    if re.search(r'https?://|www\.|\.com|\.io|claim|airdrop|visit', name):
        flags.append(_flag('high', 'scam_metadata', 'token name or symbol advertises a link or claim'))
    return {'mint': mint, 'program': 'token-2022' if program == TOKEN_2022 else 'spl-token',
            'known': f'{known[0]} ({known[1]})' if known else None, 'symbol': symbol or (known[0] if known else None),
            'flags': flags}


def mint_report(mint, call=rpc.call, url=rpc.SOLANA_RPC):
    if not isinstance(mint, str) or not PUBKEY.fullmatch(mint):
        raise ValueError('invalid Solana mint')
    value = (call(url, 'getAccountInfo', [mint, {'encoding': 'jsonParsed', 'commitment': 'finalized'}]) or {}).get('value')
    if not value:
        raise ValueError('mint account not found')
    parsed = (value.get('data') or {}).get('parsed') or {}
    if parsed.get('type') != 'mint':
        raise ValueError('account is not a token mint')
    return mint_flags(mint, parsed.get('info') or {}, value.get('owner'))


def scan(owner, call=rpc.call, url=rpc.SOLANA_RPC):
    """All token accounts of owner with account and mint risks; failed queries make the report incomplete."""
    if not isinstance(owner, str) or not PUBKEY.fullmatch(owner):
        raise ValueError('invalid Solana address')
    accounts, failed, mints = [], [], {}
    for program in PROGRAMS:
        try:
            res = call(url, 'getTokenAccountsByOwner', [owner, {'programId': program}, {'encoding': 'jsonParsed', 'commitment': 'finalized'}])
        except (rpc.RpcError, OSError, ValueError) as exc:
            failed.append({'query': 'getTokenAccountsByOwner', 'program': program, 'error': f'{type(exc).__name__}: {exc}'[:160]})
            continue
        for acc in (res or {}).get('value', []):
            info = (((acc.get('account') or {}).get('data') or {}).get('parsed') or {}).get('info') or {}
            flags = []
            delegated = (info.get('delegatedAmount') or {}).get('uiAmountString')
            if info.get('delegate'):
                flags.append(_flag('high', 'delegate', f"delegate {info['delegate']} may move {delegated or '?'} tokens"))
            if info.get('state') == 'frozen':
                flags.append(_flag('medium', 'frozen', 'account is frozen by the mint authority'))
            accounts.append({'account': acc.get('pubkey'), 'mint': info.get('mint'), 'program': program,
                             'amount': (info.get('tokenAmount') or {}).get('uiAmountString'), 'flags': flags})
            if info.get('mint'):
                mints[info['mint']] = program
    reports = {}
    keys = sorted(mints)
    for i in range(0, len(keys), 100):
        batch = keys[i:i + 100]
        try:
            res = call(url, 'getMultipleAccounts', [batch, {'encoding': 'jsonParsed', 'commitment': 'finalized'}])
        except (rpc.RpcError, OSError, ValueError) as exc:
            failed.append({'query': 'getMultipleAccounts', 'mints': len(batch), 'error': f'{type(exc).__name__}: {exc}'[:160]})
            continue
        for mint, value in zip(batch, (res or {}).get('value', [])):
            parsed = ((value or {}).get('data') or {}).get('parsed') or {}
            if parsed.get('type') == 'mint':
                reports[mint] = mint_flags(mint, parsed.get('info') or {}, (value or {}).get('owner'))
            else:
                failed.append({'query': 'mint', 'mint': mint, 'error': 'mint account unreadable'})
    for acc in accounts:
        acc['mint_report'] = reports.get(acc['mint'])
    counts = {s: 0 for s in SEVERITY}
    for acc in accounts:
        for f in acc['flags'] + ((acc['mint_report'] or {}).get('flags') or []):
            counts[f['severity']] += 1
    risky = [a for a in accounts if a['flags'] or any(f['severity'] != 'expected' for f in (a['mint_report'] or {}).get('flags', []))]
    return {'owner': owner, 'programs_scanned': list(PROGRAMS), 'incomplete': bool(failed), 'failed_queries': failed,
            'token_accounts': len(accounts), 'severity_counts': counts, 'accounts': risky}


def delegates(owner, call=rpc.call, url=rpc.SOLANA_RPC):
    """Backwards-compatible name for scan()."""
    return scan(owner, call, url)
