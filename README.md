# wallet-guard

Read-only safety checks for crypto wallets. Standard library only, no keys, no transactions.

- **EVM approvals:** finds ERC-20 `Approval` events of an owner in a block range, reads the current allowance and flags unlimited allowances and spenders without contract code.
- **Fake tokens:** flags tokens that use a well-known symbol (USDC, USDT, DAI, WETH) at a non-canonical address, or advertise links/claims in their name.
- **Solana delegates:** lists token accounts with a delegate (the Solana form of an approval), frozen accounts and Token-2022 accounts.
- **Paid API (optional, x402):** `serve` answers `402 Payment Required` with USDC payment requirements and runs the check after a facilitator verifies and settles the payment. **Status: optional module tested with simulated facilitator responses only. It is not a hosted service and has not processed a real payment.**

```bash
python3 -m wallet_guard evm-approvals --chain base --owner 0xYourAddress --from-block 30000000 --to-block 30050000
python3 -m wallet_guard evm-token --chain ethereum --token 0xTokenAddress
python3 -m wallet_guard solana-delegates --owner YourSolanaAddress
python3 -m wallet_guard serve --pay-to 0xYourAddress --price 0.01 --network base-sepolia
```

Every report says what was actually scanned. If any RPC query fails, `incomplete` is `true` and the failed queries are listed; an incomplete report is **not** a clean bill of health.

Example `evm-approvals` output (illustrative values):

```json
{
  "chain": "base",
  "owner": "0x1111111111111111111111111111111111111111",
  "scanned_block_range": [30000000, 30050000],
  "incomplete": true,
  "failed_queries": [
    {"query": "eth_getLogs", "blocks": [30018000, 30019999], "error": "RpcError: query returned more than 10000 results"}
  ],
  "approvals": [
    {"token": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "spender": "0x2222222222222222222222222222222222222222",
     "allowance": "115792089237316195423570985008687907853269984665640564039457584007913129639935",
     "flags": ["unlimited allowance"]}
  ]
}
```

Re-run failed ranges with a smaller span or your own RPC before trusting the result.

Revoke risky approvals with your wallet or a revoke tool; wallet-guard only reports. Public RPC endpoints limit `eth_getLogs` ranges; use smaller ranges or your own RPC if a query fails.

Chains: ethereum, base, arbitrum, optimism, polygon, solana.

```bash
python3 -m unittest discover -s tests
```
