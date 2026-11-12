# wallet-guard

Read-only safety checks for crypto wallets. Standard library only, no keys, no transactions.

**Try it in the browser (no install):** https://mfttt11.github.io/wallet-guard/ — a single static page that asks a Solana RPC for public data from your browser. Nothing is signed or sent anywhere else.

- **EVM approvals:** finds ERC-20 `Approval` events of an owner in a block range, reads the current allowance and flags unlimited allowances and spenders without contract code.
- **Fake tokens:** flags tokens that use a well-known symbol (USDC, USDT, DAI, WETH) at a non-canonical address, or advertise links/claims in their name.
- **Solana (SPL + Token-2022):** token-account delegates and frozen accounts; mint risks: PermanentDelegate, TransferHook, MintCloseAuthority, FreezeAuthority, MintAuthority, transfer fees, default-frozen accounts, pausable mints, and USDC / USDT / USDG / PYUSD look-alikes. Canonical regulated stablecoins (USDG and PYUSD carry a permanent delegate, a transfer hook and a close authority by design) are reported as `expected` issuer controls, not alarms.
- **Paid API (optional, x402):** `serve` answers `402 Payment Required` with USDC payment requirements and runs the check after a facilitator verifies and settles the payment. **Status: optional module tested with simulated facilitator responses only. It is not a hosted service and has not processed a real payment.**

```bash
python3 -m wallet_guard evm-approvals --chain base --owner 0xYourAddress --from-block 30000000 --to-block 30050000
python3 -m wallet_guard evm-token --chain ethereum --token 0xTokenAddress
python3 -m wallet_guard solana-scan --owner YourSolanaAddress
python3 -m wallet_guard solana-mint --mint 2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH
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

## Voluntary Open-Source Support & Self-Hosted Gateway

Voluntary non-custodial support for continuous open-source security research and scanner tooling. Voluntary contributions do not automatically grant a hosted SaaS subscription or API key; there is no hosted paid API server active.

- **EVM Support Address (Base / Arbitrum / Ethereum):** `0x80Be98bED7FB4478135525B47Dc1a181DD164646`
- **Solana Support Address (USDC / SOL):** `Ei7wdUkFQPs5kw843NA8kXsPw5qSbNRE3PcSAUoHw7Qb`

### Self-Hosted x402 Example & Local Verification

1. **Self-Hosted x402 Gateway:**
   Run the local x402 payment-gated microservice (optional module tested with simulated facilitator responses):
   ```bash
   python3 -m wallet_guard serve --pay-to 0x80Be98bED7FB4478135525B47Dc1a181DD164646 --price 0.01 --network base
   ```
   Without an `X-PAYMENT` header, requests return HTTP `402 Payment Required` detailing exact payment specs. With a valid payment settlement header from an x402 facilitator, the query executes and returns the audit result.

2. **Voluntary On-Chain Contributions:**
   Contributions (USDC, ETH, or SOL) sent to the non-custodial addresses above can be verified directly on block explorers (BaseScan, Arbiscan, Etherscan, or Solscan).

```bash
python3 -m unittest discover -s tests
```
