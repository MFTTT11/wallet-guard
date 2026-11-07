"""wallet-guard: read-only checks for risky approvals, delegates and fake tokens.

  python3 -m wallet_guard evm-approvals --chain base --owner 0x... --from-block N --to-block M
  python3 -m wallet_guard evm-token --chain ethereum --token 0x...
  python3 -m wallet_guard solana-delegates --owner <address>
  python3 -m wallet_guard serve --pay-to 0x... --price 0.01 --network base   # optional x402 paid API
"""
from __future__ import annotations

import argparse
import http.server
import json
import sys
import urllib.parse

from . import evm, rpc, solana, x402


def _print(data):
    print(json.dumps(data, indent=2, ensure_ascii=False))


def make_handler(pay_to, price, network, facilitator_url):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            q = dict(urllib.parse.parse_qsl(url.query))
            if url.path != '/token' or 'chain' not in q or 'token' not in q:
                return self._send(404, {'error': 'use /token?chain=<chain>&token=<address>'}, {})
            resource = f'http://{self.headers.get("Host", "localhost")}{self.path}'
            req = x402.requirements(resource, pay_to, price, network)
            try:
                status, body, extra = x402.handle(self.headers.get('X-PAYMENT'), req,
                                                  lambda: evm.token_info(q['chain'], q['token']), facilitator_url)
            except (ValueError, KeyError, rpc.RpcError, OSError) as exc:
                status, body, extra = 400, {'error': type(exc).__name__}, {}
            self._send(status, body, extra)

        def _send(self, status, body, extra):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            for k, v in extra.items():
                self.send_header(k, v)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass
    return Handler


def main(argv=None):
    p = argparse.ArgumentParser(prog='wallet-guard', description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)
    a = sub.add_parser('evm-approvals'); a.add_argument('--chain', choices=sorted(rpc.EVM_RPC), required=True)
    a.add_argument('--owner', required=True); a.add_argument('--from-block', type=int, required=True); a.add_argument('--to-block', type=int, required=True)
    t = sub.add_parser('evm-token'); t.add_argument('--chain', choices=sorted(rpc.EVM_RPC), required=True); t.add_argument('--token', required=True)
    s = sub.add_parser('solana-delegates'); s.add_argument('--owner', required=True)
    v = sub.add_parser('serve'); v.add_argument('--pay-to', required=True); v.add_argument('--price', default='0.01')
    v.add_argument('--network', default='base', choices=sorted(x402.USDC)); v.add_argument('--port', type=int, default=8402)
    v.add_argument('--host', default='127.0.0.1'); v.add_argument('--facilitator', default='https://x402.org/facilitator')
    args = p.parse_args(argv)
    try:
        if args.cmd == 'evm-approvals':
            _print(evm.approvals(args.chain, args.owner, args.from_block, args.to_block))
        elif args.cmd == 'evm-token':
            _print(evm.token_info(args.chain, args.token))
        elif args.cmd == 'solana-delegates':
            _print(solana.delegates(args.owner))
        else:
            evm._addr(args.pay_to)
            server = http.server.ThreadingHTTPServer((args.host, args.port), make_handler(args.pay_to, args.price, args.network, args.facilitator))
            print(f'wallet-guard x402 API on http://{args.host}:{args.port}/token', file=sys.stderr)
            server.serve_forever()
    except (ValueError, rpc.RpcError, OSError) as exc:
        print(json.dumps({'error': f'{type(exc).__name__}: {exc}'[:300]}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
