import base64
import json
import unittest

from wallet_guard import evm, solana, x402

OWNER = '0x' + '1' * 40
TOKEN = '0x' + '2' * 40
SPENDER = '0x' + '3' * 40
EOA = '0x' + '4' * 40


def _str(s):
    b = s.encode()
    return '0x' + (32).to_bytes(32, 'big').hex() + len(b).to_bytes(32, 'big').hex() + b.ljust(32, b'\0').hex()


class EvmTest(unittest.TestCase):
    def test_unlimited_and_eoa_approvals_are_flagged_zero_skipped(self):
        def call(url, method, params):
            if method == 'eth_getLogs':
                t = lambda a: '0x' + '0' * 24 + a[2:]
                return [{'address': TOKEN, 'topics': [evm.APPROVAL_TOPIC, t(OWNER), t(SPENDER)]},
                        {'address': TOKEN, 'topics': [evm.APPROVAL_TOPIC, t(OWNER), t(EOA)]}]
            if method == 'eth_call':
                spender = '0x' + params[0]['data'][-40:]
                return hex(2 ** 256 - 1) if spender == SPENDER else hex(5)
            if method == 'eth_getCode':
                return '0x6080' if params[0] == SPENDER else '0x'
            raise AssertionError(method)
        report = evm.approvals('base', OWNER, 100, 5000, call=call)
        self.assertEqual((report['incomplete'], report['failed_queries'], report['scanned_block_range']), (False, [], [100, 5000]))
        rows = report['approvals']
        self.assertEqual({r['spender']: r['flags'] for r in rows},
                         {SPENDER: ['unlimited allowance'], EOA: ['spender has no contract code (EOA): it can move these tokens directly']})

    def test_failed_queries_make_the_report_incomplete(self):
        from wallet_guard import rpc
        def call(url, method, params):
            if method == 'eth_getLogs' and params[0]['fromBlock'] == hex(2100):
                raise rpc.RpcError('query returned more than 10000 results')
            if method == 'eth_getLogs':
                t = lambda a: '0x' + '0' * 24 + a[2:]
                return [{'address': TOKEN, 'topics': [evm.APPROVAL_TOPIC, t(OWNER), t(SPENDER)]}]
            if method == 'eth_call':
                raise OSError('timeout')
            raise AssertionError(method)
        report = evm.approvals('base', OWNER, 100, 4000, call=call)
        self.assertTrue(report['incomplete'])
        self.assertEqual([q['query'] for q in report['failed_queries']], ['eth_getLogs', 'allowance'])
        self.assertEqual(report['approvals'], [])

    def test_fake_usdc_is_flagged(self):
        def call(url, method, params):
            if method == 'eth_getCode':
                return '0x60'
            return _str('USDC') if params[0]['data'] == '0x95d89b41' else _str('USD Coin - visit claim-usdc.io')
        info = evm.token_info('base', TOKEN, call=call)
        self.assertEqual(len(info['flags']), 2)
        self.assertEqual(evm.impersonation_flags('base', evm.CANONICAL['base']['USDC'], 'USDC'), [])

    def test_invalid_address_rejected(self):
        with self.assertRaises(ValueError):
            evm.approvals('base', '0x123', 1, 2, call=lambda *a: [])


class SolanaTest(unittest.TestCase):
    def test_delegate_is_reported(self):
        def call(url, method, params):
            if params[1]['programId'] == solana.PROGRAMS[1]:
                return {'value': []}
            return {'value': [{'pubkey': 'Acc1', 'account': {'data': {'parsed': {'info': {
                'mint': 'Mint1', 'delegate': 'Bad1', 'delegatedAmount': {'uiAmountString': '50'}, 'state': 'initialized',
                'tokenAmount': {'uiAmountString': '50'}}}}}}, {'pubkey': 'Acc2', 'account': {'data': {'parsed': {'info': {'mint': 'M2'}}}}}]}
        report = solana.delegates('Ei7wdUkFQPs5kw843NA8kXsPw5qSbNRE3PcSAUoHw7Qb', call=call)
        self.assertFalse(report['incomplete'])
        rows = report['accounts']
        self.assertEqual([r['account'] for r in rows], ['Acc1'])
        self.assertIn('delegate Bad1', rows[0]['flags'][0])


class X402Test(unittest.TestCase):
    def setUp(self):
        self.req = x402.requirements('http://localhost/token', '0x80Be98bED7FB4478135525B47Dc1a181DD164646', '0.01')

    def test_requirements_are_usdc_on_base(self):
        self.assertEqual((self.req['maxAmountRequired'], self.req['asset'], self.req['scheme']),
                         ('10000', '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', 'exact'))

    def test_no_payment_returns_402_without_running(self):
        status, body, _ = x402.handle(None, self.req, lambda: self.fail('must not run'), 'https://f')
        self.assertEqual((status, body['x402Version'], body['accepts'][0]['payTo']), (402, 1, self.req['payTo']))

    def test_verified_and_settled_payment_runs_once(self):
        calls = []
        def post(url, body):
            calls.append(url.rsplit('/', 1)[1])
            return {'isValid': True} if url.endswith('verify') else {'success': True, 'transaction': '0xabc'}
        header = base64.b64encode(json.dumps({'x402Version': 1, 'scheme': 'exact'}).encode()).decode()
        status, body, extra = x402.handle(header, self.req, lambda: {'ok': True}, 'https://f', post)
        self.assertEqual((status, body, calls), (200, {'ok': True}, ['verify', 'settle']))
        self.assertEqual(json.loads(base64.b64decode(extra['X-PAYMENT-RESPONSE']))['transaction'], '0xabc')

    def test_invalid_payment_is_refused(self):
        post = lambda url, body: {'isValid': False, 'invalidReason': 'insufficient_funds'}
        header = base64.b64encode(b'{}').decode()
        status, body, _ = x402.handle(header, self.req, lambda: self.fail('must not run'), 'https://f', post)
        self.assertEqual((status, body['error']), (402, 'insufficient_funds'))


if __name__ == '__main__':
    unittest.main()
