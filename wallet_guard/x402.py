"""Optional paid HTTP API in the x402 style (HTTP 402 + USDC payment requirements).

Without an X-PAYMENT header the server answers 402 with the payment
requirements. With one, it asks a facilitator to verify the payment, runs the
check, asks the facilitator to settle and returns the result with an
X-PAYMENT-RESPONSE header. The facilitator does the cryptography; this module
never holds keys.

Status: optional, tested only with simulated facilitator responses; it is not
a hosted service and has not processed a real payment.
"""
from __future__ import annotations

import base64
import json
import urllib.request

USDC = {'base': '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', 'base-sepolia': '0x036CbD53842c5426634e7929541eC2318f3dCF7e'}


def requirements(resource, pay_to, price_usdc, network='base', description='wallet-guard check'):
    if network not in USDC:
        raise ValueError('unsupported network')
    atomic = int(round(float(price_usdc) * 10 ** 6))
    if atomic <= 0:
        raise ValueError('price must be positive')
    return {'scheme': 'exact', 'network': network, 'maxAmountRequired': str(atomic), 'resource': resource,
            'description': description, 'mimeType': 'application/json', 'payTo': pay_to, 'maxTimeoutSeconds': 120,
            'asset': USDC[network], 'extra': {'name': 'USD Coin' if network == 'base' else 'USDC', 'version': '2'}}


def payment_required(req, error='X-PAYMENT header is required'):
    return {'x402Version': 1, 'error': error, 'accepts': [req]}


def decode_payment(header):
    return json.loads(base64.b64decode(header.encode('ascii'), validate=True))


def facilitator(url, action, payment, req, post=None):
    body = {'x402Version': 1, 'paymentPayload': payment, 'paymentRequirements': req}
    if post is not None:
        return post(url.rstrip('/') + '/' + action, body)
    r = urllib.request.Request(url.rstrip('/') + '/' + action, data=json.dumps(body).encode(),
                               headers={'Content-Type': 'application/json', 'User-Agent': 'wallet-guard/0.1'})
    with urllib.request.urlopen(r, timeout=30) as resp:
        return json.loads(resp.read(1_000_001))


def handle(header, req, run, facilitator_url, post=None):
    """Return (status, body, extra_headers) for one paid request."""
    if not header:
        return 402, payment_required(req), {}
    try:
        payment = decode_payment(header)
    except (ValueError, UnicodeError):
        return 402, payment_required(req, 'invalid X-PAYMENT header'), {}
    check = facilitator(facilitator_url, 'verify', payment, req, post)
    if not check.get('isValid'):
        return 402, payment_required(req, str(check.get('invalidReason') or 'payment not valid')[:200]), {}
    result = run()
    settle = facilitator(facilitator_url, 'settle', payment, req, post)
    if not settle.get('success'):
        return 402, payment_required(req, str(settle.get('errorReason') or 'settlement failed')[:200]), {}
    receipt = base64.b64encode(json.dumps(settle).encode()).decode()
    return 200, result, {'X-PAYMENT-RESPONSE': receipt}
