"""
mock_server/app.py
------------------
A deliberately vulnerable Flask server.
Use this to test Vigilant-API locally without a real target.

INTENTIONAL VULNERABILITIES (for learning):
  - /transactions/<id>   → BOLA: no ownership check, any token can read any record
  - /profile/<id>        → BOLA: same issue
  - /fetch               → SSRF: blind fetch of any URL passed in ?url= param
  - /transfer            → Body IDOR: accepts any from_account_id in POST body
  - /export              → Parameter Pollution: ?id=X&id=Y uses last value

Run with:
    cd mock_server
    python app.py

The server listens on http://localhost:5000
"""

import base64
import requests as ext_requests
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

# ── Fake database ────────────────────────────────────────────────────
USERS = {
    'token_alice': {'user_id': 1, 'name': 'alice', 'role': 'customer'},
    'token_bob':   {'user_id': 2, 'name': 'bob',   'role': 'customer'},
    'token_admin': {'user_id': 9, 'name': 'admin', 'role': 'admin'},
}

TRANSACTIONS = {
    1: {'id': 1, 'owner_id': 1, 'amount': 500.00,  'description': 'Coffee',  'status': 'settled'},
    2: {'id': 2, 'owner_id': 2, 'amount': 1200.00, 'description': 'Rent',    'status': 'settled'},
    3: {'id': 3, 'owner_id': 1, 'amount': 75.50,   'description': 'Groceries','status': 'pending'},
}

ACCOUNTS = {
    1: {'id': 1, 'owner_id': 1, 'balance': 5000.00, 'account_no': 'ACC-001'},
    2: {'id': 2, 'owner_id': 2, 'balance': 2500.00, 'account_no': 'ACC-002'},
}


def get_current_user():
    """Extract user from Authorization header."""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    token = auth[len('Bearer '):]
    return USERS.get(token)


def require_auth():
    user = get_current_user()
    if not user:
        abort(401)
    return user


# ── Endpoints ────────────────────────────────────────────────────────

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'vigilant-api mock server'})


# ❌ VULNERABLE: No ownership check — any authenticated user can read any transaction
@app.route('/transactions/<int:txn_id>', methods=['GET'])
def get_transaction(txn_id):
    require_auth()   # only checks that a token is present, NOT that it owns the resource
    txn = TRANSACTIONS.get(txn_id)
    if not txn:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(txn)   # ← BOLA: returns data to any user, not just the owner


# ❌ VULNERABLE: Same issue for profile
@app.route('/profile/<int:user_id>', methods=['GET'])
def get_profile(user_id):
    require_auth()
    for token_key, u in USERS.items():
        if u['user_id'] == user_id:
            return jsonify({'user_id': u['user_id'], 'name': u['name'], 'role': u['role']})
    return jsonify({'error': 'Not found'}), 404


# ❌ VULNERABLE: SSRF — fetches any URL passed in ?url= without validation
@app.route('/fetch', methods=['GET'])
def fetch_url():
    require_auth()
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'url param required'}), 400
    try:
        resp = ext_requests.get(url, timeout=5)   # ← SSRF: no allowlist, fetches anything
        return jsonify({'status': resp.status_code, 'body': resp.text[:500]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ❌ VULNERABLE: Body IDOR — accepts from_account_id from user without ownership check
@app.route('/transfer', methods=['POST'])
def transfer():
    user = require_auth()
    data = request.get_json() or {}
    from_id = data.get('from_account_id')
    to_id   = data.get('to_account_id')
    amount  = data.get('amount', 0)

    # ← BOLA: should check ACCOUNTS[from_id]['owner_id'] == user['user_id']
    # But it doesn't! Any user can transfer from any account.
    if from_id not in ACCOUNTS or to_id not in ACCOUNTS:
        return jsonify({'error': 'Account not found'}), 404

    return jsonify({
        'status': 'success',
        'from_account': from_id,
        'to_account': to_id,
        'amount': amount,
        'message': f'Transferred {amount} from account {from_id} to {to_id}'
    })


# ❌ VULNERABLE: Parameter Pollution — uses request.args.getlist('id')[-1] (last value wins)
@app.route('/export', methods=['GET'])
def export():
    require_auth()
    ids = request.args.getlist('id')   # e.g. ?id=1&id=2 → ['1','2']
    if not ids:
        return jsonify({'error': 'id param required'}), 400

    # Uses LAST value when multiple supplied (easy to bypass)
    target_id = int(ids[-1])
    txn = TRANSACTIONS.get(target_id)
    if not txn:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(txn)


# ❌ VULNERABLE: Indirect Reference — accepts base64/hex/int encodings of IDs
#    without verifying ownership. Attacker can encode sequential integers to
#    enumerate any transaction.
@app.route('/resource/<ref>', methods=['GET'])
def get_resource_by_ref(ref):
    require_auth()
    # Try base64 first, then hex, then plain integer
    def _pad(s):
        """Add correct base64 padding (length must be multiple of 4)."""
        return s + '=' * (-len(s) % 4)

    resource_id = None
    for decoder in [
        lambda r: int(base64.b64decode(_pad(r)).decode()),
        lambda r: int(base64.urlsafe_b64decode(_pad(r)).decode()),
        lambda r: int(r, 16),
        lambda r: int(r),
    ]:
        try:
            resource_id = decoder(ref)
            break
        except Exception:
            continue

    if resource_id is None:
        return jsonify({'error': 'Invalid reference format'}), 400

    txn = TRANSACTIONS.get(resource_id)
    if not txn:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(txn)   # ← BOLA: no ownership check — any user can decode any ID


# ❌ VULNERABLE: Mass Assignment — binds raw request body to user record
#    Accepts any field including privileged ones (role, is_admin, balance, etc.)
@app.route('/user/update', methods=['POST', 'PUT', 'PATCH'])
def update_user():
    user = require_auth()
    data = request.get_json() or {}

    # ← Mass Assignment: merges ALL request fields into user dict including
    #   privileged fields that should never be user-controllable.
    #   A real ORM equivalent would be: User.update_attributes(params)
    merged = {**user, **data}
    return jsonify(merged)


# ── SECURE versions for comparison ───────────────────────────────────

# ✅ SECURE: Checks ownership before returning data
@app.route('/secure/transactions/<int:txn_id>', methods=['GET'])
def get_transaction_secure(txn_id):
    user = require_auth()
    txn  = TRANSACTIONS.get(txn_id)
    if not txn:
        return jsonify({'error': 'Not found'}), 404
    if txn['owner_id'] != user['user_id'] and user['role'] != 'admin':
        return jsonify({'error': 'Forbidden'}), 403   # ← proper check
    return jsonify(txn)


# ✅ SECURE: Transfer validates ownership of from_account
@app.route('/secure/transfer', methods=['POST'])
def transfer_secure():
    user = require_auth()
    data = request.get_json() or {}
    from_id = data.get('from_account_id')

    account = ACCOUNTS.get(from_id)
    if not account:
        return jsonify({'error': 'Account not found'}), 404
    if account['owner_id'] != user['user_id']:
        return jsonify({'error': 'Forbidden — you do not own this account'}), 403

    return jsonify({'status': 'success', 'message': 'Transfer completed'})


if __name__ == '__main__':
    print('\n  🛡️  Vigilant-API Mock Server')
    print('  ⚠️   This server is INTENTIONALLY VULNERABLE for testing purposes')
    print('  Running on http://localhost:5000\n')
    app.run(debug=True, host='0.0.0.0', port=5000)
