from flask import jsonify

from app.libs.db_acme import *

from app.blueprint.acme import api_bp
from app.auth.decorator import login_required


@api_bp.route("/accounts")
@login_required
def api_accounts():
    items, counter = get_acme_accounts()
    if items:
        return jsonify(items)
    return jsonify({"error": "Accounts not found"}), 404


@api_bp.route("/accounts/<id>")
@login_required
def api_account_by_id(id):
    item = get_acme_account_by_id(id)
    if item:
        return jsonify(item)
    return jsonify({"error": "Account not found"}), 404


@api_bp.route("/orders")
@login_required
def api_orders():
    items = get_acme_orders()
    if items:
        return jsonify(items)
    return jsonify({"error": "Orders not found"}), 404


@api_bp.route("/certs")
@login_required
def api_certs():
    items, counter = get_acme_certs()
    if items:
        return jsonify(items)
    return jsonify({"error": "Certificates not found"}), 404


@api_bp.route("/certs/<id>")
@login_required
def api_cert_by_id(id):
    item = get_acme_cert_by_id(id)
    if item:
        return jsonify(item)
    return jsonify({"error": "Certificate not found"}), 404


@api_bp.route("/authzs")
@login_required
def api_authzs():
    items = get_acme_authzs()
    if items:
        return jsonify(items)
    return jsonify({"error": "Authorizations not found"}), 404


@api_bp.route("/authzs/<id>")
@login_required
def api_authz_by_id(id):
    item = get_acme_authz_by_id(id)
    if item:
        return jsonify(item)
    return jsonify({"error": "Authorization not found"}), 404


@api_bp.route("/challenges")
@login_required
def api_challenges():
    items = get_acme_challenges()
    if items:
        return jsonify(items)
    return jsonify({"error": "Challenges not found"}), 404


@api_bp.route("/challenges/<id>")
@login_required
def api_challenge_by_id(id):
    item = get_acme_challenge_by_id(id)
    if item:
        return jsonify(item)
    return jsonify({"error": "Authorization not found"}), 404


@api_bp.route("/account_orders_index")
@login_required
def api_account_order_index():
    items = get_acme_account_orders_index()
    if items:
        return jsonify(items)
    return jsonify({"error": "Account Orders Index not found"}), 404


@api_bp.route("/keyid_accountid_index")
@login_required
def api_keyID_accountID_index():
    items = get_acme_keyID_accountID_index()
    if items:
        return jsonify(items)
    return jsonify({"error": "KeyID-AccountID Index not found"}), 404


@api_bp.route("/serial_certs_index")
@login_required
def api_serial_certs_index():
    items = get_acme_serial_certs_index()
    if items:
        return jsonify(items)
    return jsonify({"error": "Serial Certs Index not found"}), 404
