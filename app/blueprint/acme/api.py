from flask import jsonify

from app.libs.db_acme import *

from app.blueprint.acme import api_bp
from app.auth.decorator import login_required


@api_bp.route("/accounts")
@login_required
def accounts():
    accounts = get_acme_accounts()
    if accounts:
        return jsonify(accounts)
    return jsonify({"error": "Accounts not found"}), 404

@api_bp.route("/orders")
@login_required
def orders():
    orders = get_acme_orders()
    if orders:
        return jsonify(orders)
    return jsonify({"error": "Orders not found"}), 404

@api_bp.route("/certs")
@login_required
def certs():
    certs = get_acme_certs()
    if certs:
        return jsonify(certs)
    return jsonify({"error": "Certificates not found"}), 404

@api_bp.route("/authzs")
@login_required
def authzs():
    authzs = get_acme_authzs()
    if authzs:
        return jsonify(authzs)
    return jsonify({"error": "Authorizations not found"}), 404

@api_bp.route("/challenges")
@login_required
def challenges():
    challenges = get_acme_challenges()
    if challenges:
        return jsonify(challenges)
    return jsonify({"error": "Challenges not found"}), 404

@api_bp.route("/account_orders_index")
@login_required
def account_order_index():
    index = get_acme_account_orders_index()
    if index:
        return jsonify(index)
    return jsonify({"error": "Account Orders Index not found"}), 404

@api_bp.route("/keyid_accountid_index")
@login_required
def keyID_accountID_index():
    index = get_acme_keyID_accountID_index()
    if index:
        return jsonify(index)
    return jsonify({"error": "KeyID-AccountID Index not found"}), 404

@api_bp.route("/serial_certs_index")
@login_required
def serial_certs_index():
    index = get_acme_serial_certs_index()
    if index:
        return jsonify(index)
    return jsonify({"error": "Serial Certs Index not found"}), 404
