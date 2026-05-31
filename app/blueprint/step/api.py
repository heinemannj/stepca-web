from flask import jsonify

from app.libs.db_step import *
from app.libs.stepapi import *

from app.blueprint.step import api_bp
from app.auth.decorator import login_required

from config import CA_URL
client = StepCAClient(CA_URL)

@api_bp.route("/admins")
@login_required
def api_get_admins():
    item, counter = get_admins()

    if item:
        return jsonify(item)
    return jsonify({"error": "Admins not found"}), 404

@api_bp.route("/admins_cli")
@login_required
def api_list_admins():
    item = client.list_admins()

    if item:
        return jsonify(item)
    return jsonify({"error": "Admins not found"}), 404


@api_bp.route("/provisioners")
@login_required
def api_get_provisioners():
    item, counter = get_provisioners()

    if item:
        return jsonify(item)
    return jsonify({"error": "Provisioners not found"}), 404


@api_bp.route("/provisioners/<id>")
@login_required
def api_get_provisioners_by_id(id):
    item = get_provisioners_by_id(id)

    if item:
        return jsonify(item)
    return jsonify({"error": "Provisioner not found"}), 404


@api_bp.route("/provisioners_cli")
@login_required
def api_list_provisioners():
    item = client.list_provisioners()

    if item:
        return jsonify(item)
    return jsonify({"error": "Provisioners not found"}), 404


@api_bp.route("/authority_policies")
@login_required
def api_get_authority_policies():
    item = get_authority_policies()

    if item:
        return jsonify(item)
    return jsonify({"error": "Authority Policies not found"}), 404


@api_bp.route("/nonces")
@login_required
def api_get_nonces():
    item = get_nonces()

    if item:
        return jsonify(item)
    return jsonify({"error": "Nonces not found"}), 404


@api_bp.route("/used_ott")
@login_required
def api_get_used_ott():
    item = get_used_ott()

    if item:
        return jsonify(item)
    return jsonify({"error": "UsedOtt not found"}), 404

