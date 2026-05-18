from flask import jsonify

from app.libs.db_ssh import *

from app.blueprint.ssh import api_bp
from app.auth.decorator import login_required


@api_bp.route("/certs")
@login_required
def api_get_ssh_certs():
    item = get_ssh_certs()

    if item:
        return jsonify(item)
    return jsonify({"error": "SSH certificates not found"}), 404


@api_bp.route("/host_principals")
@login_required
def api_get_ssh_host_principals():
    item = get_ssh_host_principals()

    if item:
        return jsonify(item)
    return jsonify({"error": "SSH host principals not found"}), 404


@api_bp.route("/hosts")
@login_required
def api_get_ssh_hosts():
    item = get_ssh_hosts()

    if item:
        return jsonify(item)
    return jsonify({"error": "SSH hosts not found"}), 404


@api_bp.route("/users")
@login_required
def api_get_ssh_users():
    item = get_ssh_users()

    if item:
        return jsonify(item)
    return jsonify({"error": "SSH users not found"}), 404


@api_bp.route("/revoked_certs")
@login_required
def api_get_revoked_ssh_certs():
    item = get_revoked_ssh_certs()

    if item:
        return jsonify(item)
    return jsonify({"error": "Revoked SSH certificates not found"}), 404

