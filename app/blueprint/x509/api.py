from flask import jsonify

from app.libs.db_x509 import *
from app.libs.stepapi import *

from app.blueprint.x509 import api_bp
from app.auth.decorator import login_required

from config import CA_URL
client = StepCAClient(CA_URL)


@api_bp.route("/certs/<id>")
@login_required
def api_get_x509_certs_by_id(id):
    item = get_x509_certs_by_id(id)

    if item:
        return jsonify(item)
    return jsonify({"error": "Certificate not found"}), 404


@api_bp.route("/certs")
@login_required
def api_get_x509_certs():
    item, counter = get_x509_certs()

    if item:
        return jsonify(item)
    return jsonify({"error": "Certificates not found"}), 404


@api_bp.route("/generated_certs")
@login_required
def api_get_generated_certs():
    item = get_generated_certs()

    if item:
        return jsonify(item)
    return jsonify({"error": "Generated certificates not found"}), 404


@api_bp.route("/revoked_certs")
@login_required
def api_get_revoked_x509_with_cert_info():
    item = get_revoked_x509_with_cert_info()

    if item:
        return jsonify(item)
    return jsonify({"error": "Revokoked certificates not found"}), 404


@api_bp.route("/crl")
@login_required
def api_get_x509_crl():
    item = get_x509_crl()

    if item:
        return jsonify(item)
    return jsonify({"error": "Certificate Revokation List not found"}), 404
