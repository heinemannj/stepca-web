# services/x509_service.py

import json
from datetime import datetime
import pytz
from app.extensions import db
from .cert_utils import parse_cert_from_bytes, parse_cert
from .db_step import get_provisioners
from app.models.x509 import X509Cert, X509CertData, RevokedX509Cert, X509Crl, GeneratedCert

import base64

def get_x509_certs():
    certs = []

    x509_certs = X509Cert.query.all()
    revoked_certs = get_revoked_x509_certs()
    revoked_serials = {cert["data"]["Serial"] for cert in revoked_certs}
    now = datetime.utcnow().replace(tzinfo=pytz.UTC)

    for cert in x509_certs:
        try:
            cert_id = cert.nkey.hex()
            #cert_id = cert.nkey.decode("utf-8", errors="ignore")
            cert_bytes = cert.nvalue
            data = parse_cert_from_bytes(cert_bytes)
            cert_metadata = get_x509_certs_data_by_id(cert_id)
            validation = {
                "status": None,
                "expired": None,
                "revoked": None,
                "revoked_at": None,
                "revoked_by": None
            }

            if cert_id in revoked_serials:
                revoked_data = get_revoked_x509_certs_by_id(cert_id)
                validation["revoked"] = "true"
                validation["revoked_at"] = revoked_data["data"]["RevokedAt"]
                validation["revoked_by"] = revoked_data["data"]["provisioner_name"]

            try:
                start = datetime.fromisoformat(data["validity"].get("start", "").replace("Z", "+00:00")).astimezone(pytz.UTC)
                end = datetime.fromisoformat(data["validity"].get("end", "").replace("Z", "+00:00")).astimezone(pytz.UTC)

                if start <= now <= end:
                    validation["status"] = "valid"
                else:
                    validation["expired"] = "true"
            except Exception as e:
                print(f"Invalid cert dates for {cert_id}: {e}")

            certs.append({"nkey": cert_id, "data": data, "provisioner": cert_metadata["data"]["provisioner"], "validation": validation})
        except Exception as e:
            certs.append({"nkey": cert.nkey.hex(), "data": {"subject_dn": "[error decoding cert]", "error": str(e)}})

    for cert in certs:
        subject_map = {c["nkey"] for c in certs if (c["data"]["subject_dn"] == cert["data"]["subject_dn"] and c["validation"]["status"] == "valid")}
        if subject_map and cert["validation"]["status"] != "valid":
            cert["validation"]["status"] = "renewed"
        elif not subject_map:
            cert["validation"]["status"] = "expired"
    return certs


def get_x509_certs_by_id(cert_id):
    all_certs = get_x509_certs()
    return next((c for c in all_certs if c["nkey"] == cert_id), None)


def get_x509_certs_by_serial(serial):
    all_certs = get_x509_certs()
    return next((c for c in all_certs if c["data"]["serial_number"] == serial), None)


def get_x509_certs_data():
    results = []
    for row in X509CertData.query.all():
        try:
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            results.append({"nkey": serial, "data": value})
        except Exception as e:
            results.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return results


def get_x509_certs_data_by_id(cert_id):
    for row in X509CertData.query.all():
        try:
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            if serial == cert_id:
                return {"nkey": serial, "data": value}
        except Exception as e:
            pass
    return None


def get_revoked_x509_certs():
    certs = []
    for row in RevokedX509Cert.query.all():
        try:
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            certs.append({"nkey": serial, "data": value})
        except Exception as e:
            certs.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return certs


def get_revoked_x509_certs_by_id(cert_id):
    prov_map = {p["data"]["id"]: p["data"]["name"] for p in get_provisioners() if "data" in p}
    for row in RevokedX509Cert.query.all():
        try:
            value = json.loads(row.nvalue)
            serial = value.get("Serial", "").lower()
            value["provisioner_name"] = prov_map.get(value.get("ProvisionerID"), "—")
            if serial == cert_id:
                return {"nkey": serial, "data": value}
        except Exception as e:
            pass
    return None


def get_revoked_x509_with_cert_info():
    revocations = []
    rows = RevokedX509Cert.query.all()
    cert_map = {c["nkey"]: c["data"] for c in get_x509_certs()}
    prov_map = {p["data"]["id"]: p["data"]["name"] for p in get_provisioners() if "data" in p}

    for row in rows:
        try:
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            serial_hex = value.get("Serial", "").lower()
            cert_info = cert_map.get(serial_hex)
            value["provisioner_name"] = prov_map.get(value.get("ProvisionerID"), "—")
            revocations.append({"nkey": serial, "data": value, "cert": cert_info})
        except Exception as e:
            revocations.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return revocations


def get_generated_certs():
    return [
        {
            "id": row.id,
            "serial": row.serial,
            "common_name": row.common_name,
            "provisioner": row.provisioner,
            "created_at": row.created_at,
            "csr": row.csr,
            "certificate": row.certificate,
        }
        for row in GeneratedCert.query.order_by(GeneratedCert.created_at.desc()).all()
    ]


def get_generated_cert_by_serial(serial):
    row = GeneratedCert.query.filter_by(serial=serial).first()
    if row:
        return {
            "id": row.id,
            "serial": row.serial,
            "common_name": row.common_name,
            "provisioner": row.provisioner,
            "created_at": row.created_at,
            "csr": row.csr,
            "certificate": row.certificate,
        }
    return None


def save_generated_cert(serial, common_name, provisioner, csr_pem, cert_pem):
    new_cert = GeneratedCert(serial=serial, common_name=common_name, provisioner=provisioner, csr=csr_pem, certificate=cert_pem)
    db.session.add(new_cert)
    db.session.commit()


def get_x509_active_certs():
    x509_certs = get_x509_certs()
    certs = []

    for cert in x509_certs:
        serial = cert["nkey"]

        if cert["validation"]["status"] == "valid":
            certs.append(cert)

        # Enrich with `generated` flag
        generated_serials = {g["serial"] for g in get_generated_certs()}

    for cert in certs:
        if cert["data"].get("serial") in generated_serials:
            cert["data"]["generated"] = True

    return certs


def get_x509_revoked_certs():
    x509_certs = get_x509_certs()
    certs = []

    for cert in x509_certs:
        serial = cert["nkey"]

        if cert["validation"]["revoked"] == "true":
            certs.append(cert)

    return certs


def get_x509_crl():
    item = []
    for row in X509Crl.query.all():
        try:
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            
            item.append({"nkey": serial, "data": value})
        except Exception as e:
            item.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return item
