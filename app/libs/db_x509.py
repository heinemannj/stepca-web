import json
from datetime import datetime
import pytz
from app.extensions import db
from .cert_utils import parse_cert_from_bytes, parse_cert
from .db_step import get_provisioners
from app.models.x509 import X509Cert, X509CertData, RevokedX509Cert, X509Crl, GeneratedCert

import base64

def get_x509_certs():
    items = []
    counter = {
        "total": 0,
        "valid": 0,
        "expired": 0,
        "renewed": 0,
        "revoked": 0
    }
    revoked_serials = {cert["data"]["Serial"] for cert in get_revoked_x509_certs()}
    now = datetime.utcnow().replace(tzinfo=pytz.UTC)

    for row in X509Cert.query.all():
        try:
            nkey = row.nkey.decode("utf-8", errors="ignore")
            data = parse_cert_from_bytes(row.nvalue)
            provisioner = get_x509_certs_data_by_id(nkey)
            validation = {
                "status": None,
                "expired": None,
                "revoked": None
            }
            revocation = {}

            if nkey in revoked_serials:
                revoked_data = get_revoked_x509_certs_by_id(nkey)
                validation["revoked"] = "true"
                revocation = revoked_data["data"]

            try:
                start = datetime.fromisoformat(data["validity"].get("start", "").replace("Z", "+00:00")).astimezone(pytz.UTC)
                end = datetime.fromisoformat(data["validity"].get("end", "").replace("Z", "+00:00")).astimezone(pytz.UTC)

                if now > end:
                    validation["expired"] = "true"

                if validation["revoked"] == "true":
                    validation["status"] = "revoked"
                elif start <= now <= end:
                    validation["status"] = "valid"
                else:
                    validation["status"] = "expired"

            except Exception as e:
                print(f"Invalid cert dates for {nkey}: {e}")

            items.append({"nkey": nkey, "data": data, "provisioner": provisioner["data"]["provisioner"], "revocation": revocation, "validation": validation})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"subject_dn": "[error decoding cert]", "error": str(e)}})

    for row in items:
        subject_map = {c["nkey"] for c in items if (c["data"]["subject_dn"] == row["data"]["subject_dn"] and c["data"]["validity"]["end"] > row["data"]["validity"]["end"])}
        if subject_map and row["validation"]["status"] != "valid":
            row["validation"]["status"] = "renewed"

        if row["validation"]["status"] == "renewed":
            counter["renewed"] += 1
        elif row["validation"]["status"] == "valid":
            counter["valid"] += 1
        elif row["validation"]["status"] == "revoked":
            counter["revoked"] += 1
        elif row["validation"]["status"] == "expired":
            counter["expired"] += 1

    counter["all"] = len(items)
    counter["total"] = counter["valid"] + counter["revoked"] + counter["expired"]

    return items, counter


def get_x509_certs_by_id(id: str):
    certs, counter = get_x509_certs()
    return next((c for c in certs if c["nkey"] == id), None)


def get_x509_certs_data():
    items = []
    for row in X509CertData.query.all():
        try:
            #nkey = row.nkey.hex()
            nkey = cert.nkey.decode("utf-8", errors="ignore")
            data = json.loads(row.nvalue)
            items.append({"nkey": nkey, "data": data})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return items


def get_x509_certs_data_by_id(id: str):
    for row in X509CertData.query.all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            if nkey == id:
                data = json.loads(row.nvalue)
                return {"nkey": nkey, "data": data}
        except Exception as e:
            pass
    return None


def get_revoked_x509_certs():
    items = []
    for row in RevokedX509Cert.query.all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            data = json.loads(row.nvalue)
            items.append({"nkey": nkey, "data": data})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return items


def get_revoked_x509_certs_by_id(id: str):
    provisioners, provisioners_counter = get_provisioners()
    prov_map = {p["data"]["id"]: p["data"]["name"] for p in provisioners if "data" in p}
    for row in RevokedX509Cert.query.all():
        try:
            nkey = row.nkey.decode("utf-8", errors="ignore")
            if nkey == id:
                data = json.loads(row.nvalue)
                data["ProvisionerName"] = prov_map.get(data.get("ProvisionerID"), "—")
                return {"nkey": nkey, "data": data}
        except Exception as e:
            pass
    return None

# Usage only by api_get_revoked_x509_with_cert_info
#
def get_revoked_x509_with_cert_info():
    items = []
    certs, counter = get_x509_certs()
    provisioners, provisioners_counter = get_provisioners()
    cert_map = {c["nkey"]: c["data"] for c in certs}
    prov_map = {p["data"]["id"]: p["data"]["name"] for p in provisioners if "data" in p}

    for row in RevokedX509Cert.query.all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            data = json.loads(row.nvalue)
            certificate = cert_map.get(nkey)
            data["ProvisionerName"] = prov_map.get(data.get("ProvisionerID"), "—")
            items.append({"nkey": nkey, "data": data, "certificate": certificate})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return items


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
    items = []
    certs, counter = get_x509_certs()
    for cert in certs:
        serial = cert["nkey"]

        if cert["validation"]["status"] == "valid":
            items.append(cert)

        # Enrich with `generated` flag
        generated_serials = {g["serial"] for g in get_generated_certs()}

    for cert in items:
        if cert["data"].get("serial") in generated_serials:
            cert["data"]["generated"] = True

    return items


def get_x509_revoked_certs():
    items = []
    certs, counter = get_x509_certs()
    for item in certs:
        if item["validation"]["revoked"] == "true":
            items.append(item)
    return items


def get_x509_crl():
    items = []
    for row in X509Crl.query.all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            data = json.loads(row.nvalue)
            
            items.append({"nkey": nkey, "data": data})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return items
