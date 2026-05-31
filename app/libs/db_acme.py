import json
from datetime import datetime
import pytz
from app.extensions import db
from .cert_utils import parse_cert_from_bytes, parse_cert
from .db_x509 import get_revoked_x509_certs, get_revoked_x509_certs_by_id
from app.models.acme import *


def get_acme_accounts():
    items = []
    counter = {
        "total": 0,
        "valid": 0,
        "deleted": 0
    }
    for row in db.session.query(AcmeAccount).all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode('utf-8', errors='ignore')
            data = json.loads(row.nvalue)
            if data.get('deactivatedAt', '') == '0001-01-01T00:00:00Z':
                status = "valid"
                counter["valid"] += 1
            else:
                status = "deleted"
                counter["deleted"] += 1
            items.append({"nkey": nkey, "data": data, "status": status})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})

    counter["total"] = len(items)

    return items, counter


def get_acme_account_by_id(id: str):
    for row in db.session.query(AcmeAccount).all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode('utf-8', errors='ignore')
            if nkey == id:
                data = json.loads(row.nvalue)
                if data.get('deactivatedAt', '') == '0001-01-01T00:00:00Z':
                    status = "valid"
                else:
                    status = "deleted"
                return {"nkey": nkey, "data": data, "status": status}
        except Exception as e:
            print("❌ Error parsing ACME account:", e)
    return None


def get_acme_orders():
    items = []
    for row in db.session.query(AcmeOrder).all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            data = json.loads(row.nvalue)
            account_data = get_acme_account_by_id(data["accountID"])
            account = {
                "id": account_data["data"]["id"],
                "provisionerID": account_data["data"]["provisionerID"],
                "provisionerName": account_data["data"]["provisionerName"]
            }
            items.append({"nkey": nkey, "data": data, "account": account})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return items


def get_acme_certs():
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

    for row in db.session.query(AcmeCert).all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            data = json.loads(row.nvalue)

            # Try to parse the leaf certificate if present
            parsed_info = parse_cert(data["leaf"]) if "leaf" in data else {}
            data = {**data, **parsed_info}

            account_data = get_acme_account_by_id(data["accountID"])
            account = {
                "id": account_data["data"]["id"],
                "provisionerID": account_data["data"]["provisionerID"],
                "provisionerName": account_data["data"]["provisionerName"]
            }
            provisioner = {
                "id": account_data["data"]["provisionerID"],
                "name": account_data["data"]["provisionerName"],
                "type": "ACME"
            }
            validation = {
                "status": None,
                "expired": None,
                "revoked": None
            }
            revocation = {}

            if data["serial_number"] in revoked_serials:
                revoked_data = get_revoked_x509_certs_by_id(data["serial_number"])
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

            items.append({"nkey": nkey, "data": data, "account": account, "provisioner": provisioner, "validation": validation, "revocation": revocation})
        except Exception as e:
           items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})

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


def get_acme_cert_by_id(id: str):
    for row in db.session.query(AcmeCert).all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            if nkey == id:
                data = json.loads(row.nvalue)
                parsed_info = parse_cert(data["leaf"]) if "leaf" in data else {}
                data = {**data, **parsed_info}
                account_data = get_acme_account_by_id(data["accountID"])
                account = {
                    "id": account_data["data"]["id"],
                    "provisionerID": account_data["data"]["provisionerID"],
                    "provisionerName": account_data["data"]["provisionerName"]
                }
                return {"nkey": nkey, "data": data, "account": account, "provisioner": {}, "validation": {}}
        except Exception as e:
            print("❌ Error parsing ACME certificate:", e)
    return None


def get_acme_authzs():
    items = []
    for row in db.session.query(AcmeAuthz).all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            data = json.loads(row.nvalue)
            account_data = get_acme_account_by_id(data["accountID"])
            account = {
                "id": account_data["data"]["id"],
                "provisionerID": account_data["data"]["provisionerID"],
                "provisionerName": account_data["data"]["provisionerName"]
            }
            items.append({"nkey": nkey, "data": data, "account": account})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return items


def get_acme_authz_by_id(id: str):
    for row in db.session.query(AcmeAuthz).all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            if nkey == id:
                data = json.loads(row.nvalue)
                account_data = get_acme_account_by_id(data["accountID"])
                account = {
                    "id": account_data["data"]["id"],
                    "provisionerID": account_data["data"]["provisionerID"],
                    "provisionerName": account_data["data"]["provisionerName"]
                }
                return {"nkey": nkey, "data": data, "account": account}
        except Exception as e:
            print("❌ Error parsing ACME authorization:", e)
    return None


def get_acme_challenges():
    items = []
    for row in db.session.query(AcmeChallenge).all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            data = json.loads(row.nvalue)
            account_data = get_acme_account_by_id(data["accountID"])
            account = {
                "id": account_data["data"]["id"],
                "provisionerID": account_data["data"]["provisionerID"],
                "provisionerName": account_data["data"]["provisionerName"]
            }
            items.append({"nkey": nkey, "data": data, "account": account})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return items


def get_acme_challenge_by_id(id: str):
    for row in db.session.query(AcmeChallenge).all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            if nkey == id:
                data = json.loads(row.nvalue)
                account_data = get_acme_account_by_id(data["accountID"])
                account = {
                    "id": account_data["data"]["id"],
                    "provisionerID": account_data["data"]["provisionerID"],
                    "provisionerName": account_data["data"]["provisionerName"]
                }
                return {"nkey": nkey, "data": data, "account": account}
        except Exception as e:
            print("❌ Error parsing ACME challenge:", e)
    return None


def get_acme_account_orders_index():
    items = []
    for row in db.session.query(AcmeAccountOrdersIndex).all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode('utf-8', errors='ignore')
            data = json.loads(row.nvalue)
            items.append({"nkey": nkey, "data": data})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return items


def get_acme_keyID_accountID_index():
    items = []
    for row in db.session.query(AcmeKeyIdAccountIdIndex).all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode('utf-8', errors='ignore')
            data = json.loads(row.nvalue)
            items.append({"nkey": nkey, "data": data})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return items


def get_acme_serial_certs_index():
    items = []
    for row in db.session.query(AcmeSerialCertsIndex).all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode('utf-8', errors='ignore')
            data = json.loads(row.nvalue)
            items.append({"nkey": nkey, "data": data})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return items
