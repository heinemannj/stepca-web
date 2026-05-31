import json
from datetime import datetime
import pytz
from app.extensions import db
from app.models.step import *

import base64
#from .db_conn import get_connection


def get_provisioners():
    items = []
    counter = {
        "total": 0,
        "valid": 0,
        "deleted": 0
    }
    for row in Provisioners.query.all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            data = json.loads(row.nvalue)

            details_bytes = base64.b64decode(data["details"])
            data["details"] = json.loads(details_bytes)

            if data.get('deletedAt', '') == '0001-01-01T00:00:00Z':
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


def get_provisioners_by_id(provisioner_id: str):
    for row in Provisioners.query.all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            if nkey == provisioner_id:
                data = json.loads(row.nvalue)

                details_bytes = base64.b64decode(data["details"])
                data["details"] = json.loads(details_bytes)

                if data.get('deletedAt', '') == '0001-01-01T00:00:00Z':
                    status = "valid"
                else:
                    status = "deleted"

                return {"nkey": nkey, "data": data, "status": status}
        except Exception as e:
            print("❌ Error parsing provisioner:", e)
    return None


def get_admins():
    items = []
    counter = {
        "total": 0,
        "valid": 0,
        "deleted": 0
    }
    provisioners, provisioners_counter = get_provisioners()
    prov_map = {p["nkey"]: p["data"] for p in provisioners if "data" in p}
    for row in Admins.query.all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            nvalue = row.nvalue.decode("utf-8", errors="ignore")
            data = json.loads(nvalue)
            provisioner = prov_map.get(data.get("provisionerID"), "—")

            if data.get('deletedAt', '') == '0001-01-01T00:00:00Z':
                status = "valid"
                counter["valid"] += 1
            else:
                status = "deleted"
                counter["deleted"] += 1

            items.append({
                "nkey": nkey,
                "data": data,
                "status": status,
                "provisioner": {
                    "id": provisioner["id"],
                    "authorityID": provisioner["authorityID"],
                    "name": provisioner["name"],
                    "type": provisioner["type"],
                    "createdAt": provisioner["createdAt"],
                    "deletedAt": provisioner["deletedAt"]
                }
            })
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})

    counter["total"] = len(items)

    return items, counter


def get_active_admin_map():
    admins, admins_counter = get_admins()
    admin_map = {
        admin['nkey']: admin['data']
        for admin in admins
          if admin['data'].get('deletedAt', '') == '0001-01-01T00:00:00Z'
    }
    return admin_map


def get_authority_policies():
    items = []
    for row in AuthorityPolicies.query.all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            data = json.loads(row.nvalue)
            
            items.append({"nkey": nkey, "data": data})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return items


def get_nonces():
    items = []
    for row in Nonces.query.all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            data = json.loads(row.nvalue)
            
            items.append({"nkey": nkey, "data": data})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return items


def get_used_ott():
    items = []
    for row in UsedOtt.query.all():
        try:
            #nkey = row.nkey.hex()
            nkey = row.nkey.decode("utf-8", errors="ignore")
            
            #nvalue = row.nvalue.decode("utf-8", errors="ignore")
            #value = json.loads(nvalue)
            
            data = json.loads(row.nvalue)
            
            items.append({"nkey": nkey, "data": data})
        except Exception as e:
            items.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return items

