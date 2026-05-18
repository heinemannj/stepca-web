import json
from datetime import datetime
import pytz
from app.extensions import db
from app.models.step import *

import base64
from .db_conn import get_connection

def get_provisioners():
    provisioners = []
    for row in Provisioners.query.all():
        try:
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            
            details_bytes = base64.b64decode(value["details"])
            value["details"] = json.loads(details_bytes)

            
            provisioners.append({"nkey": serial, "data": value})
        except Exception as e:
            provisioners.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return provisioners


def get_active_provisioner_map(provisioners):
    """
    Returns a map (dictionary) where the key is the 'id' and the value is the 'name'
    from a list of provisioner data, excluding provisioners that have 'deletedAt' set
    to '0001-01-01T00:00:00Z'.

    :param provisioners: List of provisioner dictionaries
    :return: A dictionary with provisioner 'id' as the key and 'name' as the value
    """
    provisioner_map = {
        provisioner['data']['id']: provisioner['data']['name']
        for provisioner in provisioners
        if provisioner['data'].get('deletedAt', '') == '0001-01-01T00:00:00Z'
    }
    return provisioner_map


def get_admins():
    admins = []
    for row in Admins.query.all():
        try:
            # serial = row.nkey.decode("utf-8", errors="ignore")
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            
            admins.append({"nkey": serial, "data": value})
        except Exception as e:
            admins.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return admins


def get_authority_policies():
    policies = []
    for row in AuthorityPolicies.query.all():
        try:
            # serial = row.nkey.decode("utf-8", errors="ignore")
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            
            policies.append({"nkey": serial, "data": value})
        except Exception as e:
            policies.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return policies


def get_nonces():
    nonces = []
    for row in Nonces.query.all():
        try:
            # serial = row.nkey.decode("utf-8", errors="ignore")
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            
            nonces.append({"nkey": serial, "data": value})
        except Exception as e:
            nonces.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return nonces


def get_used_ott():
    used_ott = []
    for row in UsedOtt.query.all():
        try:
            # serial = row.nkey.decode("utf-8", errors="ignore")
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            
            used_ott.append({"nkey": serial, "data": value})
        except Exception as e:
            used_ott.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return used_ott

