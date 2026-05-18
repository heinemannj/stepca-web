import json
#from datetime import datetime
#import pytz
from app.extensions import db
from app.models.ssh import *

#import base64


def get_ssh_certs():
    item = []
    for row in SshCerts.query.all():
        try:
            # serial = row.nkey.decode("utf-8", errors="ignore")
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            
            item.append({"nkey": serial, "data": value})
        except Exception as e:
            item.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return item


def get_ssh_host_principals():
    item = []
    for row in SshHostPrincipals.query.all():
        try:
            # serial = row.nkey.decode("utf-8", errors="ignore")
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            
            item.append({"nkey": serial, "data": value})
        except Exception as e:
            item.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return item


def get_ssh_hosts():
    item = []
    for row in SshHosts.query.all():
        try:
            # serial = row.nkey.decode("utf-8", errors="ignore")
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            
            item.append({"nkey": serial, "data": value})
        except Exception as e:
            item.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return item


def get_ssh_users():
    item = []
    for row in SshUsers.query.all():
        try:
            # serial = row.nkey.decode("utf-8", errors="ignore")
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            
            item.append({"nkey": serial, "data": value})
        except Exception as e:
            item.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return item


def get_revoked_ssh_certs():
    item = []
    for row in RevokedSshCerts.query.all():
        try:
            # serial = row.nkey.decode("utf-8", errors="ignore")
            serial = row.nkey.hex()
            value = json.loads(row.nvalue)
            
            item.append({"nkey": serial, "data": value})
        except Exception as e:
            item.append({"nkey": row.nkey.hex(), "data": {"error": str(e)}})
    return item
