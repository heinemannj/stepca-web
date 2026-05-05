import os
import json
import random
import string

basedir = os.path.abspath(os.path.dirname(__file__))
confdir = "/etc/stepca-web"

# Load settings
if os.path.exists(confdir + "/settings.json"):
  settings = confdir + "/settings.json"
elif os.path.exists("/settings.json"):
  settings = "settings.json"
else:
  print("The settings.json file does not exist.")
  exit() 

with open(settings) as f:
    config = json.load(f)

def get_config(key_path: str, default=None):
    parts = key_path.split(".")
    value = config
    try:
        for part in parts:
            value = value[part]
        return value
    except (KeyError, TypeError):
        return default

# Assign configuration values
try:
    DB_HOST = os.environ['DB_TEST']
except KeyError:
    DB_HOST = get_config("database.host")
finally:
    print("DB_HOST :", DB_HOST)

try:
    DB_USER = os.environ['DB_USER']
except KeyError:
    DB_USER = get_config("database.user")
finally:
    print("DB_USER :", DB_USER)

try:
    DB_PASSWORD = os.environ['DB_PASSWORD']
except KeyError:
    DB_PASSWORD = get_config("database.password")
finally:
    print("DB_DB_PASSWORD :", DB_PASSWORD)

try:
    DB_NAME = os.environ['DB_NAME']
except KeyError:
    DB_NAME = get_config("database.name")
finally:
    print("DB_NAME :", DB_NAME)

try:
    DB_PORT = os.environ['DB_PORT']
except KeyError:
    DB_PORT = get_config("database.port")
finally:
    print("DB_PORT :", DB_PORT)

try:
    CA_URL = os.environ['CA_URL']
except KeyError:
    CA_URL = get_config("ca.url")
finally:
    print("CA_URL :", CA_URL)

try:
    CA_FINGERPRINT = os.environ['CA_FINGERPRINT']
except KeyError:
    CA_FINGERPRINT = get_config("ca.fingerprint")
finally:
    print("CA_FINGERPRINT :", CA_FINGERPRINT)

try:
    CA_ADMIN_PROVISIONER_NAME = os.environ['CA_ADMIN_PROVISIONER_NAME']
except KeyError:
    CA_ADMIN_PROVISIONER_NAME = get_config("ca.admin_provisioner_name")
finally:
    print("CA_ADMIN_PROVISIONER_NAME :", CA_ADMIN_PROVISIONER_NAME)

class Config:
    # Authentication backend: 'ldap' (default), 'radius', 'saml', 'oidc', 'local'
    try:
        AUTH_BACKEND = os.environ['AUTH_BACKEND']
    except KeyError:
        AUTH_BACKEND = get_config("auth.backend")
    finally:
        print("AUTH_BACKEND :", AUTH_BACKEND)

    match AUTH_BACKEND:
        case "ldap":
            # LDAP-specific configuration
            LDAP_URL = os.environ.get('LDAP_URL') or get_config('ldap.url', 'ldap://localhost')
            LDAP_BASE_DN = os.environ.get('LDAP_BASE_DN') or get_config('ldap.base_dn', '')
            LDAP_DOMAIN = os.environ.get('LDAP_DOMAIN') or get_config('ldap.domain', '')
            LDAP_USER_SEARCH_FILTER = os.environ.get('LDAP_USER_SEARCH_FILTER') or get_config('ldap.user_search_filter', '(uid={username})')
            LDAP_USER_SEARCH_BASE = os.environ.get('LDAP_USER_SEARCH_BASE') or get_config('ldap.user_search_base', LDAP_BASE_DN)
            LDAP_REQUIRED_GROUP_DN = os.environ.get('LDAP_REQUIRED_GROUP_DN') or get_config('ldap.ldap_required_group_dn', LDAP_BASE_DN)
            print("LDAP_URL:", LDAP_URL)
            print("LDAP_BASE_DN:", LDAP_BASE_DN)
            print("LDAP_DOMAIN:", LDAP_DOMAIN)
            print("LDAP_USER_SEARCH_FILTER:", LDAP_USER_SEARCH_FILTER)
            print("LDAP_USER_SEARCH_BASE:", LDAP_USER_SEARCH_BASE)
            print("LDAP_REQUIRED_GROUP_DN:", LDAP_REQUIRED_GROUP_DN)
            print("SECRET_KEY:", SECRET_KEY)
            print("SQLALCHEMY_DATABASE_URI:", SQLALCHEMY_DATABASE_URI)
        case "radius":
            # RADIUS config can be added similarly
            print("Missing RADIUS settings")
            exit()
        case "saml":
            # SAML config can be added similarly
            print("Missing SAML settings")
            exit()
        case "oidc":
            # OIDC config can be added similarly
            print("Missing OIDC settings")
            exit()
        case "local":
            LOCAL_USERS = get_config("local.users")
            print("LOCAL_USERS :", LOCAL_USERS)
        case _:
            print("Missing AUTH_BACKEND setting")
            exit()

    try:
        SECRET_KEY = os.environ['SECRET_KEY']
    except KeyError:
        SECRET_KEY = "".join(
        random.choice(string.ascii_letters) for _ in range(32)
        )
    finally:
        print("SECRET_KEY :", SECRET_KEY)

    try:
        SQLALCHEMY_DATABASE_URI = os.environ['SQLALCHEMY_DATABASE_URI']
    except KeyError:
        SQLALCHEMY_DATABASE_URI = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    finally:
        print("SQLALCHEMY_DATABASE_URI :", SQLALCHEMY_DATABASE_URI)

    SQLALCHEMY_TRACK_MODIFICATIONS = False
