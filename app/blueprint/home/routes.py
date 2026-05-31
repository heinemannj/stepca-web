from flask import render_template
from app.blueprint.home import bp
from app.libs.db_x509 import *
from app.libs.db_acme import *
from app.libs.db_step import *
from config import CA_URL, APP_URL
from app.auth.decorator import login_required


@bp.route("/")
@login_required
def index():
    x509_certs, x509_certs_counter = get_x509_certs()
    acme_certs, acme_certs_counter = get_acme_certs()
    acme_accounts, acme_accounts_counter = get_acme_accounts()
    admins, admins_counter = get_admins()
    provisioners, provisioners_counter = get_provisioners()

    return render_template(
        "home/index.html",
        title = "Dashboard - Certificate Summary",
        count={
            "provisioners": provisioners_counter,
            "admins": admins_counter,
            "acme_accounts": acme_accounts_counter,
            "acme_certs": acme_certs_counter,
            "x509_certs": x509_certs_counter
        },
        ca_url=CA_URL
    )


@bp.route("/step-ca-api")
@login_required
def step_ca_api():
    return render_template(
        "home/step-ca-api.html",
        title = "step-ca API",
        ca_url = CA_URL
    )


@bp.route("/step-ca-admin-api")
@login_required
def step_ca_admin_api():
    return render_template(
        "home/step-ca-admin-api.html",
        title = "step-ca Admin API",
        ca_url = CA_URL,
        app_url = APP_URL
    )
