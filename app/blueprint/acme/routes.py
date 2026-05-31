from flask import render_template, flash, redirect, make_response, url_for, request

from app.libs.db_acme import *
from app.libs.db_step import *
from app.libs.stepapi import *

from app.blueprint.acme import bp
from config import CA_URL
from app.auth.decorator import login_required

client = StepCAClient(CA_URL)


@bp.route("/accounts")
@login_required
def accounts():
    accounts, counter = get_acme_accounts()
    return render_template(
        "acme/accounts.html",
        title = "ACME - Accounts",
        accounts = accounts,
        ca_url = CA_URL
    )


@bp.route("/orders")
@login_required
def orders():
    orders = get_acme_orders()
    return render_template(
        "acme/orders.html",
        title = "ACME - Orders",
        orders = orders,
        ca_url = CA_URL
    )


@bp.route("/certs")
@login_required
def certs():
    certs, certs_counter = get_acme_certs()
    provisioners, provisioners_counter  = get_provisioners()
    return render_template(
        "x509/certs.html",
        title = "ACME - Certificates",
        certs = certs,
        provisioners = provisioners,
        ca_url = CA_URL
    )


@bp.route("/authzs")
@login_required
def authzs():
    authzs = get_acme_authzs()
    return render_template(
        "acme/authzs.html",
        title = "ACME - Authorizations",
        authzs = authzs,
        ca_url = CA_URL
    )


@bp.route("/challenges")
@login_required
def challenges():
    challenges = get_acme_challenges()
    return render_template(
        "acme/challenges.html",
        title = "ACME - Challenges",
        challenges = challenges,
        ca_url = CA_URL
    )
