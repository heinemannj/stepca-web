from flask import render_template, request, flash, redirect, jsonify, url_for
from app.blueprint.profile import bp
from config import CA_URL, APP_URL
from app.auth.decorator import login_required


@bp.route("/profile")
@login_required
def profile():
    return render_template("profile/profile.html", title="Profile", ca_url=CA_URL)
