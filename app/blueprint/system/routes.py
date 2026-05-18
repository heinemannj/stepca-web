from flask import render_template, request, flash, redirect, jsonify, url_for
from app.libs.db_step import *
from app.blueprint.system import bp
from app.libs.stepapi import *
from config import *
import subprocess
from app.auth.decorator import login_required

client = StepCAClient(CA_URL)

SETTINGS_FILE = "settings.json"


def load_config():
    if not os.path.exists(SETTINGS_FILE):
        return {
            "database": {"host": "", "user": "", "password": "", "name": "", "port": 5432},
            "ca": {"url": "", "fingerprint": ""},
        }
    with open(SETTINGS_FILE) as f:
        return json.load(f)


@bp.route("/config", methods=["GET", "POST"])
@login_required
def config():
    config_data = load_config()

    if request.method == "POST":
        # Get data from form
        config_data["database"]["host"] = request.form["db_host"]
        config_data["database"]["user"] = request.form["db_user"]
        config_data["database"]["password"] = request.form["db_password"]
        config_data["database"]["name"] = request.form["db_name"]
        config_data["database"]["port"] = int(request.form["db_port"])
        config_data["ca"]["url"] = request.form["ca_url"]
        config_data["ca"]["root"] = request.form["ca_root"]
        config_data["ca"]["intermediate"] = request.form["ca_intermediate"]
        config_data["ca"]["fingerprint"] = request.form["ca_fingerprint"]
        config_data["ca"]["admin_provisioner_name"] = request.form["ca_admin_provisioner_name"]
        config_data["ca"]["config"] = request.form["ca_config"]
        config_data["auth"]["backend"] = request.form["auth_backend"]

        # Write updated config to JSON
        with open(SETTINGS_FILE, "w") as f:
            json.dump(config_data, f, indent=2)

        flash("Configuration updated successfully!", "success")
        return redirect(url_for("system.config"))

    # Pass values to template
    return render_template(
        "system/config_edit.html",
        title="System - Application Configuration",
        db_host=config_data["database"]["host"],
        db_user=config_data["database"]["user"],
        db_password=config_data["database"]["password"],
        db_name=config_data["database"]["name"],
        db_port=config_data["database"]["port"],
        ca_url=config_data["ca"]["url"],
        ca_root=config_data["ca"]["root"],
        ca_intermediate=config_data["ca"]["intermediate"],
        ca_fingerprint=config_data["ca"]["fingerprint"],
        ca_admin_provisioner_name=config_data["ca"]["admin_provisioner_name"],
        ca_config=config_data["ca"]["config"],
        auth_backend=config_data["auth"]["backend"]
    )


@bp.route("/service/<action>", methods=["POST"])
def step_ca_web_service_action(action):
    if action not in ["start", "stop", "restart", "status"]:
        return jsonify({"error": "Invalid action"}), 400

    try:
        output = subprocess.check_output(["sudo", "/usr/bin/systemctl", "--no-pager", "--lines=25", "-l", action, "step-ca-web.service"], stderr=subprocess.STDOUT)
        return jsonify({"success": True, "output": output.decode()})
    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "error": e.output.decode()}), 500


@bp.route("/service")
def step_ca_web_service():
    return render_template("system/service.html", title="System - App Service Control", ca_url=CA_URL)