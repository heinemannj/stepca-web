#!/usr/bin/env bash

CONF_PATH="/etc/stepca-web"
SETTINGS="${CONF_PATH}/settings.json"

echo "Change password for 'StepCA Web Admin' user 'admin'"
HASH=$(uv run python -c "from werkzeug.security import generate_password_hash; import getpass; print(generate_password_hash(getpass.getpass('New Password: ')))")
jq --arg a "$HASH" '.local.users.admin.password_hash = $a' "${SETTINGS}" > "${SETTINGS}_tmp" && mv "${SETTINGS}_tmp" "${SETTINGS}"
