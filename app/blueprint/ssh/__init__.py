from flask import Blueprint

bp = Blueprint('ssh', __name__, url_prefix='/ssh')
api_bp = Blueprint('ssh_api', __name__, url_prefix='/api/ssh')


from app.blueprint.ssh import routes, api
