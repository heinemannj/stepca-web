from flask import Blueprint

bp = Blueprint('step', __name__, url_prefix='/step')
api_bp = Blueprint('step_api', __name__, url_prefix='/api/step')

from app.blueprint.step import routes, api

