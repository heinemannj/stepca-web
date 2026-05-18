from flask import render_template, flash, redirect, make_response, url_for, request

from app.libs.db_ssh import *

from config import CA_URL
from app.auth.decorator import login_required

