from flask import Blueprint
from app.utils.email_confirmed_middleware import check_email_confirmed

auth = Blueprint('auth', __name__)

@auth.before_request
def before_request():
    response = check_email_confirmed()
    if response:
        return response

# Import routes so they are registered with the blueprint
from . import routes
