from flask import Blueprint
from app.middleware.email_confirmed import check_email_confirmed

bookings = Blueprint('bookings', __name__)

@bookings.before_request
def before_request():
    response = check_email_confirmed()
    if response:
        return response

from . import routes
