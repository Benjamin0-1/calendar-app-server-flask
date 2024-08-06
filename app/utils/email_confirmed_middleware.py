from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from app.models import User


def check_email_confirmed():
    print(f"Request endpoint: {request.endpoint}")  
    exempt_routes = [
        'auth.login', 'auth.signup', 'auth.confirm_email',
        'auth.request_password_reset', 'auth.reset_password',
    ]

    if request.endpoint in exempt_routes:
        print("Exempt route accessed.") 
        return None  # Continue with the request

    verify_jwt_in_request(optional=True)
    current_user = get_jwt_identity()
    print(f"Current user: {current_user}") 

    if current_user:
        user = User.query.filter_by(email=current_user).first()
        if user and not user.email_confirmed:
            print("Email not confirmed.")  
            return jsonify({"error": "Email not confirmed"}), 403

    return None  # let it continue with the request

'''
# as a decorator.
def check_email_confirmed(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        exempt_routes = [
            'auth.login', 'auth.signup', 'auth.confirm_email',
            'auth.request_password_reset', 'auth.reset_password'
        ]

        if request.endpoint in exempt_routes:
            return f(*args, **kwargs)

        verify_jwt_in_request(optional=True)
        current_user = get_jwt_identity()

        if current_user:
            user = User.query.filter_by(email=current_user).first()
            if user and not user.email_confirmed:
                return jsonify({"error": "Email not confirmed"}), 403

        return f(*args, **kwargs)
    
    return decorated_function

    
    '''