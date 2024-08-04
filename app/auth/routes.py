from flask import request, jsonify, Blueprint
from app import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User, LoginHistory
from app import db
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, verify_jwt_in_request, decode_token, JWTManager, get_jwt,
    exceptions
)
import re
import random
import pyotp
import os
from datetime import datetime, timedelta
from functools import wraps
from . import auth
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from ..utils.get_user_id import get_user_id  # from app/utils.
from ..services.email_service import send_email # from app/services.
import app # new line to support /refresh-token


# add brute force protection HERE
# and re implement email-confirm.

# don't use in-memory storage.
#limiter = Limiter(key_func=get_remote_address)

# NOT WORKING.

limiter = Limiter(key_func=get_remote_address)
# Example route to test rate limiter
@auth.route('/test-limiter', methods=['GET'])
@limiter.limit('2 per minute')
def test_limiter():
    return jsonify({"message": "This is a test."}), 200


# Track failed login attempts
failed_login_attempts = {}

# Define the maximum number of allowed failed attempts
MAX_FAILED_ATTEMPTS = 5

# Define the lockout period in seconds
LOCKOUT_PERIOD = 300 # 5 minutes

# this is a temporary solution, it will be changed in the future.
@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({"missingData": True}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({"userNotFound": True}), 404
    
    # Check if the user is locked out due to too many failed attempts
    if email in failed_login_attempts:
        attempts_info = failed_login_attempts[email]
        if attempts_info['attempts'] >= MAX_FAILED_ATTEMPTS:
            lockout_time = attempts_info['lockout_time']
            remaining_lockout_time = (lockout_time - datetime.now()).total_seconds()
            if remaining_lockout_time > 0:
                return jsonify({"lockedOut": True, "remainingLockoutTime": remaining_lockout_time}), 403
    
    if user and user.check_password(password):
        additional_claims = {
            'id': user.id,  
            'first_name': user.first_name,
            'email': user.email,
        }
        access_token = create_access_token(identity=email, additional_claims=additional_claims)
        refresh_token = create_refresh_token(identity=email, additional_claims=additional_claims)
        
        # Reset failed login attempts for the user
        if email in failed_login_attempts:
            del failed_login_attempts[email]

        # Add it to the login history, if successful login.
        login_record = LoginHistory(
            login_time=datetime.utcnow(),
            ip_address=request.remote_addr,
            user_agent = request.headers.get('User-Agent'),
            user_id=user.id
        )
        db.session.add(login_record)
        db.session.commit()


        # check if the user has previusly logged in from this ip address.
        # in the future, this wil also use a geolocation API to check the location of the user.
        # and the user agent.
        # right now it will only check the ip address.
        has_logged_in_before = LoginHistory.query.filter_by(user_id=user.id, ip_address=request.remote_addr).first()
        has_logged_in_from_user_agent = LoginHistory.query.filter_by(user_id=user.id, user_agent=request.headers.get('User-Agent')).first() # unsuded for now.

        #if not has_logged_in_from_user_agent or not has_logged_in_before: # <- can also do it this way.
        if not has_logged_in_before:
            send_email(
                subject='New Login Detected',
                recipient=user.email,
                body=f'''
                    <html>
                    <head>
                        <style>
                            body {{
                                font-family: Arial, sans-serif;
                                color: #333;
                                background-color: #f4f4f4;
                                margin: 0;
                                padding: 0;
                            }}
                            .container {{
                                max-width: 600px;
                                margin: 0 auto;
                                padding: 20px;
                                background-color: #fff;
                                border-radius: 8px;
                                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                            }}
                            h1 {{
                                color: #4CAF50;
                            }}
                            p {{
                                line-height: 1.6;
                            }}
                            .button {{
                                display: inline-block;
                                padding: 10px 20px;
                                font-size: 16px;
                                color: #fff;
                                background-color: #4CAF50;
                                text-decoration: none;
                                border-radius: 5px;
                                margin-top: 20px;
                            }}
                            .footer {{
                                margin-top: 20px;
                                font-size: 12px;
                                color: #777;
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h1>New Login Detected</h1>
                            <p>Hello {user.first_name},</p>
                            <p>A new login was detected from IP address {request.remote_addr}. If this was not you, please contact support immediately.</p>
                        </div>
                    </body>
                    </html>
                '''
            ) 
            print("Email sent to user for new login.")

        return jsonify(access_token=access_token, refresh_token=refresh_token), 200

    # Otherwise, Increment failed login attempts for the user
    if email in failed_login_attempts:
        failed_login_attempts[email]['attempts'] += 1
    else:
        failed_login_attempts[email] = {'attempts': 1, 'lockout_time': None} # if first failed attempt
    
    # Check if the user has reached the maximum number of failed attempts
    if failed_login_attempts[email]['attempts'] >= MAX_FAILED_ATTEMPTS: # if exceeded max attempts
        failed_login_attempts[email]['lockout_time'] = datetime.now() + timedelta(seconds=LOCKOUT_PERIOD) # then lockout the user

# I can add a is_attempt field to the model,to..
    # record a failed login attempt.
  #  login_record = LoginHistory(
  #      login_time=datetime.utcnow(),
  #      ip_address=request.remote_addr,
  #      user_agent=request.headers.get('User-Agent'),
  #      user_id=user.id if user else None # this is marked as required in the LoginHistory model.
  #  )
  #  db.session.add(login_record)
  #  db.session.commit()
    
    return jsonify({"invalidCredentials": True}), 401 # if invalid credentials, before being locked out.


# verify the new signup route.
@auth.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')

    if not all([first_name, last_name, email, password]):
        return jsonify({"missingData": True}), 400

    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, email):
        return jsonify({"invalidEmail": True}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"userAlreadyExists": True}), 400
    

    try:
        
        new_user = User(first_name=first_name, last_name=last_name, email=email)
        new_user.set_password(password)
        new_user.generate_email_confirm_uuid() # generate the email confirmation uuid.
        confirm_email_link = f'http://127.0.0.1:5000/auth/confirm-email?uuid={new_user.email_confirm_uuid}' # verify the link.
        db.session.add(new_user)
        db.session.commit() 

    except Exception as e:
        db.session.rollback()  
        return jsonify({"error": str(e)}), 500

    try:
        send_email(
            subject='Welcome to Our Service',
            recipient=new_user.email,
            body=f'''
                <html>
                <head>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            color: #333;
                            background-color: #f4f4f4;
                            margin: 0;
                            padding: 0;
                        }}
                        .container {{
                            max-width: 600px;
                            margin: 0 auto;
                            padding: 20px;
                            background-color: #fff;
                            border-radius: 8px;
                            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                        }}
                        h1 {{
                            color: #4CAF50;
                        }}
                        p {{
                            line-height: 1.6;
                        }}
                        .button {{
                            display: inline-block;
                            padding: 10px 20px;
                            font-size: 16px;
                            color: #fff;
                            background-color: #4CAF50;
                            text-decoration: none;
                            border-radius: 5px;
                            margin-top: 20px;
                        }}
                        .footer {{
                            margin-top: 20px;
                            font-size: 12px;
                            color: #777;
                        }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>Welcome to Our Service, {new_user.first_name}!</h1>
                        <p>We are excited to have you on board. Please confirm your email address by clicking the link below:</p>
                        <a href="{confirm_email_link}" class="button">Confirm Email</a>
                        <p>This link will expire in 24 hours.</p>
                        <p class="footer">If you have any questions, feel free to reach out to our support team.</p>
                    </div>
                </body>
                </html>
            '''
        )

        return jsonify("User created successfully"), 201

    except Exception as e:
        return jsonify({"message": "User created but failed to send email."}), 500



# Manually decoding the refresh token.
@auth.route('/refresh-token', methods=['POST'])
def refresh_token():
    data = request.get_json()
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        return jsonify({"error": "Refresh token is missing"}), 400

    try:
        # Verify the refresh token
        verify_jwt_in_request(refresh_token)

        # Decode the refresh token to get user information
        decoded_token = decode_token(refresh_token)
        current_user_email = decoded_token.get('sub')  # 'sub' is used for email

        # Retrieve the user from the database
        user = User.query.filter_by(email=current_user_email).first()

        if not user:
            return jsonify({"error": "User not found"}), 404

        # Create a new access token
        additional_claims = {
            'id': user.id,
            'first_name': user.first_name,
            'email': user.email,
        }
        access_token = create_access_token(identity=user.email, additional_claims=additional_claims)

        # Return the new access token and its expiration time
        #expires_in = app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()
        return jsonify(access_token=access_token), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


    



@auth.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    try:
        # Generate a unique OTP secret for the user
        otp_secret_base32 = pyotp.random_base32() 
        user.otp_secret = otp_secret_base32
        
        print(f"OTP SECRET: {otp_secret_base32}")  # Debug: Print the secret to verify it's correct
        
        otp = pyotp.TOTP(otp_secret_base32)
        otp_code = otp.now()
        
        print(f"Generated OTP Code: {otp_code}")  # Debug: Print the generated OTP
        
        # Assign OTP and expiration to the user
        user.otp = otp_code
        user.otp_expiration = datetime.utcnow() + timedelta(minutes=10)
        db.session.commit()

        send_email(
            subject='Your OTP for Password Reset',
            recipient=email,
            body=f'Your OTP is {otp_code}. It expires in 10 minutes. Use this OTP to reset your password.'
        )

        return jsonify({"message": "OTP sent successfully. Please check your email."}), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error: {e}")  # Detailed logging of the error
        return jsonify({"error": str(e)}), 500






@auth.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    otp_code = data.get('otp')
    new_password = data.get('new_password')
    confirm_new_password = data.get('confirm_new_password')

    if not email or not otp_code or not new_password or not confirm_new_password:
        return jsonify({"error": "Missing required data"}), 400

    if new_password != confirm_new_password:
        return jsonify({"error": "Passwords don't match"}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"error": "No user with such email was found"}), 404

    if not user.otp_secret:
        return jsonify({"error": "User OTP secret is missing"}), 500

    otp = pyotp.TOTP(user.otp_secret)
    if otp_code == user.otp and datetime.utcnow() < user.otp_expiration:
        try:
            # Update the user password
            user.set_password(new_password)  # Call the set_password method
            print(f"NEW USER PASSWORD HASH: {user.password_hash}")
            # and then CLEAN UP.
            user.otp = None  
            user.otp_expiration = None  
            user.otp_secret = None  # Optionally clear the OTP secret if it's no longer needed
            db.session.commit()

            return jsonify({"message": "Password reset successfully"}), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500
    else:
        return jsonify({"error": "Invalid OTP or it has expired"}), 403


@auth.route('/user-profile')
@jwt_required()
def view_user_profile():

    current_user_id = get_user_id()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify(user.serialize()), 200 


@auth.route('/update-profile', methods=['PATCH'])
@jwt_required()
def update_profile():
    data = request.get_json()
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    
    if not first_name and not last_name:
        return jsonify({"error": "At least one parameter to be updated is required"}), 400
    
    current_user_id = get_user_id()  
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    try:
        updated = False
        
        if first_name and first_name != user.first_name:
            user.first_name = first_name
            updated = True
            
        if last_name and last_name != user.last_name:
            user.last_name = last_name
            updated = True
            
        if updated:
            db.session.commit()
            return jsonify({"message": "Profile updated successfully"}), 200
        else:
            return jsonify({"message": "No changes detected"}), 400
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500




@auth.route('/update-password', methods=['PUT'])
@jwt_required()
def update_password():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_new_password = data.get('confirm_new_password')

    # All fields are required.
    if not current_password or not new_password or not confirm_new_password:
        return jsonify({"error": "All fields are required"}), 400
    
    current_user_id = get_user_id()
    user = User.query.get_or_404(current_user_id) 

    # Check if the current password is correct.
    if not user.check_password(current_password):
        return jsonify({"error": "Current password is incorrect"}), 403
    
    # Check if the new passwords match.
    if new_password != confirm_new_password:
        return jsonify({"error": "New passwords don't match"}), 400
    
    # Check if the new password is different from the current password.
    if user.check_password(new_password):
        return jsonify({"error": "New password cannot be the same as the current password"}), 400
    
    try:
        user.set_password(new_password)
        db.session.commit()

        return jsonify({"message": "Password updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# route to confirm the email, it doesn't require authentication.
# it will check if the uuid is valid and if it's not expired.
# and it's via query string.
# so it's a GET method, this will make it easier for the user to confirm their email, they will only need to click on a link.
@auth.route('/confirm-email', methods=['GET'])
def confirm_email():
    uuid = request.args.get('uuid') # retrieve the uuid from the query string.
    user = User.query.filter_by(email_confirm_uuid=uuid).first() # find the user the uuid belongs to.
    # this filters directly by the uuid, meaning we don't need to check for the email existence.

    if not user:
        return jsonify({"error": "Invalid or expired confirmation link"}), 400

    
    if user.email_confirm_expiration < datetime.utcnow(): # check if the link has expired.
        return jsonify({"error": "Confirmation link has expired"}), 400

    try:
        user.email_confirmed = True
        user.email_confirm_uuid = None
        user.email_confirm_expiration = None
        db.session.commit()
        return jsonify({"message": "Email confirmed successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    

# new route to see login history.
@auth.route('/login-history')
@jwt_required()
def login_history():
    current_user_id = get_user_id()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    login_records = LoginHistory.query.filter_by(user_id=current_user_id).all()
    return jsonify([record.serialize() for record in login_records]), 200

'''
# This will be replaced for a much better implementation of the same thing.
# The user will now only need to click on a link to confirm their email, instead of entering an OTP.
# and I will have a route which will decode it and then verify the email and its expiration.
# TEST THIS ROUTE <= AND SEE IF IT'S WELL THOUGHT OUT.
@auth.route('/confirm-email', methods=['POST'])
def confirm_email():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    user = User.query.filter_by(email=email).first()

    if not user or user.email_otp != otp or user.email_otp_expiration < datetime.utcnow():
        return jsonify({"error": "Invalid or expired OTP"}), 400

    # Check if another user has already confirmed the email
    confirmed_user = User.query.filter_by(email=email, email_confirmed=True).first()
    if confirmed_user and confirmed_user.id != user.id:
        return jsonify({"error": "This email is already confirmed by another user."}), 400

    # Confirm the email for the current user
    try:
        user.email_confirmed = True
        user.email_otp = None
        user.email_otp_expiration = None
        db.session.commit()
        return jsonify({"message": "Email confirmed successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

'''


'''
# Middleware to check if email is confirmed
@app.before_request
def check_email_confirmed():
    if request.endpoint in ['login', 'signup', 'confirm_email', 'request_password_reset', 'reset_password']:  # allow these endpoints
        return
    
    verify_jwt_in_request(optional=True)
    current_user = get_jwt_identity()

    if current_user:
        user = User.query.filter_by(email=current_user).first()
        if user and not user.email_confirmed:
            return jsonify({"error": "Email not confirmed"}), 403


    

            # NEW SIGNUP ROUTE: 
    @auth.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')

    if not all([first_name, last_name, email, password]):
        return jsonify({"missingData": True}), 400

    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, email):
        return jsonify({"invalidEmail": True}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"userAlreadyExists": True}), 400

    try:
        new_user = User(first_name=first_name, last_name=last_name, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        otp = pyotp.TOTP(os.environ.get('OTP_SECRET'))
        otp_code = otp.now()
        new_user.otp = otp_code
        new_user.otp_expiration = datetime.utcnow() + timedelta(minutes=10)
        db.session.commit()

        send_email(
            subject='Confirm your email',
            recipient=new_user.email,
            body=f'Hello {new_user.first_name},\n\nPlease confirm your email using this OTP: {otp_code}. It expires in 10 minutes.'
        )

        return jsonify({"message": "User created successfully. Please check your email to confirm your account."}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@auth.route('/confirm-email', methods=['POST'])
def confirm_email():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    user = User.query.filter_by(email=email).first()

    if not user or user.otp != otp or user.otp_expiration < datetime.utcnow():
        return jsonify({"error": "Invalid or expired OTP"}), 400

    user.email_confirmed = True
    user.otp = None
    user.otp_expiration = None
    db.session.commit()

    return jsonify({"message": "Email confirmed successfully"}), 200


from flask import request
from flask_mail import Mail, Message
from geopy.geocoders import Nominatim
import re

mail = Mail()

def calculate_risk_score(user, current_ip, user_agent, current_location):
    risk_score = 0
    
    # Check if IP is new
    recent_logins = LoginHistory.query.filter_by(user_id=user.id).all()
    ip_found = any(record.ip_address == current_ip for record in recent_logins)
    
    if not ip_found:
        risk_score += 10

    # Check geographic location
    geolocator = Nominatim(user_agent="geoapiExercises")
    location = geolocator.geocode(current_ip)
    if location and location != current_location:
        risk_score += 15

    # Check user-agent
    recent_agents = [record.user_agent for record in recent_logins if record.user_agent]
    if user_agent not in recent_agents:
        risk_score += 5

    return risk_score

def login_user(email, password):
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        current_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        current_location = request.remote_addr # This should be more precise in a real scenario

        risk_score = calculate_risk_score(user, current_ip, user_agent, current_location)
        
        if risk_score > 20:
            send_notification_email(user, current_ip, risk_score)
            return "Suspicious activity detected. Please check your email."
        else:
            # Proceed with login
            return "Login successful"
    return "Invalid credentials"

def send_notification_email(user, current_ip, risk_score):
    subject = 'Suspicious Login Alert'
    body = (f'Hello {user.first_name},\n\n'
            f'A login was detected with a risk score of {risk_score} from IP address ({current_ip}). '
            'If this was not you, please contact support immediately.')
    
    msg = Message(subject=subject, recipients=[user.email], body=body)
    mail.send(msg)

'''

