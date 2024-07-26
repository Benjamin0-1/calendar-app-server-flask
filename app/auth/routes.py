from flask import request, jsonify, Blueprint
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app import db
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
import re
import random
import pyotp
import os
from datetime import datetime, timedelta
from . import auth
from ..utils.get_user_id import get_user_id  # from app/utils.
from ..services.email_service import send_email # from app/services.


# add brute force protection HERE
# and re implement email-confirm.
# add password reset.
# for now : <- I will add a get email route to test its functionality.


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
    
    if user and user.check_password(password):
   
        additional_claims = {
            'id': user.id,  
            'first_name': user.first_name,
            'email': user.email,
        }
        access_token = create_access_token(identity=email, additional_claims=additional_claims)
        refresh_token = create_refresh_token(identity=email, additional_claims=additional_claims)
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200

    return jsonify({"invalidCredentials": True}), 401

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

    except Exception as e:
        db.session.rollback()  
        return jsonify({"error": str(e)}), 500

    try:
        send_email(
            subject='Welcome to Our Service',
            recipient=new_user.email,
            body=f'Hello {new_user.first_name} {new_user.last_name},\n\nWelcome to our service! We are glad to have you.'
        )

        return jsonify("User created successfully"), 201

    except Exception as e:
        return jsonify({"message": "User created but failed to send email."}), 500


@auth.route('/refresh-token', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user).first()

    if not user:
        return jsonify({"userNotFound": True}), 404

    additional_claims = {
        'id': user.id,
        'first_name': user.first_name,
        'email': user.email,
    }
    access_token = create_access_token(identity=current_user, additional_claims=additional_claims)
    return jsonify(access_token=access_token)


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
        otp = pyotp.TOTP(os.environ.get('OTP_SECRET'))
        otp_code = otp.now()
        
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

    otp = pyotp.TOTP(os.environ.get('OTP_SECRET'))
    if otp_code == user.otp and datetime.utcnow() < user.otp_expiration:
        try:
            # Update the user password
            user.password = generate_password_hash(new_password)  
            user.otp = None  
            user.otp_expiration = None  
            db.session.commit()

            return jsonify({"message": "Password reset successfully"}), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500
    else:
        return jsonify({"error": "Invalid OTP or it has expired"}), 403



'''
# Middleware to check if email is confirmed
@app.before_request
def check_email_confirmed():
    if request.endpoint in ['login', 'signup', 'confirm_email']:  # allow these endpoints
        return
    
    verify_jwt_in_request(optional=True)
    current_user = get_jwt_identity()

    if current_user:
        user = User.query.filter_by(email=current_user).first()
        if user and not user.email_confirmed:
            return jsonify({"error": "Email not confirmed"}), 403

def expire_otps():
    with app.app_context():
        now = datetime.utcnow()
        expired_users = User.query.filter(User.otp_expiration < now).all()
        for user in expired_users:
            user.otp = None
            user.otp_expiration = None
        db.session.commit()  # commit once to improve efficiency

scheduler = BackgroundScheduler()
scheduler.add_job(func=expire_otps, trigger='interval', minutes=1)
scheduler.start()

# Confirm email route
@app.route('/confirm-email', methods=['POST'])
def confirm_email():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    user = User.query.filter_by(email=email).first()

    if not user or user.otp != otp or user.otp_expiration < datetime.utcnow():
        return jsonify({"error": "Invalid or expired OTP"}), 400

    existing_user = User.query.filter_by(email=email, email_confirmed=True).first()
    if existing_user:
        db.session.delete(user)
        db.session.commit()
        existing_user.email_confirmed = True
        existing_user.otp = None
        existing_user.otp_expiration = None
        db.session.commit()
        return jsonify({"success": "Email confirmed successfully and associated with the existing user"}), 200

    user.email_confirmed = True
    user.otp = None
    user.otp_expiration = None
    db.session.commit()



'''