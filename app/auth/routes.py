from flask import request, jsonify, Blueprint
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app import db
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
import re

from . import auth

# add brute force protection HERE
# and re implement email-confirm.

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
    
   
    new_user = User(first_name=first_name, last_name=last_name, email=email)
    new_user.set_password(password)
    # wrap in try except.
    db.session.add(new_user)
    db.session.commit()

    return jsonify("User created successfully"), 201

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