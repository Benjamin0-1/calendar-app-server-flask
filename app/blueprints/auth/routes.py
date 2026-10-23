import os

from flask import jsonify, redirect, request
from flask_jwt_extended import jwt_required, verify_jwt_in_request

from . import auth # blueprint
from app.errors import error_text, respond_on_failure
from app.schemas.auth import (
    GoogleLoginSchema, LoginSchema, PasswordResetRequestSchema, PasswordResetSchema, PasswordUpdateSchema,
    ProfileUpdateSchema, RefreshTokenSchema, ResendConfirmationSchema, SignupSchema,
)
from app.schemas.base import load_json
from app.services import account_service, auth_service
from app.utils.get_user_id import get_user_id


# ---- signup & login ----

@auth.route('/signup', methods=['POST'])
def signup():
    auth_service.signup(**load_json(SignupSchema))
    return jsonify("User created successfully"), 201


@auth.route('/login', methods=['POST'])
def login():
    data = load_json(LoginSchema)
    tokens = auth_service.login(data['email'], data['password'],
                                ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent'))
    return jsonify(tokens), 200


@auth.route('/access-token', methods=['POST'])
def refresh_token():
    data = load_json(RefreshTokenSchema)
    # an Authorization header, when sent, must still hold a valid token.
    with respond_on_failure(error_text):
        verify_jwt_in_request(optional=True)
    return jsonify(auth_service.refresh_access_token(data['refresh_token'])), 200


@auth.route('/google-login', methods=['POST'])
def handle_google_login():
    data = load_json(GoogleLoginSchema)
    return jsonify(auth_service.google_login(data['google_token'], data['email'], data['user_id'])), 200


# ---- email confirmation ----

# the link in the confirmation email points here, so it's a GET with the uuid in the query string.
@auth.route('/confirm-email', methods=['GET'])
def confirm_email():
    auth_service.confirm_email(request.args.get('uuid'))
    return redirect(f"{os.environ.get('FRONTEND_URL')}/email-confirmed")


@auth.route('/resend-email-confirmation', methods=['POST'])
def resend_email_confirmation():
    auth_service.resend_email_confirmation(load_json(ResendConfirmationSchema)['email'])
    return jsonify({"message": "Confirmation link sent successfully"}), 200


# ---- password reset ----

# emails a link to the frontend carrying the email and otp; the frontend then posts them to /reset-password.
@auth.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    auth_service.request_password_reset(load_json(PasswordResetRequestSchema)['email'])
    return jsonify({"message": "OTP sent successfully. Please check your email."}), 200


@auth.route('/reset-password', methods=['POST'])
def reset_password():
    data = load_json(PasswordResetSchema)
    auth_service.reset_password(data['email'], data['otp'], data['new_password'])
    return jsonify({"message": "Password reset successfully"}), 200


# ---- account ----

@auth.route('/user-profile', methods=['GET'])
@jwt_required()
def view_user_profile():
    return jsonify(account_service.get_profile(get_user_id())), 200


@auth.route('/update-profile', methods=['PATCH'])
@jwt_required()
def update_profile():
    account_service.update_profile(get_user_id(), **load_json(ProfileUpdateSchema))
    return jsonify({"message": "Profile updated successfully"}), 200


@auth.route('/update-password', methods=['PUT'])
@jwt_required()
def update_password():
    account_service.update_password(get_user_id(), **load_json(PasswordUpdateSchema))
    return jsonify({"message": "Password updated successfully"}), 200


@auth.route('/login-history')
@jwt_required()
def login_history():
    return jsonify(account_service.login_history(get_user_id())), 200
