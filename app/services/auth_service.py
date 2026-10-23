import os
import random
from datetime import datetime, timedelta

from firebase_admin import auth as firebase_auth
from flask_jwt_extended import create_access_token, create_refresh_token, decode_token

from app import config
from app.errors import APIError, error, error_text, respond_on_failure
from app.extensions import db
from app.models import LoginHistory, Provider, User
from app.services.email_service import send_template_email
from app.services.login_attempts import failed_login_attempts


def _token_claims(user):
    return {
        'id': user.id,
        'first_name': user.first_name,
        'email': user.email,
    }


def _reject_third_party_user(user):
    if user.provider:
        raise error("User registered with a third-party provider", 403)


# ---- signup & login ----

def signup(first_name, last_name, email, password):
    if User.query.filter_by(email=email).first():
        raise APIError({"userAlreadyExists": True}, 400)

    with respond_on_failure(error_text):
        new_user = User(first_name=first_name, last_name=last_name, email=email)
        new_user.set_password(password)
        new_user.generate_email_confirm_uuid()
        db.session.add(new_user)
        db.session.commit()

    with respond_on_failure(lambda e: {"message": "User created but failed to send email."}):
        send_template_email(
            'Welcome to Our Service', new_user.email, 'welcome.html',
            first_name=new_user.first_name,
            confirm_email_link=f'{config.EMAIL_CONFIRM_URL}?uuid={new_user.email_confirm_uuid}',
        )


def login(email, password, ip_address, user_agent):
    user = User.query.filter_by(email=email).first()
    if not user:
        raise APIError({"userNotFound": True}, 404)
    # this won't allow third party users to login locally.
    if user.provider:
        raise error("user registered with a third party provider", 403)

    remaining_lockout_time = failed_login_attempts.remaining_lockout(email)
    if remaining_lockout_time:
        raise APIError({"lockedOut": True, "remainingLockoutTime": remaining_lockout_time}, 403)

    if not user.check_password(password):
        failed_login_attempts.record_failure(email)
        raise APIError({"invalidCredentials": True}, 401)

    failed_login_attempts.reset(email)
    claims = _token_claims(user)
    tokens = {
        'access_token': create_access_token(identity=email, additional_claims=claims),
        'refresh_token': create_refresh_token(identity=email, additional_claims=claims),
        'refresh_token_expires_in': os.environ.get('JWT_REFRESH_TOKEN_EXPIRES'),
        'access_token_expires_in': os.environ.get('JWT_ACCESS_TOKEN_EXPIRES'),
    }

    db.session.add(LoginHistory(login_time=datetime.utcnow(), ip_address=ip_address, user_agent=user_agent, user_id=user.id))
    db.session.commit()

    # warn the user about logins from an ip address they haven't used before.
    # note: this runs after the current login was recorded, so it always finds a previous login.
    has_logged_in_before = LoginHistory.query.filter_by(user_id=user.id, ip_address=ip_address).first()
    if not has_logged_in_before:
        send_template_email('New Login Detected', user.email, 'new_login.html',
                            first_name=user.first_name, ip_address=ip_address)

    return tokens


def refresh_access_token(refresh_token):
    with respond_on_failure(error_text):
        decoded_token = decode_token(refresh_token)
        user = User.query.filter_by(email=decoded_token.get('sub')).first()
        if not user:
            raise error("User not found", 404)

        access_token = create_access_token(identity=user.email, additional_claims=_token_claims(user))
        return {'access_token': access_token, 'expires_in': os.environ.get('JWT_ACCESS_TOKEN_EXPIRES')}


# ---- google ----

def _google_tokens(user):
    access_token_expires_in = os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 15)
    refresh_token_expires_in = os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', 30)
    claims = _token_claims(user)
    return {
        'access_token': create_access_token(identity=user.email, additional_claims=claims,
                                            expires_delta=timedelta(minutes=int(access_token_expires_in))),
        'refresh_token': create_refresh_token(identity=user.email, additional_claims=claims,
                                              expires_delta=timedelta(days=int(refresh_token_expires_in))),
        'access_token_expires_in': int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 60)),
        'refresh_token_expires_in': int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', 15)),
    }


def _get_or_create_provider(provider_name, provider_uuid):
    provider = Provider.query.filter_by(provider_name=provider_name, provider_uuid=provider_uuid).first()
    if not provider:
        provider = Provider(provider_name=provider_name, provider_uuid=provider_uuid)
        db.session.add(provider)
        db.session.commit()
    return provider


def google_login(google_token, email, google_user_id):
    with respond_on_failure(error_text):
        decoded_token = firebase_auth.verify_id_token(google_token)
        if email != decoded_token.get('email') or google_user_id != decoded_token.get('uid'):
            raise error("Token and provided data do not match", 400)

        user = User.query.filter_by(email=email).first()
        if user:
            if user.provider and user.provider.provider_name == 'google':
                return _google_tokens(user)
            raise error("User registered with a different provider, cannot log in with Google", 403)

        provider = _get_or_create_provider('google', google_user_id)
        new_user = User(
            first_name=decoded_token.get('given_name', ''),
            last_name=decoded_token.get('family_name', ''),
            email=email,
            provider_id=provider.id,
        )
        new_user.set_password(str(random.randint(100000, 999999)))  # third-party users never log in with it.
        db.session.add(new_user)
        db.session.commit()

        send_template_email('Welcome to Our Service', new_user.email, 'google_welcome.html', first_name=new_user.first_name)
        return _google_tokens(new_user)


# ---- email confirmation ----

def confirm_email(uuid):
    user = User.query.filter_by(email_confirm_uuid=uuid).first()
    if not user:
        raise error("Invalid or expired confirmation link", 400)
    _reject_third_party_user(user)
    if user.email_confirm_expiration < datetime.utcnow():
        raise error("Confirmation link has expired", 400)

    with respond_on_failure(error_text):
        user.email_confirmed = True
        user.email_confirm_uuid = None
        user.email_confirm_expiration = None
        db.session.commit()


def resend_email_confirmation(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        raise error("User not found", 404)
    if user.email_confirmed:
        raise error("Email already confirmed", 400)
    _reject_third_party_user(user)

    # note: generate_email_confirm_uuid() returns None, so the link carries uuid=None.
    new_uuid = user.generate_email_confirm_uuid()
    send_template_email('Confirm your email', user.email, 'confirm_email_reminder.html',
                        first_name=user.first_name,
                        confirm_email_link=f'{config.EMAIL_CONFIRM_URL}?uuid={new_uuid}')
    db.session.commit()


# ---- password reset ----

def request_password_reset(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        raise error("User not found", 404)
    _reject_third_party_user(user)

    with respond_on_failure(error_text):
        otp_code = str(random.randint(100000, 999999))
        user.otp = otp_code
        user.otp_expiration = datetime.utcnow() + timedelta(minutes=10)
        db.session.commit()

        # the frontend page reads the email and otp from the url and posts them back with the new password.
        reset_link = f'{os.environ.get("FRONTEND_URL")}/reset-password?email={email}&otp={otp_code}'
        send_template_email('Your OTP for Password Reset', email, 'password_reset.html',
                            otp_code=otp_code, reset_link=reset_link)


def reset_password(email, otp_code, new_password):
    user = User.query.filter_by(email=email).first()
    if not user:
        raise error("No user with such email was found", 404)
    _reject_third_party_user(user)
    if not user.otp:
        raise error("User OTP is missing", 500)
    if otp_code != user.otp or datetime.utcnow() >= user.otp_expiration:
        raise error("Invalid OTP or it has expired", 403)

    with respond_on_failure(error_text):
        user.set_password(new_password)
        user.otp = None
        user.otp_expiration = None
        db.session.commit()
