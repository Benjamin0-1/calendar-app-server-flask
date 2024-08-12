from .. import db
from werkzeug.security import generate_password_hash, check_password_hash # check venv/lib/python3.8/site-packages/werkzeug/security.py
from datetime import datetime, timedelta
import pyotp
import os
from sqlalchemy import UniqueConstraint, CheckConstraint
from uuid import uuid4 # for generating the email_confirm_uuid.


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False, info={'check': 'email ~* \'^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$\''})
    password_hash = db.Column(db.String(250), nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(6), nullable=True)
    recovery_otp_expiration = db.Column(db.DateTime, nullable=True)  # Expiration for OTP used for email confirmation
    otp_secret = db.Column(db.String(32), nullable=True)  # Must be base32 encoded, this is for password recovery.
    email_confirm_uuid = db.Column(db.String(36), default=str(uuid4()), nullable=True)
    email_confirm_expiration = db.Column(db.DateTime, nullable=True)

    # Relationships
    properties = db.relationship('Property', back_populates='owner')
    booked_dates = db.relationship('BookedDate', back_populates='user')
    login_history = db.relationship('LoginHistory', back_populates='user', lazy='dynamic')
    # provider
    provider_id = db.Column(db.Integer, db.ForeignKey('provider.id')) # references Provider
    provider = db.relationship('Provider', back_populates='users', uselist=False)

    def set_password(self, password):
        """Hash the password and set it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if the provided password matches the hashed password."""
        return check_password_hash(self.password_hash, password)

    def set_otp(self, otp):
        """Set the OTP and its expiration time."""
        self.otp = otp
        self.recovery_otp_expiration = datetime.utcnow() + timedelta(minutes=10)

    def generate_otp(self):
        """Generate a new OTP if the secret is not set, create one, and return it."""
        if not self.otp_secret:
            self.otp_secret = pyotp.random_base32()
        otp = pyotp.TOTP(self.otp_secret)
        return otp.now()

    def generate_email_confirm_uuid(self):
        """Generate a new UUID for email confirmation and set expiration time."""
        if not self.email_confirm_uuid or self.email_confirm_expiration < datetime.utcnow():
            self.email_confirm_uuid = str(uuid4())
            self.email_confirm_expiration = datetime.utcnow() + timedelta(hours=24)

    def serialize(self):
        """Serialize user information for easy JSON output."""
        properties = [prop.serialize() for prop in self.properties]
        booked_dates = [date.serialize() for date in self.booked_dates]
        return {
            'firstName': self.first_name,
            'lastName': self.last_name,
            'email': self.email,
            'properties': properties,
            'bookedDates': booked_dates,
            'isThirdPartyUser': True if self.provider else False  # Indicates if the user has a third-party provider record.
        }

    def resend_email_confirmation(self):
        """Send an email confirmation if the email is not yet confirmed and the UUID is set."""
        if not self.email_confirmed and self.email_confirm_uuid and self.email_confirm_expiration > datetime.utcnow():
            # Logic to send the confirmation email
            pass



    # this could be used GET /bookings, or create another serializer for the bookings, which would be more efficient.
    def serialize(self):
        properties = [prop.serialize() for prop in self.properties]
        booked_dates = [date.serialize() for date in self.booked_dates]
        return {
            'firstName': self.first_name,
            'lastName': self.last_name,
            'email': self.email,
            'properties': properties,
            'bookedDates': booked_dates,
            'isThirdPartyUser': True if self.provider else False # this is a way to check if the user is a third party user. can do filtering in the frontend.
        }
