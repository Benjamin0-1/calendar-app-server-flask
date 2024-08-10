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
    recovery_otp_expiration = db.Column(db.DateTime, nullable=True)  # OTP for email confirmation
    otp_secret = db.Column(db.String(32), nullable=True)  # Must be base32 encoded
    email_confirm_uuid = db.Column(db.String(36), default=str(uuid4()), nullable=True)
    email_confirm_expiration = db.Column(db.DateTime, nullable=True)

    # Relationships
    properties = db.relationship('Property', back_populates='owner')
    booked_dates = db.relationship('BookedDate', back_populates='user')
    login_history = db.relationship('LoginHistory', back_populates='user', lazy='dynamic')
    provider = db.relationship('Provider', uselist=False, back_populates='user')


    def set_password(self, password):  # used in /reset-password
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_otp(self, otp):
        self.otp = otp
        self.otp_expiration = datetime.utcnow() + timedelta(minutes=10)

    def generate_otp(self):
        if not self.otp_secret:
            self.otp_secret = pyotp.random_base32()
        # now set the user otp column
        otp = pyotp.TOTP(self.otp_secret)
        return otp.now()
    
    def generate_email_confirm_uuid(self): 
        if not self.email_confirm_uuid or self.email_confirm_expiration < datetime.utcnow():
            self.email_confirm_uuid = str(uuid4())
            self.email_confirm_expiration = datetime.utcnow() + timedelta(hours=24)

    # new method, or a modification of the corresponding existing one.
    # to re send the email confirmation email, in case the user didn't receive it (it must check if the email is confirmed or not).


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
