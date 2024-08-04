from .. import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pyotp
import os
from sqlalchemy import UniqueConstraint, CheckConstraint
from uuid import uuid4 # for generating random strings and also for the email confirmation.

#otp_secret = os.environ.get('OTP_SECRET')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False, info={'check': 'email ~* \'^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$\''})  
    password_hash = db.Column(db.String(250), nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(6), nullable=True)

    otp_expiration = db.Column(db.DateTime, nullable=True) # TO BE REMOVED.
    email_otp_expiration = db.Column(db.DateTime, nullable=True)  # Email confirmation <- TP BE REMOVED.
    
    recovery_otp_expiration = db.Column(db.DateTime, nullable=True)  # OTP for the email confirm.
    otp_secret = db.Column(db.String(32), nullable=True)  # must be base32 encoded
    # the ones below are for the seamless email confirmation.
    email_confirm_uuid = db.Column(db.String(36), default=str(uuid4()), nullable=True) 
    email_confirm_expiration = db.Column(db.DateTime, nullable=True)

    properties = db.relationship('Property', back_populates='owner')
    booked_dates = db.relationship('BookedDate', back_populates='user')

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


    
    def serialize(self):
        properties = [prop.serialize() for prop in self.properties]
        booked_dates = [date.serialize() for date in self.booked_dates]
        return {
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'properties': properties,
            'booked_dates': booked_dates
        }
