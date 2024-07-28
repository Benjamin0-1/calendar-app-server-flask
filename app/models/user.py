from .. import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pyotp
import os
from sqlalchemy import UniqueConstraint, CheckConstraint

otp_secret = os.environ.get('OTP_SECRET')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False) #CHECK (email ~* '^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$')  
    password_hash = db.Column(db.String(250), nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(6), nullable=True)
    otp_expiration = db.Column(db.DateTime, nullable=True)

    properties = db.relationship('Property', back_populates='owner')
    booked_dates = db.relationship('BookedDate', back_populates='user')

    def set_password(self, password):   # used in /reset-password
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_otp(self, otp):
        self.otp = otp
        self.otp_expiration = datetime.utcnow() + timedelta(minutes=10)

    def generate_otp(self):
        otp = pyotp.TOTP(otp_secret) 
        return otp.now()
