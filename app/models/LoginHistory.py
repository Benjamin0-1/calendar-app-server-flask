from .. import db
from datetime import datetime
from sqlalchemy import CheckConstraint, UniqueConstraint

class LoginHistory(db.Model):
    __tablename__ = 'login_history'
    id = db.Column(db.Integer, primary_key=True)
    login_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime, nullable=True) # front end will handle this, and it will be stored here
    ip_address = db.Column(db.String(45), nullable=False)  # IPv4 is 15 characters long
    user_agent = db.Column(db.String(250), nullable=True) # user agent string
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    user = db.relationship('User', back_populates='login_history')

    def serialize(self):
        return {
            'login_time': self.login_time,
            'logout_time': self.logout_time, # will be None if the user is still logged in. It would be implemented in the front end.
            'ip_address': self.ip_address,
            'user_agent': self.user_agent
        }