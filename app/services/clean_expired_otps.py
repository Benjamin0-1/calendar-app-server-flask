

from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from .. import app, db
from app.models import User  # Import your User model

def expire_otps():
    with app.app_context():
        now = datetime.utcnow()
        expired_users = User.query.filter(
            (User.email_otp_expiration < now) | (User.recovery_otp_expiration < now)
        ).all()
        for user in expired_users:
            if user.email_otp_expiration and user.email_otp_expiration < now:
                user.email_otp = None
                user.email_otp_expiration = None
            if user.recovery_otp_expiration and user.recovery_otp_expiration < now:
                user.recovery_otp = None
                user.recovery_otp_expiration = None
        db.session.commit()  # commit once to improve efficiency

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=expire_otps, trigger='interval', minutes=1)
    scheduler.start()

