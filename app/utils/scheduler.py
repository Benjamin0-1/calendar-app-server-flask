from apscheduler.schedulers.background import BackgroundScheduler
from flask import current_app as app
from app.models import User, BookedDate, Property
from app.services import send_email
from datetime import datetime
from .. import db

def expire_otps():
    with app.app_context():
        try:
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
            db.session.commit()  
        except Exception as e:
            app.logger.error(f"Error in expire_otps job: {e}")

def send_booking_reminders():
    with app.app_context():
        try:
            today = datetime.utcnow().date()
            bookings = BookedDate.query.filter_by(date=today).all()

            for booking in bookings:
                user = User.query.get(booking.user_id)
                property = Property.query.get(booking.property_id)  

                if user and property:
                    send_email(
                        subject='Reminder: Your booking is today!',
                        recipient=user.email,
                        body=f'Hello {user.first_name},\n\nThis is a reminder that you have a booking today for the event: {booking.customer_name}.\n'
                             f'Property: {property.property_name}'
                    )
        except Exception as e:
            app.logger.error(f"Error in send_booking_reminders job: {e}")

def start_scheduler(app):
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=expire_otps, trigger='interval', minutes=1)
    scheduler.add_job(func=send_booking_reminders, trigger='interval', hours=1)
    scheduler.start()
    def stop_scheduler(scheduler):
        scheduler.shutdown()
    return scheduler