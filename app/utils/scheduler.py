from app.services import send_email
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from app.models import User, BookedDate, Property
from flask import current_app as app

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

def send_booking_reminders():
    with app.app_context():
        today = datetime.utcnow().date()
        bookings = BookedDate.query.filter(date=today).all()

        for booking in bookings:
            user = User.query.get(booking.user_id)
            property = Property.query.get(booking.user_id)

            if user and property:
                send_email(
                    subject='Reminder: Your booking is today!',
                    recipient=user.email,
                    body=f'Hello {user.first_name},\n\nThis is a reminder that you have a booking today for the event: {booking.customer_name}.\n'
                         f'Property: {property.property_name}'
                )

def start_scheduler(app):
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=expire_otps, trigger='interval', minutes=1)
    scheduler.add_job(func=send_booking_reminders, trigger='interval', hours=1)
    scheduler.start()
    return scheduler
