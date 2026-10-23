from apscheduler.schedulers.background import BackgroundScheduler
from app.extensions import db
from app.models import User, BookedDate, Property, Provider
from app.services.email_service import send_email
from datetime import datetime

# jobs run on the scheduler's thread, outside of any request, so each one gets the app explicitly
# and pushes its own app context.

def create_default_provider(app): # google for now
    with app.app_context():
        try:
            provider = Provider.query.filter(Provider.provider_name.ilike('google')).first()
            if not provider:
                provider = Provider(provider_name='Google', provider_uuid='google')
                db.session.add(provider)
                db.session.commit()
                app.logger.info("Default provider created: google.")
        except Exception as e:
            app.logger.error(f"Error in create_default_provider: {e}")

# this function will no longer works thanks to moving to a click for email confirm.
def expire_otps(app):
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

def send_booking_reminders(app):
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
    #scheduler.add_job(func=expire_otps, args=[app], trigger='interval', minutes=1)
    scheduler.add_job(func=send_booking_reminders, args=[app], trigger='interval', hours=1) # this is working.
    scheduler.start()
    create_default_provider(app)
    return scheduler
