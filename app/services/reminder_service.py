from datetime import datetime
from .. import db
from ..models import User, BookedDate, Property # import property to get the property_name on the email.
from .email_service import send_email
from flask import current_app as app

# this has a different use case from send_email (example: welcome email), but can work together.
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



