from datetime import datetime
from .. import db
from ..models import User, BookedDate
from .email_service import send_email
from flask import current_app as app


def send_booking_reminders():
    with app.app_context():
        today = datetime.utcnow().date() 
        bookings = BookedDate.query.filter_by(date=today).all()
        for booking in bookings:
            user = User.query.get(booking.user_id)
            if user:
                send_email(
                    subject='Reminder: Your booking is today!',
                    recipient=user.email,
                    body=f'Hello {user.email},\n\nThis is a reminder that you have a booking today for the event: {booking.customer_name}.
                    property: {property.user}'
                )
                # fix the property.user