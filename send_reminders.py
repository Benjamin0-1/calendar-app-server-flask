from app import create_app
from app.services.reminder_service import send_booking_reminders

app = create_app()

if __name__ == '__main__':
    send_booking_reminders()

