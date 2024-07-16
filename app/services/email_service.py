from flask_mail import Message
from .. import mail
import os

email_sender = os.environ.get('EMAIL_SENDER') or 'oliver125125@gmail.com'

def send_email(subject, recipient, body):
    msg = Message(subject, sender=email_sender, recipients=[recipient])
    msg.body = body
    mail.send(msg)

