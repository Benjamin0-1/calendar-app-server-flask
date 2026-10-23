from flask import render_template
from flask_mail import Message
from app.extensions import mail
import os

email_sender = os.environ.get('EMAIL_SENDER') or 'oliver125125@gmail.com'

def send_email(subject, recipient, body):
    msg = Message(subject, sender=email_sender, recipients=[recipient])
    msg.html = body  # .html for html emails.
    mail.send(msg)

def send_template_email(subject, recipient, template, **context):
    """Render one of the templates in app/templates/email/ and send it."""
    send_email(subject, recipient, render_template(f'email/{template}', **context))
