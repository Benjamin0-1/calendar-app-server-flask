from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from datetime import timedelta
from sqlalchemy import UniqueConstraint, CheckConstraint, Index

db = SQLAlchemy()
mail = Mail()


SECRET_KEY = os.environ.get('SECRET_KEY') or 'secret-key'
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://postgres:12241530@localhost/calendar-app'
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'your_jwt_secret_key'
JWT_ACCESS_TOKEN_EXPIRES = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 15))  # minutes
JWT_REFRESH_TOKEN_EXPIRES = int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', 30))  # days

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') or 'your-email@example.com'
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') or 'your-password'
    app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRES)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=JWT_REFRESH_TOKEN_EXPIRES)
    # to easily switch between production and development
    app.config['ENV'] = 'development'

    db.init_app(app)
    mail.init_app(app)
    CORS(app)  # Enable CORS for all routes
    jwt = JWTManager(app)

    # migrations
    migrate = Migrate(app, db)

    #limiter
    limiter = Limiter(get_remote_address, app=app)

    # Register Blueprints
    from app.main import main as main_blueprint
    app.register_blueprint(main_blueprint, url_prefix='/main')

    from app.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from app.bookings import bookings as bookings_blueprint
    app.register_blueprint(bookings_blueprint, url_prefix='/bookings')
         

    return app

app = create_app()
