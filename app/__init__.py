from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
import os
import firebase_admin
from firebase_admin import credentials

from app import config
from app.extensions import db, mail, oauth  # re-exported so `from app import db` keeps working.

def create_app(test_config=None):
    app = Flask(__name__)
    app.config['SECRET_KEY'] = config.SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@example.com')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-password')
    app.config['JWT_SECRET_KEY'] = config.JWT_SECRET_KEY
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = config.JWT_ACCESS_TOKEN_EXPIRES
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = config.JWT_REFRESH_TOKEN_EXPIRES
    app.config['ENV'] = os.environ.get('ENVIRON', 'development')

    # overrides used by the test suite (e.g. an SQLite database).
    if test_config:
        app.config.update(test_config)

    # Initialize Firebase
    firebase_config_path = config.FIREBASE_CONFIG_PATH
    print(f"Attempting to load Firebase config from: {firebase_config_path}")

    if not os.path.exists(firebase_config_path):
        raise FileNotFoundError(f"Firebase config file not found at {firebase_config_path}")

    # Check if Firebase app is already initialized
    if not len(firebase_admin._apps):
        cred = credentials.Certificate(firebase_config_path)
        firebase_admin.initialize_app(cred)

    db.init_app(app)
    mail.init_app(app)
    CORS(app, supports_credentials=True, resources={r"/*": {"origins": list(config.CORS_ORIGINS)}})

    jwt = JWTManager(app)
    migrate = Migrate(app, db)

    # Google OAuth
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

    oauth.init_app(app)
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params=None,
        access_token_url='https://accounts.google.com/o/oauth2/token',
        access_token_params=None,
        refresh_token_url=None,
        client_kwargs={'scope': 'openid profile email'},
        userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
        userinfo_compliance_fix=None,
        client_class=None,
        callback_url='http://127.0.0.1:5000/auth/google/callback',
        response_type='code'
    )

    from app.errors import register_error_handlers
    register_error_handlers(app)

    from app.blueprints.main import main as main_blueprint
    app.register_blueprint(main_blueprint, url_prefix='/main')

    from app.blueprints.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from app.blueprints.bookings import bookings as bookings_blueprint
    app.register_blueprint(bookings_blueprint, url_prefix='/bookings')

    return app
