from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
import os
from datetime import timedelta
from authlib.integrations.flask_client import OAuth
import firebase_admin
from firebase_admin import credentials

db = SQLAlchemy()
mail = Mail()
oauth = OAuth()

access_token_expiracy = os.environ.get('JWT_ACCESS_TOKEN_EXPIRES') # in minutes
refresh_token_expiracy = os.environ.get('JWT_REFRESH_TOKEN_EXPIRES') # in days

access_token_expiracy = int(access_token_expiracy) if access_token_expiracy else 60  
refresh_token_expiracy = int(refresh_token_expiracy) if refresh_token_expiracy else 15  

SECRET_KEY = os.environ.get('SECRET_KEY', 'secret-key')
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://postgres:12241530@localhost/calendar-app')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your_jwt_secret_key')

JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=access_token_expiracy)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=refresh_token_expiracy)

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = SECRET_KEY 
    app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@example.com')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-password')
    app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = JWT_ACCESS_TOKEN_EXPIRES
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = JWT_REFRESH_TOKEN_EXPIRES
    app.config['ENV'] = os.environ.get('ENVIRON', 'development')

    # Initialize Firebase
    firebase_config_path = os.path.join(os.path.dirname(__file__), 'FirebaseConfig', 'firebase_config.json')
    print(f"Attempting to load Firebase config from: {firebase_config_path}")

    if not os.path.exists(firebase_config_path):
        raise FileNotFoundError(f"Firebase config file not found at {firebase_config_path}")

    # Check if Firebase app is already initialized
    if not len(firebase_admin._apps):
        cred = credentials.Certificate(firebase_config_path)
        firebase_admin.initialize_app(cred)

    db.init_app(app)
    mail.init_app(app)
    CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:5173"}})

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

    from app.main import main as main_blueprint
    app.register_blueprint(main_blueprint, url_prefix='/main')

    from app.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from app.bookings import bookings as bookings_blueprint
    app.register_blueprint(bookings_blueprint, url_prefix='/bookings')

    return app

app = create_app()

# if for some reason cors don't work, use this command on mac, to disable web security on chrome, and test the app: 
# command: /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --disable-web-security --user-data-dir="/tmp/chrome_dev"
