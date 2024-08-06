from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_cors import CORS, cross_origin
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
import os
from datetime import timedelta


db = SQLAlchemy()
mail = Mail()


access_token_expiracy = os.environ.get('JWT_ACCESS_TOKEN_EXPIRES')
refresh_token_expiracy = os.environ.get('JWT_REFRESH_TOKEN_EXPIRES')


access_token_expiracy = int(access_token_expiracy) if access_token_expiracy else 60  
refresh_token_expiracy = int(refresh_token_expiracy) if refresh_token_expiracy else 15  

SECRET_KEY = os.environ.get('SECRET_KEY', 'secret-key')
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://postgres:12241530@localhost/calendar-app')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your_jwt_secret_key')


JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=access_token_expiracy)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=refresh_token_expiracy)

# now you can simply change the value of the environment variable JWT_ACCESS_TOKEN_EXPIRES to change the expiration time of the access token.
# access token number is in minutes and refresh token number is in days.

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




    db.init_app(app)
    mail.init_app(app)


#    CORS(app, supports_credentials=True, resources={r"/*": {
#    "origins": "http://localhost:5173",
#    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
#    "allow_headers": ["Content-Type", "Authorization", 'Access-Control-Allow-Origin'],
#}})


    CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:5173"}})


    jwt = JWTManager(app)
    migrate = Migrate(app, db)



    # Register Blueprints
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
