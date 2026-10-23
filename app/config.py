import os
from datetime import timedelta

access_token_expiracy = os.environ.get('JWT_ACCESS_TOKEN_EXPIRES') # in minutes
refresh_token_expiracy = os.environ.get('JWT_REFRESH_TOKEN_EXPIRES') # in days

access_token_expiracy = int(access_token_expiracy) if access_token_expiracy else 60  
refresh_token_expiracy = int(refresh_token_expiracy) if refresh_token_expiracy else 15  

SECRET_KEY = os.environ.get('SECRET_KEY', 'secret-key')
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://postgres:12241530@localhost/calendar-app')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your_jwt_secret_key')

JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=access_token_expiracy)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=refresh_token_expiracy)

# frontend origins allowed by CORS. ORIGIN from .env is added on top of the local dev ones.
CORS_ORIGINS = {"http://localhost:5173", "http://127.0.0.1:5173"}
if os.environ.get('ORIGIN'):
    CORS_ORIGINS.add(os.environ['ORIGIN'])

# instance/ lives at the project root, next to app/.
FIREBASE_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance', 'firebase_config.json')

# link sent in email confirmation emails.
EMAIL_CONFIRM_URL = 'http://127.0.0.1:5000/auth/confirm-email'
