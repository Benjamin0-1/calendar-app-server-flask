from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth

db = SQLAlchemy()
mail = Mail()
oauth = OAuth()

# currently not working, to be fixed in the future.
limiter = Limiter(key_func=get_remote_address)
