import sys
import os

# Add the project directory to the system path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from app import create_app
from flask_migrate import Migrate, upgrade
from app import db  # Importing db directly from app

app = create_app()
migrate = Migrate(app, db)

if __name__ == '__main__':
    with app.app_context():
        upgrade()
