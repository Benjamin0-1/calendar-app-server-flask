import sys
import os

# Add the project directory to the system path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from app import create_app
from flask_migrate import upgrade
from app import db  # Importing db directly from app

def reset_database():
    app = create_app()
    with app.app_context():
        db.drop_all()
        print("All tables have been dropped.")
        
        db.create_all()
        print("All tables have been created.")

if __name__ == "__main__":
    reset_database()
