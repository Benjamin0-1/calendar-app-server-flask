




import pytest
from app import create_app, db
from app.models.user import User
from app.models.property import Property

def test_client():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_client() as testing_client:
        with app.app_context():
            db.create_all()
        yield testing_client
        with app.app_context():
            db.drop_all()

@pytest.fixture(scope='module')
def init_db(test_client):
    # Initialize database with test data if needed
    yield db
    db.drop_all()
