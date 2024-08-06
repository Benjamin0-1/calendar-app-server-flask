import pytest
from app import create_app, db

@pytest.fixture
def test_client():
 
    app = create_app('testing')


    client = app.test_client()


    ctx = app.app_context()
    ctx.push()


    db.create_all()

    yield client  


    db.drop_all()
    ctx.pop()
