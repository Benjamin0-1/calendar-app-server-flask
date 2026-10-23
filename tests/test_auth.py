import json
import pytest
from datetime import datetime, timedelta

from app.services.login_attempts import failed_login_attempts

user_data = {
    'email': 'testuser@example.com',
    'password': 'password123',
    'firstName': 'Test',
    'lastName': 'User'
}

@pytest.fixture(autouse=True)
def reset_login_attempts():
    # lockouts live in process memory, so they would leak between tests.
    failed_login_attempts._attempts.clear()

def create_user(test_client, user_data):
    test_client.post('/auth/signup', json=user_data)

def test_login_success(test_client):
    create_user(test_client, user_data)
    
    response = test_client.post('/auth/login', json={
        'email': user_data['email'],
        'password': user_data['password']
    })
    
    assert response.status_code == 200
    response_json = json.loads(response.data)
    assert 'access_token' in response_json
    assert 'refresh_token' in response_json

def test_login_missing_data(test_client):
    response = test_client.post('/auth/login', json={
        'email': user_data['email']
    })
    
    assert response.status_code == 400
    assert json.loads(response.data).get('missingData') is True

def test_login_user_not_found(test_client):
    response = test_client.post('/auth/login', json={
        'email': 'nonexistent@example.com',
        'password': 'password123'
    })
    
    assert response.status_code == 404
    assert json.loads(response.data).get('userNotFound') is True

def test_login_invalid_credentials(test_client):
    create_user(test_client, user_data)
    
    response = test_client.post('/auth/login', json={
        'email': user_data['email'],
        'password': 'wrongpassword'
    })
    
    assert response.status_code == 401
    assert json.loads(response.data).get('invalidCredentials') is True

def test_login_brute_force_lockout(test_client):
    create_user(test_client, user_data)
    
    for _ in range(5):
        response = test_client.post('/auth/login', json={
            'email': user_data['email'],
            'password': 'wrongpassword'
        })
        assert response.status_code == 401
    
    response = test_client.post('/auth/login', json={
        'email': user_data['email'],
        'password': 'wrongpassword'
    })
    assert response.status_code == 403
    assert json.loads(response.data).get('lockedOut') is True

def test_login_brute_force_unlock(test_client):
    create_user(test_client, user_data)
    
    for _ in range(5):
        response = test_client.post('/auth/login', json={
            'email': user_data['email'],
            'password': 'wrongpassword'
        })
        assert response.status_code == 401
    
    # Simulate the lockout period expiring
    failed_login_attempts._attempts[user_data['email']]['lockout_time'] = datetime.now() - timedelta(seconds=1)
    
    response = test_client.post('/auth/login', json={
        'email': user_data['email'],
        'password': 'wrongpassword'
    })
    assert response.status_code == 401  # Adjust this if necessary
    assert json.loads(response.data).get('invalidCredentials') is True

def test_signup_success(test_client):
    response = test_client.post('/auth/signup', json=user_data)
    
    assert response.status_code == 201
    assert json.loads(response.data) == "User created successfully"

def test_signup_missing_data(test_client):
    response = test_client.post('/auth/signup', json={
        'email': user_data['email'],
        'password': user_data['password']
    })
    
    assert response.status_code == 400
    assert json.loads(response.data).get('missingData') is True

def test_signup_invalid_email(test_client):
    response = test_client.post('/auth/signup', json={
        'email': 'invalid-email',
        'password': user_data['password'],
        'firstName': user_data['firstName'],
        'lastName': user_data['lastName']
    })
    
    assert response.status_code == 400
    assert json.loads(response.data).get('invalidEmail') is True

def test_signup_user_already_exists(test_client):
    test_client.post('/auth/signup', json=user_data)
    
    response = test_client.post('/auth/signup', json=user_data)
    assert response.status_code == 400
    assert json.loads(response.data).get('userAlreadyExists') is True

def test_signup_email_sending_failure(test_client, mocker):
    mock_send_email = mocker.patch('app.services.email_service.send_email', side_effect=Exception("Email service failure"))
    response = test_client.post('/auth/signup', json=user_data)
    
    assert response.status_code == 500
    assert json.loads(response.data).get('message') == "User created but failed to send email."
    mock_send_email.assert_called_once()

def test_signup_email_sending_success(test_client, mocker):
    mock_send_email = mocker.patch('app.services.email_service.send_email')
    response = test_client.post('/auth/signup', json=user_data)
    
    assert response.status_code == 201
    assert json.loads(response.data) == "User created successfully"
    mock_send_email.assert_called_once()
