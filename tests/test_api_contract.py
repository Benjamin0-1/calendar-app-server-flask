"""
Characterization test for the HTTP API.

Runs a scripted session against every endpoint and compares each response (status code, JSON body,
redirect target and any emails sent) with tests/snapshots/api_contract.json, which was recorded from
the original implementation. Refactors must keep this test green so the frontend sees no change.

To re-record after an intentional API change:  UPDATE_SNAPSHOT=1 pytest tests/test_api_contract.py
"""
import json
import os
import random
import re
from datetime import date, timedelta
from pathlib import Path

import firebase_admin.auth
import pytest

from app.extensions import db, mail
from app.models import User

SNAPSHOT_PATH = Path(__file__).parent / 'snapshots' / 'api_contract.json'

TODAY = date.today()
FUTURE_1 = TODAY + timedelta(days=10)
FUTURE_2 = TODAY + timedelta(days=20)
FUTURE_3 = TODAY + timedelta(days=30)
PAST = TODAY - timedelta(days=1)
DATES = {'D+10': FUTURE_1, 'D+20': FUTURE_2, 'D+30': FUTURE_3, 'D-1': PAST}

PREFLIGHT_HEADERS = {
    'Origin': 'http://localhost:5173',
    'Access-Control-Request-Method': 'GET',
    'Access-Control-Request-Headers': 'authorization',
}

# firebase id tokens accepted by the fake verifier below.
FIREBASE_TOKENS = {
    'google-token-new': {'email': 'gina@example.com', 'uid': 'google-uid-1', 'given_name': 'Gina', 'family_name': 'Goo'},
    'google-token-local-user': {'email': 'alice@example.com', 'uid': 'google-uid-2'},
}


def fake_verify_id_token(token):
    if token not in FIREBASE_TOKENS:
        raise ValueError('Invalid Firebase ID token')
    return FIREBASE_TOKENS[token]


def normalize(text):
    """Mask values that legitimately change between runs."""
    text = re.sub(r'"remainingLockoutTime": [\d.]+', '"remainingLockoutTime": "<seconds>"', text)
    text = re.sub(r'eyJ[\w-]+\.[\w-]+\.[\w-]+', '<jwt>', text)
    text = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<uuid>', text)
    text = re.sub(r'(?<!#)\b\d{6}\b', '<otp>', text)  # not css colors
    text = re.sub(r'\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT', '<timestamp>', text)
    for label, value in DATES.items():
        text = text.replace(value.isoformat(), f'<{label}>')
        text = text.replace(value.strftime('%a, %d %b %Y'), f'<{label}>')
    return text


class Session:
    def __init__(self, client):
        self.client = client
        self.entries = []

    def call(self, label, method, path, token=None, headers=None, **kwargs):
        headers = dict(headers or {})
        if token:
            headers['Authorization'] = f'Bearer {token}'
        with mail.record_messages() as outbox:
            response = self.client.open(path, method=method, headers=headers, **kwargs)

        entry = {'label': label, 'request': f'{method} {path}', 'status': response.status_code}
        if response.is_json:
            entry['json'] = response.get_json()
        elif 300 <= response.status_code < 400:
            entry['location'] = response.headers.get('Location')
        elif method == 'OPTIONS':
            entry['allow_origin'] = response.headers.get('Access-Control-Allow-Origin')
        else:
            entry['body'] = response.get_data(as_text=True)[:120]
        if outbox:
            entry['emails'] = [{
                'subject': message.subject,
                'recipients': message.recipients,
                'html': ' '.join((message.html or '').split()),
            } for message in outbox]

        self.entries.append(json.loads(normalize(json.dumps(entry, default=str))))
        # keep the raw sent emails around so the script can follow links in them.
        self.last_emails = outbox
        return response


def user_row(app, email):
    with app.app_context():
        return db.session.execute(db.select(User).filter_by(email=email)).scalar_one()


def run_session(app, client):
    s = Session(client)
    call = s.call

    call('root', 'GET', '/main/')
    call('preflight bookings', 'OPTIONS', '/bookings', headers=PREFLIGHT_HEADERS)
    call('preflight user profile', 'OPTIONS', '/auth/user-profile', headers=PREFLIGHT_HEADERS)

    # ---- signup ----
    alice = {'firstName': 'Alice', 'lastName': 'Anders', 'email': 'alice@example.com', 'password': 'alice-pass-1'}
    call('signup missing fields', 'POST', '/auth/signup', json={'email': 'x@example.com', 'password': 'p'})
    call('signup empty first name', 'POST', '/auth/signup', json={**alice, 'firstName': ''})
    call('signup invalid email', 'POST', '/auth/signup', json={**alice, 'email': 'not-an-email'})
    call('signup missing first name and invalid email', 'POST', '/auth/signup', json={**alice, 'firstName': None, 'email': 'nope'})
    call('signup alice', 'POST', '/auth/signup', json=alice)
    alice_confirm_link = re.search(r'href="([^"]+)"', s.last_emails[0].html).group(1)
    call('signup duplicate', 'POST', '/auth/signup', json=alice)
    bob = {'firstName': 'Bob', 'lastName': 'Brown', 'email': 'bob@example.com', 'password': 'bob-pass-1'}
    call('signup bob', 'POST', '/auth/signup', json=bob)
    bob_confirm_link = re.search(r'href="([^"]+)"', s.last_emails[0].html).group(1)
    carol = {'firstName': 'Carol', 'lastName': 'Cole', 'email': 'carol@example.com', 'password': 'carol-pass-1'}
    call('signup carol', 'POST', '/auth/signup', json=carol)

    # ---- login before confirming, and the email-confirmed middleware ----
    r = call('login alice unconfirmed', 'POST', '/auth/login', json={'email': alice['email'], 'password': alice['password']})
    unconfirmed_token = r.get_json()['access_token']
    call('profile while unconfirmed', 'GET', '/auth/user-profile', token=unconfirmed_token)
    call('bookings while unconfirmed', 'GET', '/bookings/', token=unconfirmed_token)

    # ---- email confirmation ----
    call('confirm email bad uuid', 'GET', '/auth/confirm-email?uuid=does-not-exist')
    call('confirm email no uuid', 'GET', '/auth/confirm-email')
    call('confirm email alice', 'GET', alice_confirm_link.replace('http://127.0.0.1:5000', ''))
    call('confirm email alice again', 'GET', alice_confirm_link.replace('http://127.0.0.1:5000', ''))
    call('resend confirmation missing email', 'POST', '/auth/resend-email-confirmation', json={})
    call('resend confirmation unknown', 'POST', '/auth/resend-email-confirmation', json={'email': 'ghost@example.com'})
    call('resend confirmation already confirmed', 'POST', '/auth/resend-email-confirmation', json={'email': alice['email']})
    # note: the resent link currently carries uuid=None, so bob confirms with the signup link.
    call('resend confirmation bob', 'POST', '/auth/resend-email-confirmation', json={'email': bob['email']})
    call('confirm email bob', 'GET', bob_confirm_link.replace('http://127.0.0.1:5000', ''))

    # ---- login ----
    call('login missing password', 'POST', '/auth/login', json={'email': alice['email']})
    call('login empty password', 'POST', '/auth/login', json={'email': alice['email'], 'password': ''})
    call('login unknown user', 'POST', '/auth/login', json={'email': 'ghost@example.com', 'password': 'x'})
    for attempt in range(1, 6):
        call(f'login carol wrong password #{attempt}', 'POST', '/auth/login', json={'email': carol['email'], 'password': 'wrong'})
    call('login carol locked out', 'POST', '/auth/login', json={'email': carol['email'], 'password': 'wrong'})
    call('login carol locked out with right password', 'POST', '/auth/login', json={'email': carol['email'], 'password': carol['password']})

    r = call('login alice', 'POST', '/auth/login', json={'email': alice['email'], 'password': alice['password']}, environ_base={'REMOTE_ADDR': '10.0.0.1'})
    alice_token = r.get_json()['access_token']
    alice_refresh = r.get_json()['refresh_token']
    call('login alice from new ip', 'POST', '/auth/login', json={'email': alice['email'], 'password': alice['password']}, environ_base={'REMOTE_ADDR': '10.0.0.2'})
    r = call('login bob', 'POST', '/auth/login', json={'email': bob['email'], 'password': bob['password']})
    bob_token = r.get_json()['access_token']

    # ---- refresh ----
    call('refresh missing token', 'POST', '/auth/access-token', json={})
    call('refresh garbage token', 'POST', '/auth/access-token', json={'refreshToken': 'garbage'})
    call('refresh alice', 'POST', '/auth/access-token', json={'refreshToken': alice_refresh})

    # ---- profile ----
    call('profile without token', 'GET', '/auth/user-profile')
    call('profile alice', 'GET', '/auth/user-profile', token=alice_token)
    call('update profile nothing', 'PATCH', '/auth/update-profile', token=alice_token, json={})
    call('update profile same values', 'PATCH', '/auth/update-profile', token=alice_token, json={'firstName': 'Alice', 'lastName': 'Anders'})
    call('update profile', 'PATCH', '/auth/update-profile', token=alice_token, json={'firstName': 'Alicia'})
    call('login history alice', 'GET', '/auth/login-history', token=alice_token)

    # ---- update password ----
    call('update password missing', 'PUT', '/auth/update-password', token=alice_token, json={'currentPassword': alice['password']})
    call('update password wrong current', 'PUT', '/auth/update-password', token=alice_token,
         json={'currentPassword': 'nope', 'newPassword': 'a', 'confirmNewPassword': 'b'})
    call('update password mismatch', 'PUT', '/auth/update-password', token=alice_token,
         json={'currentPassword': alice['password'], 'newPassword': 'a', 'confirmNewPassword': 'b'})
    call('update password same as current', 'PUT', '/auth/update-password', token=alice_token,
         json={'currentPassword': alice['password'], 'newPassword': alice['password'], 'confirmNewPassword': alice['password']})
    call('update password', 'PUT', '/auth/update-password', token=alice_token,
         json={'currentPassword': alice['password'], 'newPassword': 'alice-pass-2', 'confirmNewPassword': 'alice-pass-2'})
    call('login alice old password', 'POST', '/auth/login', json={'email': alice['email'], 'password': alice['password']})
    call('login alice new password', 'POST', '/auth/login', json={'email': alice['email'], 'password': 'alice-pass-2'})

    # ---- password reset ----
    call('reset request missing email', 'POST', '/auth/request-password-reset', json={})
    call('reset request unknown', 'POST', '/auth/request-password-reset', json={'email': 'ghost@example.com'})
    call('reset bob without otp', 'POST', '/auth/reset-password',
         json={'email': bob['email'], 'otp': '123456', 'newPassword': 'n', 'confirmNewPassword': 'n'})
    call('reset request bob', 'POST', '/auth/request-password-reset', json={'email': bob['email']})
    bob_otp = user_row(app, bob['email']).otp
    call('reset missing data', 'POST', '/auth/reset-password', json={'email': bob['email'], 'otp': bob_otp})
    call('reset mismatch', 'POST', '/auth/reset-password',
         json={'email': bob['email'], 'otp': bob_otp, 'newPassword': 'a', 'confirmNewPassword': 'b'})
    call('reset unknown user', 'POST', '/auth/reset-password',
         json={'email': 'ghost@example.com', 'otp': bob_otp, 'newPassword': 'n', 'confirmNewPassword': 'n'})
    call('reset wrong otp', 'POST', '/auth/reset-password',
         json={'email': bob['email'], 'otp': '000000', 'newPassword': 'n', 'confirmNewPassword': 'n'})
    call('reset bob', 'POST', '/auth/reset-password',
         json={'email': bob['email'], 'otp': bob_otp, 'newPassword': 'bob-pass-2', 'confirmNewPassword': 'bob-pass-2'})
    call('login bob new password', 'POST', '/auth/login', json={'email': bob['email'], 'password': 'bob-pass-2'})

    # ---- google login ----
    call('google login missing data', 'POST', '/auth/google-login', json={'googleToken': 'google-token-new'})
    call('google login invalid token', 'POST', '/auth/google-login',
         json={'googleToken': 'forged', 'email': 'gina@example.com', 'userId': 'google-uid-1'})
    call('google login data mismatch', 'POST', '/auth/google-login',
         json={'googleToken': 'google-token-new', 'email': 'other@example.com', 'userId': 'google-uid-1'})
    r = call('google login new user', 'POST', '/auth/google-login',
             json={'googleToken': 'google-token-new', 'email': 'gina@example.com', 'userId': 'google-uid-1'})
    gina_token = r.get_json()['access_token']
    call('google login existing user', 'POST', '/auth/google-login',
         json={'googleToken': 'google-token-new', 'email': 'gina@example.com', 'userId': 'google-uid-1'})
    call('google login for local user', 'POST', '/auth/google-login',
         json={'googleToken': 'google-token-local-user', 'email': 'alice@example.com', 'userId': 'google-uid-2'})
    call('third-party local login', 'POST', '/auth/login', json={'email': 'gina@example.com', 'password': 'x'})
    call('third-party reset request', 'POST', '/auth/request-password-reset', json={'email': 'gina@example.com'})
    call('third-party reset', 'POST', '/auth/reset-password',
         json={'email': 'gina@example.com', 'otp': '1', 'newPassword': 'n', 'confirmNewPassword': 'n'})
    call('third-party resend confirmation', 'POST', '/auth/resend-email-confirmation', json={'email': 'gina@example.com'})
    call('third-party profile', 'GET', '/auth/user-profile', token=gina_token)
    call('third-party update password', 'PUT', '/auth/update-password', token=gina_token,
         json={'currentPassword': 'a', 'newPassword': 'b', 'confirmNewPassword': 'b'})

    # ---- properties ----
    call('bookings with no properties', 'GET', '/bookings/', token=alice_token)
    call('user properties none', 'GET', '/bookings/user-properties', token=alice_token)
    call('create property missing name', 'POST', '/bookings/create-property', token=alice_token, json={})
    r = call('create property beach', 'POST', '/bookings/create-property', token=alice_token, json={'propertyName': 'Beach House'})
    beach_id = r.get_json()['property']['id']
    call('create property duplicate other case', 'POST', '/bookings/create-property', token=alice_token, json={'propertyName': 'beach house'})
    r = call('create property cabin', 'POST', '/bookings/create-property', token=alice_token, json={'propertyName': 'Cabin'})
    cabin_id = r.get_json()['property']['id']
    r = call('create property bob loft', 'POST', '/bookings/create-property', token=bob_token, json={'propertyName': 'Loft'})
    loft_id = r.get_json()['property']['id']
    call('user properties', 'GET', '/bookings/user-properties', token=alice_token)
    call('property details', 'GET', f'/bookings/property-details/{beach_id}', token=alice_token)
    call('property details not owned', 'GET', f'/bookings/property-details/{loft_id}', token=alice_token)
    call('bookings with empty properties', 'GET', '/bookings', token=alice_token)

    # ---- create bookings ----
    call('book missing everything', 'POST', '/bookings/', token=alice_token, json={})
    call('book bad property id', 'POST', '/bookings/', token=alice_token,
         json={'propertyId': 'abc', 'customerName': 'Zed', 'date': FUTURE_1.isoformat()})
    call('book bad date', 'POST', '/bookings/', token=alice_token,
         json={'propertyId': beach_id, 'customerName': 'Zed', 'date': '10/10/2030'})
    call('book past date', 'POST', '/bookings/', token=alice_token,
         json={'propertyId': beach_id, 'customerName': 'Zed', 'date': PAST.isoformat()})
    call('book past date without customer', 'POST', '/bookings/', token=alice_token,
         json={'propertyId': beach_id, 'date': PAST.isoformat()})
    call('book missing customer', 'POST', '/bookings/', token=alice_token,
         json={'propertyId': beach_id, 'date': FUTURE_1.isoformat()})
    call('book property not owned', 'POST', '/bookings/', token=alice_token,
         json={'propertyId': loft_id, 'customerName': 'Zed', 'date': FUTURE_1.isoformat()})
    call('book beach D+10', 'POST', '/bookings/', token=alice_token,
         json={'propertyId': beach_id, 'customerName': 'Zed Zimmer', 'date': FUTURE_1.isoformat()})
    call('book beach D+10 again', 'POST', '/bookings/', token=alice_token,
         json={'propertyId': beach_id, 'customerName': 'Zed Zimmer', 'date': FUTURE_1.isoformat()})
    call('book beach D+20 without slash', 'POST', '/bookings', token=alice_token,
         json={'propertyId': str(beach_id), 'customerName': 'Yara Young', 'date': FUTURE_2.isoformat()})
    call('book cabin D+10', 'POST', '/bookings/', token=alice_token,
         json={'propertyId': cabin_id, 'customerName': 'Xavier', 'date': FUTURE_1.isoformat()})
    call('bookings', 'GET', '/bookings/', token=alice_token)

    # ---- update bookings ----
    call('update booking missing property', 'PATCH', '/bookings/', token=alice_token, json={'currentDate': FUTURE_1.isoformat()})
    call('update booking missing current date', 'PATCH', '/bookings/', token=alice_token, json={'propertyId': beach_id})
    call('update booking not owned', 'PATCH', '/bookings/', token=alice_token,
         json={'propertyId': loft_id, 'currentDate': FUTURE_1.isoformat(), 'customerName': 'Q'})
    call('update booking not found', 'PATCH', '/bookings/', token=alice_token,
         json={'propertyId': beach_id, 'currentDate': FUTURE_3.isoformat(), 'customerName': 'Q'})
    call('update booking nothing to update', 'PATCH', '/bookings/', token=alice_token,
         json={'propertyId': beach_id, 'currentDate': FUTURE_1.isoformat()})
    call('update booking bad new date', 'PATCH', '/bookings/', token=alice_token,
         json={'propertyId': beach_id, 'currentDate': FUTURE_1.isoformat(), 'newDate': 'tomorrow'})
    call('update booking past new date', 'PATCH', '/bookings/', token=alice_token,
         json={'propertyId': beach_id, 'currentDate': FUTURE_1.isoformat(), 'newDate': PAST.isoformat()})
    call('update booking name', 'PATCH', '/bookings/', token=alice_token,
         json={'propertyId': beach_id, 'currentDate': FUTURE_1.isoformat(), 'customerName': 'Zed Updated'})
    call('update booking date', 'PATCH', '/bookings/', token=alice_token,
         json={'propertyId': beach_id, 'currentDate': FUTURE_1.isoformat(), 'newDate': FUTURE_3.isoformat()})

    # ---- filter bookings ----
    call('filter default', 'GET', '/bookings/filter-bookings', token=alice_token)
    call('filter property not owned', 'GET', '/bookings/filter-bookings?propertyName=Loft', token=alice_token)
    call('filter by property name', 'GET', '/bookings/filter-bookings?propertyName=Cabin', token=alice_token)
    call('filter bad date', 'GET', '/bookings/filter-bookings?date=nope', token=alice_token)
    call('filter by date', 'GET', f'/bookings/filter-bookings?date={FUTURE_2.isoformat()}', token=alice_token)
    call('filter by customer', 'GET', '/bookings/filter-bookings?customerName=zed', token=alice_token)
    call('filter bad property id', 'GET', '/bookings/filter-bookings?propertyId=x', token=alice_token)
    call('filter by property id asc', 'GET', f'/bookings/filter-bookings?propertyId={beach_id}&sort_order=asc', token=alice_token)
    call('filter paginated', 'GET', f'/bookings/filter-bookings?propertyId={beach_id}&page=1&perPage=1', token=alice_token)
    call('filter paginated page 2', 'GET', f'/bookings/filter-bookings?propertyId={beach_id}&page=2&perPage=1&sort_order=desc', token=alice_token)
    call('filter no results', 'GET', '/bookings/filter-bookings?customerName=nobody', token=alice_token)

    # ---- delete bookings and the deleted-bookings archive ----
    call('deleted bookings none', 'GET', '/bookings/view-deleted-bookings', token=alice_token)
    call('delete all deleted none', 'DELETE', '/bookings/delete-all-deleted-bookings', token=alice_token)
    call('delete booking missing data', 'DELETE', '/bookings/', token=alice_token, json={'propertyId': beach_id})
    call('delete booking not owned', 'DELETE', '/bookings/', token=alice_token, json={'propertyId': loft_id, 'date': FUTURE_1.isoformat()})
    call('delete booking not found', 'DELETE', '/bookings/', token=alice_token, json={'propertyId': beach_id, 'date': FUTURE_1.isoformat()})
    call('delete booking', 'DELETE', '/bookings/', token=alice_token, json={'propertyId': beach_id, 'date': FUTURE_3.isoformat()})
    call('deleted bookings', 'GET', '/bookings/view-deleted-bookings', token=alice_token)
    call('delete deleted booking missing', 'DELETE', '/bookings/delete-deleted-booking', token=alice_token, json={'date': FUTURE_3.isoformat()})
    call('delete deleted booking bad date', 'DELETE', '/bookings/delete-deleted-booking', token=alice_token,
         json={'date': 'nope', 'propertyName': 'Beach House'})
    call('delete deleted booking not found', 'DELETE', '/bookings/delete-deleted-booking', token=alice_token,
         json={'date': FUTURE_1.isoformat(), 'propertyName': 'Beach House'})
    call('delete deleted booking', 'DELETE', '/bookings/delete-deleted-booking', token=alice_token,
         json={'date': FUTURE_3.isoformat(), 'propertyName': 'Beach House'})
    call('delete booking again', 'DELETE', '/bookings/', token=alice_token, json={'propertyId': beach_id, 'date': FUTURE_2.isoformat()})
    r = call('deleted bookings again', 'GET', '/bookings/view-deleted-bookings', token=alice_token)
    archived_id = r.get_json()['deletedBookings'][0]['id']
    call('delete deleted booking by id not found', 'DELETE', '/bookings/delete-deleted-booking/9999', token=alice_token)
    call('delete deleted booking by id', 'DELETE', f'/bookings/delete-deleted-booking/{archived_id}', token=alice_token)

    # ---- delete properties ----
    call('delete property missing id', 'DELETE', '/bookings/delete-property', token=alice_token, json={})
    call('delete property not owned', 'DELETE', '/bookings/delete-property', token=alice_token, json={'property_id': loft_id})
    call('delete property cabin', 'DELETE', '/bookings/delete-property', token=alice_token, json={'property_id': cabin_id})
    call('deleted bookings after property delete', 'GET', '/bookings/view-deleted-bookings', token=alice_token)
    call('delete all deleted', 'DELETE', '/bookings/delete-all-deleted-bookings', token=alice_token)
    call('bookings after deletes', 'GET', '/bookings/', token=alice_token)

    return s.entries


def test_api_contract(app, test_client, monkeypatch):
    monkeypatch.setattr(firebase_admin.auth, 'verify_id_token', fake_verify_id_token)
    random.seed(0)

    entries = run_session(app, test_client)

    if os.environ.get('UPDATE_SNAPSHOT'):
        SNAPSHOT_PATH.parent.mkdir(exist_ok=True)
        SNAPSHOT_PATH.write_text(json.dumps(entries, indent=2) + '\n')
        pytest.skip('snapshot updated')

    expected = json.loads(SNAPSHOT_PATH.read_text())
    assert [e['label'] for e in entries] == [e['label'] for e in expected]
    mismatches = [
        f"{actual['label']}:\n  expected {json.dumps(want)}\n  actual   {json.dumps(actual)}"
        for actual, want in zip(entries, expected) if actual != want
    ]
    assert not mismatches, f'{len(mismatches)} responses changed:\n' + '\n'.join(mismatches)
