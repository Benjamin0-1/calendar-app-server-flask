from app.errors import error, error_text, respond_on_failure
from app.extensions import db
from app.models import LoginHistory, User


def _get_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        raise error("User not found", 404)
    return user


def get_profile(user_id):
    return _get_user(user_id).serialize()


def update_profile(user_id, first_name=None, last_name=None):
    user = _get_user(user_id)

    with respond_on_failure(error_text):
        updated = False
        if first_name and first_name != user.first_name:
            user.first_name = first_name
            updated = True
        if last_name and last_name != user.last_name:
            user.last_name = last_name
            updated = True

        if not updated:
            raise error("No changes detected", 400)
        db.session.commit()


def update_password(user_id, current_password, new_password, confirm_new_password):
    user = db.get_or_404(User, user_id)
    if user.provider:
        raise error("User registered with a third-party provider", 403)
    if not user.check_password(current_password):
        raise error("Current password is incorrect", 403)
    if new_password != confirm_new_password:
        raise error("New passwords don't match", 400)
    if user.check_password(new_password):
        raise error("New password cannot be the same as the current password", 400)

    with respond_on_failure(error_text):
        user.set_password(new_password)
        db.session.commit()


def login_history(user_id):
    _get_user(user_id)
    return [record.serialize() for record in LoginHistory.query.filter_by(user_id=user_id).all()]
