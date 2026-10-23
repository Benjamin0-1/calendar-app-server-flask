from contextlib import contextmanager

from flask import jsonify

from app.extensions import db


class APIError(Exception):
    """An expected failure, carrying the exact JSON body and status code the client receives."""

    def __init__(self, body, status=400):
        super().__init__(body)
        self.body = body
        self.status = status


def error(message, status=400):
    return APIError({"error": message}, status)


@contextmanager
def respond_on_failure(make_body):
    """
    Turn an unexpected exception inside the block into a 500 whose body is make_body(exception),
    rolling back the session first. APIErrors raised inside pass through untouched.
    """
    try:
        yield
    except APIError:
        raise
    except Exception as e:
        db.session.rollback()
        raise APIError(make_body(e), 500) from e


def error_text(e):
    return {"error": str(e)}


def failed(message):
    return lambda e: {"error": message, "details": str(e)}


def register_error_handlers(app):
    @app.errorhandler(APIError)
    def handle_api_error(e):
        return jsonify(e.body), e.status
