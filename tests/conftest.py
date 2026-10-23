from datetime import date

import pytest
from sqlalchemy import CheckConstraint
from sqlalchemy.dialects.sqlite.base import DATE as SQLiteDate

from app import create_app, db
from app.models import BookedDate

TEST_CONFIG = {
    'TESTING': True,
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    'MAIL_SUPPRESS_SEND': True,
    'JWT_SECRET_KEY': 'test-jwt-secret',
    # unhandled errors become 500 responses, as in production, instead of failing the test.
    'PROPAGATE_EXCEPTIONS': False,
}


def _make_sqlite_behave_like_postgres(monkeypatch):
    # Postgres coerces 'YYYY-MM-DD' strings into DATE columns and some queries rely on it;
    # SQLite's DATE type only accepts date objects.
    original_bind_processor = SQLiteDate.bind_processor

    def bind_processor(self, dialect):
        process = original_bind_processor(self, dialect)

        def coerce(value):
            if isinstance(value, str):
                value = date.fromisoformat(value)
            return process(value)
        return coerce

    monkeypatch.setattr(SQLiteDate, 'bind_processor', bind_processor)

    # regex CHECK constraints (~*) are Postgres-only.
    for constraint in list(BookedDate.__table__.constraints):
        if isinstance(constraint, CheckConstraint) and '~*' in str(constraint.sqltext):
            BookedDate.__table__.constraints.discard(constraint)


@pytest.fixture
def app(monkeypatch):
    _make_sqlite_behave_like_postgres(monkeypatch)
    monkeypatch.setenv('FRONTEND_URL', 'http://frontend.test')
    monkeypatch.delenv('JWT_ACCESS_TOKEN_EXPIRES', raising=False)
    monkeypatch.delenv('JWT_REFRESH_TOKEN_EXPIRES', raising=False)

    app = create_app(TEST_CONFIG)
    # no app context is held while tests run, so each request gets its own db session like in production.
    with app.app_context():
        db.create_all()
    yield app
    with app.app_context():
        db.drop_all()


@pytest.fixture
def test_client(app):
    return app.test_client()
