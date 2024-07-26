from app import create_app
from app import db

app = create_app()

def log_session_state():
    with app.app_context():
        app.logger.info(f"Session state: {db.session.dirty}, {db.session.new}, {db.session.deleted}")

if __name__ == '__main__':
    log_session_state()
    app.run(debug=True)
    