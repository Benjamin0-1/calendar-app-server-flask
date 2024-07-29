from app import create_app, db
from app.utils.scheduler import start_scheduler

app = create_app()

# Pass the app instance to the scheduler
scheduler = start_scheduler(app)

def log_session_state():
    with app.app_context():
        app.logger.info(f"Session state: {db.session.dirty}, {db.session.new}, {db.session.deleted}")

if __name__ == '__main__':
    log_session_state()
    app.run(debug=True)





'''from app import create_app
from app import db

app = create_app()

# avoid circular imports.
from app.utils.scheduler import start_scheduler
start_scheduler()

def log_session_state():
    with app.app_context():
        app.logger.info(f"Session state: {db.session.dirty}, {db.session.new}, {db.session.deleted}")

if __name__ == '__main__':
    log_session_state()
    app.run(debug=True)
    '''