from datetime import datetime, timedelta

# Define the maximum number of allowed failed attempts
MAX_FAILED_ATTEMPTS = 5
# Define the lockout period in seconds
LOCKOUT_PERIOD = 300 # 5 minutes


class LoginAttempts:
    """
    Failed login attempts per email.
    Kept in process memory: it resets on restart and isn't shared between workers (temporary solution).
    """

    def __init__(self):
        self._attempts = {}

    def remaining_lockout(self, email):
        """Seconds left in the email's lockout, or None when it isn't locked out."""
        attempts_info = self._attempts.get(email)
        if attempts_info and attempts_info['attempts'] >= MAX_FAILED_ATTEMPTS:
            remaining_lockout_time = (attempts_info['lockout_time'] - datetime.now()).total_seconds()
            if remaining_lockout_time > 0:
                return remaining_lockout_time
        return None

    def record_failure(self, email):
        attempts_info = self._attempts.setdefault(email, {'attempts': 0, 'lockout_time': None})
        attempts_info['attempts'] += 1
        if attempts_info['attempts'] >= MAX_FAILED_ATTEMPTS: # if exceeded max attempts
            attempts_info['lockout_time'] = datetime.now() + timedelta(seconds=LOCKOUT_PERIOD) # then lockout the user

    def reset(self, email):
        self._attempts.pop(email, None)


failed_login_attempts = LoginAttempts()
