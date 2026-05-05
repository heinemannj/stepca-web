from .base import AuthBackend
from werkzeug.security import check_password_hash

class LocalAuthBackend(AuthBackend):
    def __init__(self, config):
        print("Using LocalAuthBackend")
        self.config = config
        self.users = config.get('LOCAL_USERS')

    def authenticate(self, username, password):
        user = self.users.get(username)
        if user and check_password_hash(user['password_hash'], password):
            return {'id': user['id'], 'attributes': user.get('attributes', {})}
        return None

    def get_user(self, user_id):
        user = self.users.get(user_id)
        if user:
            return {'id': user['id'], 'attributes': user.get('attributes', {})}
        return None
