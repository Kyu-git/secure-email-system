# your_user_model.py
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

class User(UserMixin):
    def __init__(self):
        self.id = None
        self.email = None
        self.fullname = None
        self.is_admin = False
        self._authenticated = False

    @staticmethod
    def get(user_id):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, email, fullname, is_admin FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            user = User()
            user.id = user_data[0]
            user.email = user_data[1]
            user.fullname = user_data[2]
            user.is_admin = bool(user_data[3])
            user._authenticated = True
            return user
        return None

    @staticmethod
    def get_by_email(email):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, email, fullname, is_admin FROM users WHERE email = ?', (email,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            user = User()
            user.id = user_data[0]
            user.email = user_data[1]
            user.fullname = user_data[2]
            user.is_admin = bool(user_data[3])
            user._authenticated = True
            return user
        return None

    def is_authenticated(self):
        return self._authenticated

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)
