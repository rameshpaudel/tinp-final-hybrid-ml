import datetime
import jwt
from utils.main import db, auth
from flask import current_app

# werkzug allows -> headers, query args, form data, files, and cookies
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password = db.Column(db.String(128))
    email = db.Column(db.String(100), index=True)
    role = db.Column(db.String(5))
    reset_token = db.Column(db.String(50))
    
    ##TODO : Add created at and updated at columns

    def hash_password(self, password):
        self.password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

    def generate_auth_token(self, expires_in=24):
        return jwt.encode(
            {'id': self.id, 'exp': datetime.datetime.now() + datetime.timedelta(hours=expires_in)},
            current_app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'],algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])
