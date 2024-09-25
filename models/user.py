import datetime
import jwt
from utils.main import db
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
    auth_token = db.Column(db.String(500), nullable=True)

    #add relationship
    login_history = db.relationship('LoginHistory', backref='user', lazy='dynamic')

    ##TODO : Add created at and updated at columns

    def hash_password(self, password):
        self.password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

    def generate_auth_token(self, expires_in=24):
        payload = {
            'id': self.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=expires_in)
        }
        self.auth_token = jwt.encode(payload, current_app.config['JWT_SECRET'])
        db.session.commit()
        return self.auth_token

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, current_app.config['JWT_SECRET'])
            user = User.query.get(data['id'])
            if user.auth_token == token:
                return user
            return None
        except:
            return None

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    login_time = db.Column(db.DateTime, nullable=True)
    logout_time = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f"LoginHistory(user_id={self.user_id}, login_time={self.login_time}, logout_time={self.logout_time})"