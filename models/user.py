import datetime
import jwt
from utils.main import BaseModel, db
from flask import current_app

# werkzug allows -> headers, query args, form data, files, and cookies
from werkzeug.security import generate_password_hash, check_password_hash
'''User model for storing user information'''
class User(BaseModel):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password = db.Column(db.String(128))
    email = db.Column(db.String(100), index=True)
    role = db.Column(db.String(5))
    reset_token = db.Column(db.String(50))
    auth_token = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now())
    
    _default_fields = [
        "username",
        "email",
        "role",
        "created_at"
    ]
    _hidden_fields = [
        "password",
    ]
    _readonly_fields = [
        "reset_token",
    ]
   
    #add relationship 
    token = db.relationship("LoginToken", backref='user', lazy='dynamic')

    #Generate hashed password
    def hash_password(self, password):
        self.password = generate_password_hash(password)

    #Verify the provided password
    def verify_password(self, password):
        return check_password_hash(self.password, password)

    #Generate jwt auth token for the logged in user
    def generate_auth_token(self, expires_in=24):
        payload = {
            'id': self.id,
            'username': self.username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=expires_in)
        }
        self.auth_token = jwt.encode(payload, current_app.config['JWT_SECRET'])
        db.session.commit()
        return self.auth_token

    #Verify the jwt authentication token
    @staticmethod
    def verify_auth_token(token):
        try:
            
            data = jwt.decode(token.strip(), current_app.config['JWT_SECRET'] , algorithms=["HS256"])
            
            user = User.query.get(data['id'])
            if user.auth_token == token:
                return user
            return None
        except:
            return None
        
    #Verify if the user is administrator
    @staticmethod
    def verify_is_admin(token):
        try:
            data = jwt.decode(token, current_app.config['JWT_SECRET'],algorithm="HS256")
            user = User.query.get(data['id'])
            if user.role == 'admin':
                return user
            return None
        except:
            return None
        
'''Stores user token with login history for each user'''    
class LoginToken(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    token=db.Column(db.String(400))
    user_id=db.Column(db.Integer,db.ForeignKey("users.id"), nullable=True)
    blocked= db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=True, default=datetime.datetime.now())
    revoked_at = db.Column(db.DateTime, nullable=True)