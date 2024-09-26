
import jwt
import datetime
from flask import jsonify, g, request, current_app, Blueprint
# werkzug allows -> headers, query args, form data, files, and cookies
from werkzeug.security import generate_password_hash, check_password_hash
from utils.api_response import success_message,error_response, success_response
from models.user import User,LoginToken
from utils.main import db, auth
from sqlalchemy import or_

auth_routes = Blueprint("auth", __name__)

##Routes
@auth_routes.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if username and password:
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            token = user.generate_auth_token()
            #Add the login token to the database
            login_token = LoginToken(user_id=user.id,token=token,blocked=False)
            db.session.add(login_token)
            db.session.commit()
            return jsonify({'token': token})
        return jsonify(error_response('Invalid credentials')), 401
    else:
        return jsonify(error_response('No credentials')), 400

@auth_routes.route('/register', methods=['POST'])
def register():
    try:
        if {'username', 'password', 'email'} <= request.json.keys():
            email = request.json['email']
            username = request.json['username']
            password = request.json['password']
            ##Check if the user already exists
            user = User.query.filter(or_(User.username == username, User.email == email)).first()
            if user:
                return jsonify(error_response("User already exists")), 400
            hashed_password = generate_password_hash(password, method='sha256')
            #Register a new generic user to the database
            new_user = User(username=username, password=hashed_password, email=email, role="user")
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': "User created successfully"}), 200
        else:
            return jsonify(error_response('Username, email, and password fields are required')), 400
    except Exception as e:
        return jsonify(error_response(str(e))), 500

@auth_routes.route('/logout', methods=['POST'])
@auth.login_required
def logout():
    token = request.headers.get('Authorization', None)
    if token:
        #Remove Bearer from token
        token = token.split()[1]
        user = User.verify_auth_token(token)
        
        if user:
            # Log the successful logout
            login_token = LoginToken.query.filter_by(user_id=user.id,token=token).first()
            if login_token:
                login_token.blocked = True
                login_token.revoked_at =datetime.datetime.now()
                db.session.commit()
                
            user.auth_token = None
            db.session.commit()
            
            return jsonify(success_message('Logged out successfully')), 200
    return jsonify(error_response('No token provided')), 401


@auth_routes.route('/login-history', methods=['GET'])
@auth.login_required
def get_login_history():
    user_id = g.user.id
    login_history = LoginToken.query.filter_by(user_id=user_id).order_by(LoginToken.created_at.desc()).all()
    history_data = [
        {
            'login_time': str(entry.created_at),
            'logout_time': str(entry.revoked_at) if entry.revoked_at else None
        } for entry in login_history
    ]
    return jsonify(success_response(history_data))

#Get the login history of a user
@auth_routes.route('/user/<int:user_id>/login-history', methods=['GET'])
@auth.login_required
def get_user_login_history(user_id):
    if g.user.id != user_id or g.user.role != 'admin':
        return jsonify(error_response('You are not authorized to view this user\'s login history')), 403

    login_history = LoginToken.query.filter_by(user_id=user_id).order_by(LoginToken.created_at.desc()).all()
    history_data = [
        {
            'login_time': str(entry.created_at),
            'logout_time': str(entry.revoked_at) if entry.revoked_at else None
        } for entry in login_history
    ]
    return jsonify(success_response(history_data))

#Get the login history of a user
@auth_routes.route('/user/login-history/<int:id>/revoke', methods=['PUT'])
@auth.login_required
def revoke_user_login_token(id):
    if g.user.role != 'admin':
        return jsonify(error_response('You are not authorized to update this user\'s login data')), 403

    login_token = LoginToken.query.filter_by(id=id).all()
    login_token.revoked_at =datetime.datetime.now()
    db.session.commit()
    return jsonify(success_response(login_token,message="Sucessfully revoked login token"))

# @auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

##Verify the token for the user
@auth.verify_token
def verify_token(token):
    token = LoginToken.query.filter_by(token=token, blocked=False, revoked_at=None).first()
    if token:
        user = User.query.filter_by(id=token.user_id).first()
        g.user = user
        return True
    return False