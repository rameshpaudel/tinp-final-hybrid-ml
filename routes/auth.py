
import jwt
import datetime
from flask import jsonify, g, request, current_app, Blueprint
# werkzug allows -> headers, query args, form data, files, and cookies
from werkzeug.security import generate_password_hash, check_password_hash
from utils.api_response import success_response,error_response
from models.user import User, LoginHistory
from utils.main import db, auth

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
            # Log the successful login
            login_history = LoginHistory(user_id=user.id, login_time=datetime.datetime.utcnow())
            db.session.add(login_history)
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
            hashed_password = generate_password_hash(password, method='sha256')
            new_user = User(username=username, password=hashed_password, email=email, role="user")
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': "User created successfully"}), 200
        else:
            return jsonify(error_response('Username, email, and password fields are required')), 400
    except Exception as e:
        return jsonify(error_response(str(e))), 500

@auth_routes.route('/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization', None)
    if token:
        user = User.verify_auth_token(token)
        if user:
            # Log the successful logout
            login_history = LoginHistory.query.filter_by(user_id=user.id, logout_time=None).order_by(LoginHistory.login_time.desc()).first()
            if login_history:
                login_history.logout_time = datetime.datetime.utcnow()
                db.session.commit()
            user.auth_token = None
            db.session.commit()
            return jsonify(success_response('Logged out successfully')), 200
    return jsonify(error_response('Invalid token')), 401


@auth_routes.route('/login-history', methods=['GET'])
@auth.login_required
def get_login_history():
    user_id = g.user.id
    login_history = LoginHistory.query.filter_by(user_id=user_id).order_by(LoginHistory.login_time.desc()).all()
    history_data = [
        {
            'login_time': str(entry.login_time),
            'logout_time': str(entry.logout_time) if entry.logout_time else None
        } for entry in login_history
    ]
    return jsonify(success_response(history_data))

@auth_routes.route('/user/<int:user_id>/login-history', methods=['GET'])
@auth.login_required
def get_user_login_history(user_id):
    if g.user.id != user_id and g.user.role != 'admin':
        return jsonify(error_response('You are not authorized to view this user\'s login history')), 403

    login_history = LoginHistory.query.filter_by(user_id=user_id).order_by(LoginHistory.login_time.desc()).all()
    history_data = [
        {
            'login_time': str(entry.login_time),
            'logout_time': str(entry.logout_time) if entry.logout_time else None
        } for entry in login_history
    ]
    return jsonify(success_response(history_data))

@auth.verify_password
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

