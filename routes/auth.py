
import re
import datetime
from flask import jsonify, g, request, current_app, Blueprint
from werkzeug.security import generate_password_hash, check_password_hash
from utils.api_response import success_message,error_response, respond_success_data
from models.user import User,LoginToken
from utils.main import db, auth
from sqlalchemy import or_

auth_routes = Blueprint("auth", __name__)

'''Login Routes for authenticating users'''
@auth_routes.route('/login', methods=['POST'])
def login():
    #Get username and password from the request
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

'''Register a new user'''
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
            
            password_validation = validate_password(password)
            if password_validation is not True:
                return jsonify(error_response(password_validation)), 400

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

'''Revoke tokens on user logout'''
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

'''Change password of logged in user'''
@auth_routes.route('/change-password', methods=['POST'])
@auth.login_required
def change_password():
    try:
        current_user_id = g.user.id
        user = User.query.get(current_user_id)

        if not user:
            return jsonify(error_response("User not found")), 404

        data = request.json
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not current_password or not new_password:
            return jsonify(error_response("Current password and new password are required")), 400

        # Verify current password
        if not check_password_hash(user.password, current_password):
            return jsonify(error_response("Current password is incorrect")), 401

        # Validate new password
        password_validation = validate_password(new_password)
        if password_validation is not True:
            return jsonify(error_response(password_validation)), 400

        # Check if new password is different from the current one
        if check_password_hash(user.password, new_password):
            return jsonify(error_response("New password must be different from the current password")), 400

        # Update password
        user.password = generate_password_hash(new_password, method='sha256')
        db.session.commit()

        return jsonify(success_message( "Password changed successfully")), 200

    except Exception as e:
        return jsonify(error_response(str(e))), 500
    
    
'''Display the login history for current user'''
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
    return jsonify(respond_success_data(history_data))


'''Display login history for any user when logged in as an administrator'''
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
    return jsonify(respond_success_data(history_data))


'''Revoke the token of any user when logged in as an administrator'''
@auth_routes.route('/user/login-history/<int:id>/revoke', methods=['PUT'])
@auth.login_required
def revoke_user_login_token(id):
    if g.user.role != 'admin':
        return jsonify(error_response('You are not authorized to update this user\'s login data')), 403

    login_token = LoginToken.query.filter_by(id=id).all()
    login_token.revoked_at =datetime.datetime.now()
    db.session.commit()
    return jsonify(respond_success_data(login_token,message="Sucessfully revoked login token"))

'''Get current logged in user'''
@auth_routes.route('/current-user', methods=['GET'])
@auth.login_required
def get_logged_in_user():
    if g.user is not None:
        return jsonify(respond_success_data(data=g.user.to_dict() , message="User is logged in"))
    return jsonify(error_response("User is not logged in"))


'''Validate a strong password'''
def validate_password(password):
    """
    Validate the strength of a password.
    Returns True if the password is strong, or a string describing the weakness if not.
    """
    if len(password) < 12:
        return "Password must be at least 12 characters long"
    
    if not re.search(r'[A-Z]', password):
        return "Password must include at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return "Password must include at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return "Password must include at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Password must include at least one special character"
    
    # Check for common patterns
    common_patterns = ['123', 'abc', 'qwerty', 'password', 'admin']
    if any(pattern in password.lower() for pattern in common_patterns):
        return "Password contains a common pattern and is too weak"
    
    return True


'''Verify password for HttpBasicAuth'''
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

'''Verify the token for the user'''
@auth.verify_token
def verify_token(token):
    token = LoginToken.query.filter_by(token=token, blocked=False, revoked_at=None).first()
    if token:
        user = User.query.filter_by(id=token.user_id).first()
        g.user = user
        return True
    return False

