
import jwt
import datetime
from flask import jsonify, g, request, current_app, Blueprint
# werkzug allows -> headers, query args, form data, files, and cookies
from werkzeug.security import generate_password_hash, check_password_hash
from utils.api_response import success_response,error_response
from models.user import User
from utils.main import db, auth

auth_routes = Blueprint("auth", __name__)

##Routes
@auth_routes.route('/login', methods=['POST'])
def login():
    username = None
    password = None
    auth_data = request.authorization or None
    if auth_data:
        username = auth_data.username
        password = auth_data.password
    else:
        username = request.json['username']
        password = request.json['password']
    
    if username and password:
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            token = jwt.encode({'id': user.id,
                                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
                               current_app.config['JWT_SECRET'])  
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

