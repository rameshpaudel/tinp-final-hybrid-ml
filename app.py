import os
import jwt
import datetime
from flask import Flask
from dotenv import load_dotenv
# werkzug allows -> headers, query args, form data, files, and cookies
from werkzeug.security import generate_password_hash, check_password_hash
from utils.api_response import success_response,error_response
from models.user import User
from utils.main import db, auth
from routes.auth import auth_routes

#Load environment variables
load_dotenv()
## Database Configurations
app = Flask(__name__)

#Application Configurations
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql://{os.getenv('DB_USERNAME')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}?unix_socket=/var/run/mysqld/mysqld.sock"
app.config['SECRET_KEY'] =os.getenv('SECRET_KEY')
app.config['JWT_TOKEN_LOCATION'] =os.getenv('JWT_TOKEN_LOCATION')
app.config['DEBUG'] =os.getenv('DEBUG')
app.config['TESTING'] =os.getenv('TESTING')
app.config['JWT_SECRET'] =os.getenv('JWT_SECRET')


#initialize db
db.init_app(app)
#Register the authentication routes
app.register_blueprint(auth_routes)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)