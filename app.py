import os
from flask import Flask
from dotenv import load_dotenv, find_dotenv
# werkzug allows -> headers, query args, form data, files, and cookies
from werkzeug.security import generate_password_hash, check_password_hash
from utils.api_response import success_message,error_response

from utils.main import db
from routes.auth import auth_routes
from routes.dashboard import dashboard_routes
from routes.frontend import webapp as frontend_routes

#Load environment variables
load_dotenv(dotenv_path=find_dotenv(), override=True)
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

#Configure upload folder
UPLOAD_FOLDER = '/tmp/secure_uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB limit

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


#initialize db
db.init_app(app)
with app.app_context():
        db.create_all()
        
#Register the authentication routes
app.register_blueprint(auth_routes)
app.register_blueprint(dashboard_routes)
app.register_blueprint(frontend_routes)


if __name__ == "__main__":
    #Auto create tables if it doesnot exist
    app.run(debug=True, host='0.0.0.0', port=os.getenv("PORT"), threaded=True)