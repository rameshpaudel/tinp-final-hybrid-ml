import os
from flask import Flask
from dotenv import load_dotenv, find_dotenv
# werkzug allows -> headers, query args, form data, files, and cookies
from werkzeug.security import generate_password_hash, check_password_hash
from utils.api_response import success_message,error_response
from utils.config import ProductionConfig, DevelopmentConfig
from utils.main import db
from routes.auth import auth_routes
from routes.dashboard import dashboard_routes
from routes.frontend import webapp as frontend_routes
from routes.training import training_routes
from routes.faq_chat import faq_chat as faq_routes
from flask_cors import CORS
from flask_session import Session


## Database Configurations
app = Flask(__name__)
# Choose the configuration based on environment
if os.getenv('FLASK_ENV') == 'production':
    app.config.from_object(ProductionConfig)
else:
    app.config.from_object(DevelopmentConfig)
CORS(app)


Session(app)
# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

#Fix CORS issue to allow access from all domains
@app.after_request
def handle_options(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Requested-With, Authorization"

    return response

#initialize db
db.init_app(app)
with app.app_context():
    #create the tables
        db.create_all()
        
#Register the authentication routes
app.register_blueprint(auth_routes)
app.register_blueprint(dashboard_routes)
app.register_blueprint(frontend_routes)
app.register_blueprint(training_routes)
app.register_blueprint(faq_routes)



if __name__ == "__main__":
    #Auto create tables if it doesnot exist
    app.run(debug=True, host='0.0.0.0', port=os.getenv("PORT"), threaded=True)