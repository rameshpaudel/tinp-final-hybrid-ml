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

## Database Configurations
app = Flask(__name__)

# Choose the configuration based on environment
if os.getenv('FLASK_ENV') == 'production':
    app.config.from_object(ProductionConfig)
else:
    app.config.from_object(DevelopmentConfig)

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


#initialize db
db.init_app(app)
with app.app_context():
        db.create_all()
        
#Register the authentication routes
app.register_blueprint(auth_routes)
app.register_blueprint(dashboard_routes)
app.register_blueprint(frontend_routes)
app.register_blueprint(training_routes)


if __name__ == "__main__":
    #Auto create tables if it doesnot exist
    app.run(debug=True, host='0.0.0.0', port=os.getenv("PORT"), threaded=True)