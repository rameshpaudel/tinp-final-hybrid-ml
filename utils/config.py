import os
from dotenv import load_dotenv, find_dotenv
#Load environment variables
load_dotenv(dotenv_path=find_dotenv(), override=True)

'''Application main Configuration '''
class Config:
    """Base config."""
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    #JWT_SECRET KEY
    SECRET_KEY = os.getenv('SECRET_KEY')
    #Configuration for checking JWT token location. Default: 'headers'
    JWT_TOKEN_LOCATION = os.getenv('JWT_TOKEN_LOCATION')
    #Check debug Mode
    DEBUG = os.getenv('DEBUG', 'False').lower() in ['true', '1', 't']
    TESTING = os.getenv('TESTING', 'False').lower() in ['true', '1', 't']
    JWT_SECRET = os.getenv('JWT_SECRET')
    UPLOAD_FOLDER = '/tmp/secure_uploads'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB limit
    SQLALCHEMY_DATABASE_URI = (
        f"mysql://{os.getenv('DB_USERNAME')}:{os.getenv('DB_PASSWORD')}"
        f"@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
        "?unix_socket=/var/run/mysqld/mysqld.sock"
    )

class DevelopmentConfig(Config):
    """Development config."""
    DEBUG = True

class ProductionConfig(Config):
    """Production config."""
    DEBUG = False
    TESTING = False