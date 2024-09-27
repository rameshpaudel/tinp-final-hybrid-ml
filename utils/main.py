'''Database and authentication used throughout the project'''
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth,HTTPTokenAuth, MultiAuth
'''Initialize database and authentication'''
db = SQLAlchemy()
auth = HTTPTokenAuth()

