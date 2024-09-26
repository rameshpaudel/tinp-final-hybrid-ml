import datetime
from utils.main import db
from flask import current_app
# werkzug allows -> headers, query args, form data, files, and cookies
from werkzeug.security import generate_password_hash, check_password_hash

'''Displays the scan history of each files and their result'''
class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(15), index=True)
    file_size = db.Column(db.String(15))
    status = db.Column(db.String(15))
    details = db.Column(db.JSON, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now())