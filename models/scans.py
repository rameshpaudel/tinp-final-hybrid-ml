import datetime
from utils.main import db

'''Displays the scan history of each files and their result'''
class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(150), index=True)
    hashed_name = db.Column(db.String(250), nullable=True)
    file_size = db.Column(db.String(15),nullable=True)
    status = db.Column(db.String(15), nullable=True)
    results = db.Column(db.String(150), nullable=True)
    details = db.Column(db.JSON, nullable=True)
    request_info = db.Column(db.JSON, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now())